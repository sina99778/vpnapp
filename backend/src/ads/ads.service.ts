import {
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { pool, withTransaction } from '../db/pool';
import { randomUrlToken } from '../common/http';
import { IPanelClient, PANEL_CLIENT } from '../panel/IPanelClient';
import { AdMobReward } from './admob-ssv.verifier';
import { SessionConfigService } from '../connection/session-config.service';
import { EncryptedPayloadDto } from '../connection/payload-cipher';

export type AdGrantPurpose = 'connect' | 'extend' | 'disconnect';

export interface RequestTokenResult {
  grantId: string;
  nonce: string; // pass as AdMob custom_data
  requiredAds: number;
  grantMinutes: number;
  expiresAt: string; // ISO; window to finish watching the ads
}

export interface VerifyRewardResult {
  sessionId: string;
  expiresAt: string; // new absolute session expiry
  grantedMinutes: number;
  panelSync: 'synced' | 'pending' | 'unchanged';
  // The encrypted config — delivered HERE (not at /connect) for the free tier,
  // once the ads are verified (Provisioning Model). Null on a disconnect grant.
  payload?: EncryptedPayloadDto;
}

const TOKEN_WINDOW_MIN = Number(process.env.AD_TOKEN_WINDOW_MIN ?? 15);
const MAX_SESSION_MIN = Number(process.env.MAX_SESSION_MINUTES ?? 1440);

/**
 * Sentinel `custom_data` the Flutter client sends for the best-effort "watch 1
 * ad to disconnect" view (see ConnectionFlowController.closingAdNonce). It is
 * deliberately NOT a real grant nonce: a validly-signed SSV callback carrying
 * it must be acknowledged (200) but must never grant time or touch a session.
 * This string is a cross-process contract with the client — keep them in sync.
 */
export const CLOSING_SESSION_NONCE = 'closing-session-no-grant';

@Injectable()
export class AdsService {
  private readonly log = new Logger(AdsService.name);

  constructor(
    @Inject(PANEL_CLIENT) private readonly panel: IPanelClient,
    private readonly sessionConfig: SessionConfigService,
  ) {}

  private rulesFor(purpose: AdGrantPurpose): { requiredAds: number; grantMinutes: number } {
    switch (purpose) {
      case 'connect':
        return { requiredAds: 2, grantMinutes: 60 }; // 2 ads → 1 hour
      case 'extend':
        return { requiredAds: 2, grantMinutes: 60 };
      case 'disconnect':
        return { requiredAds: 1, grantMinutes: 0 }; // graceful-close ad, no time
    }
  }

  // -------------------------------------------------------------------------
  // 1) request-ad-token : mint a single-use grant + nonce. No external I/O.
  // -------------------------------------------------------------------------
  async requestAdToken(
    userId: string,
    deviceId: string,
    purpose: AdGrantPurpose,
    sessionId: string | null,
  ): Promise<RequestTokenResult> {
    const { requiredAds, grantMinutes } = this.rulesFor(purpose);
    const nonce = randomUrlToken(32);

    const { rows } = await pool.query(
      `insert into ad_reward_grants
         (user_id, device_id, session_id, purpose, nonce, required_ads, grant_minutes, expires_at)
       values ($1,$2,$3,$4,$5,$6,$7, now() + ($8 * interval '1 minute'))
       returning id, expires_at`,
      [userId, deviceId, sessionId, purpose, nonce, requiredAds, grantMinutes, TOKEN_WINDOW_MIN],
    );

    return {
      grantId: rows[0].id,
      nonce,
      requiredAds,
      grantMinutes,
      expiresAt: new Date(rows[0].expires_at).toISOString(),
    };
  }

  // -------------------------------------------------------------------------
  // 2) SSV callback intake : record a verified ad. Called by the SSV endpoint
  //    AFTER the signature has been checked. No external I/O here; the short tx
  //    only inserts the reward and bumps the grant counter. Idempotent via the
  //    (network, transaction_id) unique constraint.
  // -------------------------------------------------------------------------
  async recordVerifiedReward(reward: AdMobReward): Promise<void> {
    // Sentinel guard: the closing-ad callback is genuinely signed by AdMob but
    // must never fund a grant. Acknowledge it (caller returns 200, so AdMob
    // won't retry) and do ZERO database work — no grant lookup, no session
    // change. This runs before any transaction is opened.
    if (reward.customData === CLOSING_SESSION_NONCE) {
      // Production-visible (not debug) so closing-ad delivery is auditable and
      // correlatable with AdMob's logs by transaction_id. No DB work, no grant.
      this.log.log(`acknowledged closing-session SSV callback, no grant (txn ${reward.transactionId})`);
      return;
    }

    await withTransaction(async (c) => {
      const g = await c.query(
        `select id, status, required_ads, verified_ads, expires_at
           from ad_reward_grants
          where nonce = $1
          for update`,
        [reward.customData],
      );
      if (g.rowCount === 0) {
        // Unknown nonce → forged or already-cleaned grant. Reject so the SSV
        // endpoint returns a 4xx (and we never credit a phantom grant).
        throw new NotFoundException('unknown grant nonce');
      }
      const grant = g.rows[0];

      // Store every verified reward for audit; the unique constraint dedupes
      // redelivered callbacks.
      const ins = await c.query(
        `insert into ad_rewards
           (grant_id, network, transaction_id, ad_unit, reward_item, reward_amount, signature_key_id, raw)
         values ($1,'admob',$2,$3,$4,$5,$6,$7)
         on conflict (network, transaction_id) do nothing
         returning id`,
        [
          grant.id,
          reward.transactionId,
          reward.adUnit ?? null,
          reward.rewardItem ?? null,
          reward.rewardAmount ?? null,
          reward.keyId,
          reward.raw,
        ],
      );
      if (ins.rowCount === 0) return; // duplicate SSV callback → no-op

      // Only count toward fulfillment if the grant is still open.
      const open = grant.status === 'pending' && new Date(grant.expires_at) > new Date();
      if (!open) return;

      const verified = grant.verified_ads + 1;
      const fulfilled = verified >= grant.required_ads;
      await c.query(
        `update ad_reward_grants
            set verified_ads = $2,
                status       = case when $3 then 'fulfilled' else status end,
                fulfilled_at = case when $3 then now()       else fulfilled_at end
          where id = $1`,
        [grant.id, verified, fulfilled],
      );
    });
  }

  // -------------------------------------------------------------------------
  // 3) verify-ad-reward : claim a fulfilled grant → extend the session by
  //    exactly grant_minutes, then mirror to the panel.
  //
  //    Phase A: ONE short transaction. Locks the grant + session, validates,
  //             writes the new expiry, marks the grant consumed, and enqueues a
  //             panel outbox op. COMMIT releases all locks.
  //    Phase B: with NO locks held, push the new expiry to the panel. If it
  //             fails, the outbox worker retries — the DB expiry is already
  //             authoritative and the reaper enforces it regardless.
  // -------------------------------------------------------------------------
  async verifyAdReward(
    userId: string,
    grantId: string,
    sessionId: string,
  ): Promise<VerifyRewardResult> {
    const planned = await withTransaction(async (c) => {
      // Lock order is always grant → session to avoid deadlocks.
      const g = await c.query(
        `select id, user_id, purpose, required_ads, verified_ads, grant_minutes,
                status, expires_at, session_id
           from ad_reward_grants
          where id = $1
          for update`,
        [grantId],
      );
      if (g.rowCount === 0) throw new NotFoundException('grant not found');
      const grant = g.rows[0];
      if (grant.user_id !== userId) throw new ForbiddenException('grant not owned by caller');

      // A grant funds EXACTLY ONE session. 'extend'/'disconnect' grants are bound
      // to their session at request time; 'connect' grants carry session_id=null
      // until first funded (bound below, on consume). Reject any attempt to point
      // a grant at a session other than the one it is bound to.
      if (grant.session_id !== null && grant.session_id !== sessionId) {
        throw new ForbiddenException('grant is bound to a different session');
      }

      // Idempotent replay: a grant can fund a session exactly once. Use the
      // grant's OWN bound session, never the (possibly different) request param.
      if (grant.status === 'consumed') {
        const boundSessionId = grant.session_id ?? sessionId;
        const s = await c.query(`select id, expires_at from vpn_sessions where id = $1`, [
          boundSessionId,
        ]);
        if (s.rowCount === 0) throw new NotFoundException('session not found');
        return {
          kind: 'idempotent' as const,
          sessionId: boundSessionId,
          expiresAt: new Date(s.rows[0].expires_at).toISOString(),
        };
      }

      if (grant.status === 'expired' || new Date(grant.expires_at) <= new Date()) {
        await c.query(
          `update ad_reward_grants set status='expired' where id=$1 and status<>'consumed'`,
          [grantId],
        );
        throw new ConflictException('ad grant window expired; request a new token');
      }
      if (grant.verified_ads < grant.required_ads) {
        throw new ConflictException(
          `ads not yet verified (${grant.verified_ads}/${grant.required_ads}); retry shortly`,
        );
      }

      // Lock the session row.
      const s = await c.query(
        `select id, user_id, panel_username, status, expires_at, created_at
           from vpn_sessions
          where id = $1
          for update`,
        [sessionId],
      );
      if (s.rowCount === 0) throw new NotFoundException('session not found');
      const session = s.rows[0];
      if (session.user_id !== userId) throw new ForbiddenException('session not owned by caller');
      if (!['provisioning', 'active', 'limited'].includes(session.status)) {
        throw new ConflictException(`session is not live (${session.status})`);
      }

      // Add EXACTLY grant_minutes, floored at now (so an already-expired session
      // restarts from now) and capped at the absolute max session length.
      const now = Date.now();
      const base = Math.max(now, new Date(session.expires_at).getTime());
      const capMs = new Date(session.created_at).getTime() + MAX_SESSION_MIN * 60_000;
      // Fail fast at the lifetime ceiling rather than silently granting 0 minutes
      // (which would still burn the user's 2 ads). The client surfaces this.
      if (grant.grant_minutes > 0 && base >= capMs) {
        throw new ConflictException('session lifetime cap reached; cannot extend further');
      }
      let newMs = base + grant.grant_minutes * 60_000;
      if (newMs > capMs) newMs = capMs; // last partial extension, up to the cap
      const newExpires = new Date(newMs);

      // Consume the grant first (so a concurrent verify can't reuse it) and bind
      // it to this session if it wasn't already (the 'connect' case).
      await c.query(
        `update ad_reward_grants
            set status='consumed', consumed_at=now(), session_id=$2
          where id=$1`,
        [grantId, sessionId],
      );

      let opId: string | null = null;
      if (grant.grant_minutes > 0) {
        await c.query(
          `update vpn_sessions
              set expires_at       = $2,
                  extensions_count = extensions_count + 1,
                  last_ad_grant_id = $3,
                  status           = case when status='provisioning' then 'active' else status end
            where id = $1`,
          [sessionId, newExpires.toISOString(), grantId],
        );

        // Durable outbox row: the intent to push this expiry to the panel.
        const op = await c.query(
          `insert into panel_operations (session_id, op, payload, status, next_attempt_at)
           values ($1, 'extend_user', $2, 'pending', now())
           returning id`,
          [sessionId, { panel_username: session.panel_username, expire_epoch: Math.floor(newMs / 1000) }],
        );
        opId = op.rows[0].id;
      }

      return {
        kind: 'extend' as const,
        sessionId,
        panelUsername: session.panel_username as string,
        newExpires,
        grantedMinutes: grant.grant_minutes as number,
        opId,
      };
    });
    // ===== transaction COMMITTED — every row lock is now released =====

    if (planned.kind === 'idempotent') {
      // Re-deliver the payload so a retried verify (e.g. after a dropped
      // response) doesn't leave the client without a config. Rebuilt with a
      // fresh server ephemeral key; the client's session key still derives.
      return {
        sessionId: planned.sessionId,
        expiresAt: planned.expiresAt,
        grantedMinutes: 0,
        panelSync: 'unchanged',
        payload: await this.payloadFor(planned.sessionId),
      };
    }

    // disconnect / 0-minute grant: nothing to mirror to the panel.
    if (planned.grantedMinutes === 0 || !planned.opId) {
      return {
        sessionId: planned.sessionId,
        expiresAt: planned.newExpires.toISOString(),
        grantedMinutes: 0,
        panelSync: 'unchanged',
      };
    }

    // ===== Phase B: external panel call, NO database locks held =====
    let panelSync: 'synced' | 'pending' = 'pending';
    try {
      await this.panel.setUserExpiry(planned.panelUsername, planned.newExpires);
      await pool.query(
        `update panel_operations set status='succeeded', completed_at=now() where id=$1`,
        [planned.opId],
      );
      await pool.query(`update vpn_sessions set last_panel_sync_at=now() where id=$1`, [
        planned.sessionId,
      ]);
      panelSync = 'synced';
    } catch (err) {
      // The session expiry is already authoritative in our DB; the outbox
      // worker will converge the panel. Never fail the user's request for a
      // transient panel hiccup.
      const msg = err instanceof Error ? err.message : String(err);
      this.log.error(`panel extend failed for ${planned.panelUsername}; queued for retry: ${msg}`);
      await pool.query(
        `update panel_operations
            set status='failed', last_error=$2, next_attempt_at = now() + interval '15 seconds'
          where id=$1`,
        [planned.opId, msg.slice(0, 500)],
      );
    }

    return {
      sessionId: planned.sessionId,
      expiresAt: planned.newExpires.toISOString(),
      grantedMinutes: planned.grantedMinutes,
      panelSync,
      // Deliver the encrypted config now that the ads are verified and the panel
      // user is extended. Built outside any DB lock (CPU + one sensitive read).
      payload: await this.payloadFor(planned.sessionId),
    };
  }

  /** Build the encrypted config for a now-funded session (free-tier delivery). */
  private async payloadFor(sessionId: string): Promise<EncryptedPayloadDto | undefined> {
    try {
      return await this.sessionConfig.encryptedPayloadForSession(sessionId);
    } catch (e) {
      // Don't fail the (already-committed) reward over a payload build hiccup —
      // the client surfaces a missing payload and reconnects.
      this.log.error(`payload build failed for session ${sessionId}: ${(e as Error).message}`);
      return undefined;
    }
  }
}
