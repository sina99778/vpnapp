import { Inject, Injectable, Logger } from '@nestjs/common';
import { randomUUID, randomBytes } from 'crypto';
import type { PoolClient } from 'pg';
import { pool, withTransaction } from '../db/pool';
import { randomUrlToken } from '../common/http';
import { IPanelClient, PANEL_CLIENT } from '../panel/IPanelClient';
import { PanelError } from '../panel/panel.types';
import { PayloadCipher, EncryptedPayloadDto } from './payload-cipher';
import { buildSingboxConfig } from './config-builder';

export class ConnectError extends Error {
  constructor(
    readonly reason: string,
    readonly httpStatus = 503,
  ) {
    super(reason);
    this.name = 'ConnectError';
  }
}

type Tier = 'free' | 'premium';

export type ConnectResult =
  | { tier: 'premium'; sessionId: string; expiresAt: string; payload: EncryptedPayloadDto }
  | {
      tier: 'free';
      sessionId: string;
      grantId: string;
      nonce: string;
      requiredAds: number;
      provisioningExpiresAt: string;
    };

interface NodePick {
  nodeId: string;
  inboundTag: string;
  protocol: string;
}
interface TxResult {
  sessionId: string;
  panelUsername: string;
  credentialRef: string;
  node: NodePick;
  revokeUsernames: string[];
  grantId: string | null;
  nonce: string | null;
}

// Tunables (env-overridable). Free: 1 concurrent, 5-min provisioning window.
const FREE_MAX = Number(process.env.FREE_MAX_SESSIONS ?? 1);
const PREMIUM_MAX = Number(process.env.PREMIUM_MAX_SESSIONS ?? 3);
const FREE_TTL_MS = Number(process.env.FREE_PROVISIONING_TTL_MS ?? 5 * 60_000);
const PREMIUM_FALLBACK_TTL_MS = Number(process.env.PREMIUM_FALLBACK_TTL_MS ?? 30 * 24 * 60 * 60_000);
const REQUIRED_ADS = Number(process.env.CONNECT_REQUIRED_ADS ?? 2);
const GRANT_MINUTES = Number(process.env.CONNECT_GRANT_MINUTES ?? 60);
const VLESS_FLOW = process.env.VLESS_FLOW ?? 'xtls-rprx-vision';

/**
 * The /connect flow. Strict lock discipline: ALL panel/network I/O happens with
 * NO database transaction open. The DB transaction only does fast local work
 * (concurrency check, session insert, grant insert, revoke bookkeeping), then
 * commits; panel provisioning runs afterward and fails SAFE.
 */
@Injectable()
export class ConnectionService {
  private readonly log = new Logger(ConnectionService.name);

  constructor(
    @Inject(PANEL_CLIENT) private readonly panel: IPanelClient,
    private readonly cipher: PayloadCipher,
  ) {}

  async connect(input: { userId: string; deviceId: string; clientPubKey: Buffer }): Promise<ConnectResult> {
    // Resolve tier AND expiry in ONE authoritative read — a lapsed subscription
    // can never yield premium (the query mirrors effective_tier exactly).
    const { tier, expiresAt } = await this.resolveTierAndExpiry(input.userId);
    const maxConcurrent = tier === 'premium' ? PREMIUM_MAX : FREE_MAX;

    // ── Phase A: ONE serializable tx, NO panel calls. ──
    const tx = await withTransaction<TxResult>(async (c) => {
      // Lock the user's live sessions so the concurrency decision is race-free.
      const live = await c.query(
        `select id, panel_username from vpn_sessions
          where user_id = $1 and status in ('provisioning','active','limited')
          order by created_at asc
          for update`,
        [input.userId],
      );

      const revokeUsernames: string[] = [];
      if (live.rows.length >= maxConcurrent) {
        const overBy = live.rows.length - maxConcurrent + 1; // make room for the new one
        for (const r of live.rows.slice(0, overBy)) {
          await c.query(
            `update vpn_sessions set status='revoked', closed_at=now(), close_reason='concurrency' where id=$1`,
            [r.id],
          );
          // Durable revoke (the outbox worker guarantees the panel converges
          // even if the inline call below fails).
          await c.query(
            `insert into panel_operations (session_id, op, payload, status, next_attempt_at)
             values ($1, 'revoke_user', $2, 'pending', now())`,
            [r.id, { panel_username: r.panel_username }],
          );
          revokeUsernames.push(r.panel_username as string);
        }
      }

      const node = await this.pickNode(c, tier);
      if (!node) throw new ConnectError('no_node_capacity');

      const panelUsername = `s_${base62(22)}`;
      const credentialRef = randomUUID();
      const ins = await c.query(
        `insert into vpn_sessions
           (user_id, device_id, node_id, tier, status, panel_username, credential_ref,
            inbound_tag, protocol, client_public_key, expires_at)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         returning id`,
        [
          input.userId,
          input.deviceId,
          node.nodeId,
          tier,
          tier === 'premium' ? 'active' : 'provisioning',
          panelUsername,
          credentialRef,
          node.inboundTag,
          node.protocol,
          input.clientPubKey, // bound to THIS session's payload encryption
          expiresAt,
        ],
      );
      const sessionId = ins.rows[0].id as string;

      let grantId: string | null = null;
      let nonce: string | null = null;
      if (tier === 'free') {
        nonce = randomUrlToken(32);
        const g = await c.query(
          `insert into ad_reward_grants
             (user_id, device_id, session_id, purpose, nonce, required_ads, grant_minutes, status, expires_at)
           values ($1,$2,$3,'connect',$4,$5,$6,'pending',$7)
           returning id`,
          [input.userId, input.deviceId, sessionId, nonce, REQUIRED_ADS, GRANT_MINUTES, expiresAt],
        );
        grantId = g.rows[0].id as string;
      }

      return { sessionId, panelUsername, credentialRef, node, revokeUsernames, grantId, nonce };
    }, 'serializable');

    // ── Phase B: panel I/O, NO locks held. ──
    // 1) Revoke the displaced sessions (best-effort; outbox is the guarantee).
    for (const username of tx.revokeUsernames) {
      try {
        await this.panel.disableUser(username);
        await this.panel.deleteUser(username);
        await pool.query(
          `update panel_operations set status='succeeded', completed_at=now()
             where op='revoke_user' and status='pending' and payload->>'panel_username' = $1`,
          [username],
        );
      } catch (e) {
        this.log.warn(`inline revoke of ${username} failed; outbox will retry: ${(e as Error).message}`);
      }
    }

    // 2) Provision the new ephemeral user. Fail SAFE on any panel error.
    try {
      await this.panel.createUser({
        username: tx.panelUsername,
        expireAt: expiresAt,
        proxies: { [tx.node.protocol]: { id: tx.credentialRef, flow: VLESS_FLOW } },
        inboundsByProtocol: { [tx.node.protocol]: [tx.node.inboundTag] }, // tier-scoped, non-empty
      });
      // Round-trip the expiry — a seconds/ms mix-up on a Marzban fork would
      // otherwise silently make the session never expire.
      const stored = await this.panel.getUser(tx.panelUsername);
      if (!stored || !expiryMatches(stored.expireAt, expiresAt)) {
        throw new PanelError('expiry round-trip mismatch', undefined, false);
      }
    } catch (e) {
      await this.failSession(tx.sessionId, tx.panelUsername);
      this.log.error(`provisioning failed for session ${tx.sessionId}: ${(e as Error).message}`);
      throw new ConnectError('provision_failed');
    }

    // ── Phase C: build the response. ──
    if (tier === 'premium') {
      await pool.query(`update vpn_sessions set activated_at = now() where id = $1`, [tx.sessionId]);
      const payload = await this.buildPayload(tx, input.clientPubKey);
      return { tier: 'premium', sessionId: tx.sessionId, expiresAt: expiresAt.toISOString(), payload };
    }
    // Free: NO payload here — it is delivered by verify-ad-reward after the ads.
    return {
      tier: 'free',
      sessionId: tx.sessionId,
      grantId: tx.grantId!,
      nonce: tx.nonce!,
      requiredAds: REQUIRED_ADS,
      provisioningExpiresAt: expiresAt.toISOString(),
    };
  }

  // ── helpers ──────────────────────────────────────────────────────────────

  /**
   * Single source of truth for tier + expiry. The premium query is identical to
   * effective_tier()'s rule (active/in_grace AND period not lapsed), so a lapsed
   * subscriber resolves to FREE — never to a fallback-length premium session.
   */
  private async resolveTierAndExpiry(userId: string): Promise<{ tier: Tier; expiresAt: Date }> {
    const { rows } = await pool.query(
      `select s.current_period_end
         from subscriptions s join plans p on p.id = s.plan_id
        where s.user_id = $1 and p.tier = 'premium' and s.status in ('active','in_grace')
          and (s.current_period_end is null or s.current_period_end > now())
        order by s.current_period_end desc nulls last
        limit 1`,
      [userId],
    );
    if (rows.length === 0) {
      return { tier: 'free', expiresAt: new Date(Date.now() + FREE_TTL_MS) };
    }
    const end = rows[0].current_period_end as Date | null;
    // A null period end = unlimited plan (promo/internal) → bound it to a cap
    // that is re-evaluated on every connect, so it is never truly unbounded.
    const expiresAt = end ? new Date(end) : new Date(Date.now() + PREMIUM_FALLBACK_TTL_MS);
    return { tier: 'premium', expiresAt };
  }

  private async pickNode(c: PoolClient, tier: Tier): Promise<NodePick | null> {
    // Free → free nodes + free inbounds only. Premium → free or premium, both.
    const allowed = tier === 'premium' ? ['free', 'premium'] : ['free'];
    const { rows } = await c.query(
      `select n.id as node_id, ni.inbound_tag, ni.protocol
         from nodes n
         join node_inbounds ni on ni.node_id = n.id
        where n.status = 'active'
          and n.is_active                       -- admin not draining this node
          and n.tier = any($1::plan_tier[])
          and ni.tier = any($1::plan_tier[])
          and exists (select 1 from node_endpoints ne
                       where ne.node_id = n.id and ne.inbound_tag = ni.inbound_tag and ne.is_active)
        order by n.current_load asc, n.sort_weight asc
        limit 1`,
      [allowed],
    );
    if (rows.length === 0) return null;
    return { nodeId: rows[0].node_id, inboundTag: rows[0].inbound_tag, protocol: rows[0].protocol };
  }

  private async buildPayload(tx: TxResult, clientPubKey: Buffer): Promise<EncryptedPayloadDto> {
    // Sensitive read: only this code path touches node_endpoints.
    const { rows } = await pool.query(
      `select address, port, security from node_endpoints
        where node_id = $1 and inbound_tag = $2 and is_active
        limit 1`,
      [tx.node.nodeId, tx.node.inboundTag],
    );
    if (rows.length === 0) throw new ConnectError('endpoint_unavailable');
    const ep = rows[0];
    const configJson = buildSingboxConfig({
      protocol: tx.node.protocol,
      address: ep.address,
      port: ep.port,
      uuid: tx.credentialRef,
      flow: VLESS_FLOW,
      security: ep.security ?? {},
    });
    return this.cipher.encryptFor(configJson, tx.sessionId, clientPubKey);
  }

  private async failSession(sessionId: string, panelUsername: string): Promise<void> {
    await pool
      .query(
        `update vpn_sessions set status='failed', closed_at=now(), close_reason='panel_provision_failed'
           where id = $1`,
        [sessionId],
      )
      .catch(() => undefined);
    // Reclaim any partially-created user via the outbox.
    await pool
      .query(
        `insert into panel_operations (session_id, op, payload, status, next_attempt_at)
         values ($1, 'delete_user', $2, 'pending', now())`,
        [sessionId, { panel_username: panelUsername }],
      )
      .catch(() => undefined);
  }
}

function base62(len: number): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i++) out += alphabet[bytes[i] % 62];
  return out;
}

/** Compare to the second — panels store expiry as a unix-seconds integer. */
function expiryMatches(a: Date | null, b: Date): boolean {
  if (!a) return false;
  return Math.abs(Math.floor(a.getTime() / 1000) - Math.floor(b.getTime() / 1000)) <= 2;
}
