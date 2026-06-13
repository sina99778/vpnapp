import {
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { randomUUID } from 'crypto';
import * as argon2 from 'argon2';
import type { PoolClient } from 'pg';
import { pool, withTransaction } from '../db/pool';
import { TokenService, ADMIN_DID } from './token.service';

export type Platform = 'android' | 'ios';

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: string;
}

// Argon2id, tunable at deploy time (raise params after a security audit without
// a rebuild). Defaults exceed OWASP minimums.
const ARGON_OPTS: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: Number(process.env.ARGON_MEMORY_MIB ?? 64) * 1024, // KiB
  timeCost: Number(process.env.ARGON_TIME_COST ?? 3),
  parallelism: Number(process.env.ARGON_PARALLELISM ?? 4),
};
const MAX_FAILED = Number(process.env.LOGIN_MAX_FAILED ?? 5);
const LOCKOUT_MS = Number(process.env.LOGIN_LOCKOUT_MS ?? 15 * 60_000);

@Injectable()
export class AuthService {
  private readonly log = new Logger(AuthService.name);
  /** Fixed dummy hash so a login for an unknown email still spends ~argon2 time. */
  private dummyHash?: Promise<string>;

  constructor(private readonly tokens: TokenService) {}

  // ── POST /auth/anon ──────────────────────────────────────────────────────
  /** First launch: anonymous user + device + first refresh token (new family). */
  async anon(input: { platform: Platform; installId: string; appVersion?: string }): Promise<TokenPair> {
    const result = await withTransaction(async (c) => {
      const u = await c.query(`insert into users (is_anonymous) values (true) returning id`);
      const userId = u.rows[0].id as string;
      const d = await c.query(
        `insert into devices (user_id, platform, install_id, app_version)
         values ($1,$2,$3,$4) returning id`,
        [userId, input.platform, input.installId, input.appVersion ?? null],
      );
      const deviceId = d.rows[0].id as string;
      const refreshRaw = await this.issueRefresh(c, userId, deviceId, randomUUID(), null);
      return { userId, deviceId, refreshRaw };
    });
    return this.pair(result.userId, result.deviceId, result.refreshRaw);
  }

  // ── POST /auth/register (access-token protected) ─────────────────────────
  /** Claim an anonymous account with email + password. */
  async register(userId: string, email: string, password: string): Promise<{ ok: true }> {
    // Hash OUTSIDE any transaction — argon2 is intentionally slow (~100ms); we
    // never hold a DB row lock across it.
    const passwordHash = await argon2.hash(password, ARGON_OPTS);

    try {
      await withTransaction(async (c) => {
        const u = await c.query(
          `select is_anonymous from users where id=$1 and status='active' for update`,
          [userId],
        );
        if (u.rowCount === 0) throw new UnauthorizedException('user not found');
        if (u.rows[0].is_anonymous !== true) throw new ConflictException('account already registered');
        await c.query(
          `update users set email=$2, password_hash=$3, is_anonymous=false, updated_at=now()
            where id=$1`,
          [userId, email.toLowerCase(), passwordHash],
        );
      });
    } catch (e) {
      // citext unique index on email → 23505 means the email is taken.
      if ((e as { code?: string }).code === '23505') throw new ConflictException('email already in use');
      throw e;
    }
    return { ok: true };
  }

  // ── POST /auth/login ─────────────────────────────────────────────────────
  /** Email/password auth with per-user lockout. Establishes/links the device. */
  async login(input: {
    email: string;
    password: string;
    platform: Platform;
    installId: string;
    appVersion?: string;
  }): Promise<TokenPair> {
    const email = input.email.toLowerCase();
    const { rows } = await pool.query(
      `select id, password_hash, status, failed_login_count, locked_until
         from users where email=$1`,
      [email],
    );
    const user = rows[0];

    // Locked? Reject without revealing whether the password was right.
    if (user?.locked_until && new Date(user.locked_until) > new Date()) {
      throw new ForbiddenException('account temporarily locked');
    }

    // Verify (always spend argon2 time — even for unknown emails — to avoid a
    // timing oracle that reveals which emails exist).
    const ok =
      user && user.password_hash && user.status === 'active'
        ? await argon2.verify(user.password_hash, input.password)
        : (await this.verifyDummy(input.password), false);

    if (!ok) {
      if (user) await this.recordFailedLogin(user.id);
      throw new UnauthorizedException('invalid credentials');
    }

    // Success → reset lockout, find-or-create the device, issue a fresh family.
    // Re-check lockout under FOR UPDATE: a flurry of concurrent failures could
    // have locked the account between our stale read and here.
    return withTransaction(async (c) => {
      const fresh = await c.query(`select locked_until from users where id=$1 for update`, [user.id]);
      const lockedUntil = fresh.rows[0]?.locked_until;
      if (lockedUntil && new Date(lockedUntil) > new Date()) {
        throw new ForbiddenException('account temporarily locked');
      }
      await c.query(`update users set failed_login_count=0, locked_until=null where id=$1`, [user.id]);
      const deviceId = await this.findOrCreateDevice(c, user.id, input);
      const refreshRaw = await this.issueRefresh(c, user.id, deviceId, randomUUID(), null);
      return this.pair(user.id, deviceId, refreshRaw);
    }, 'serializable');
  }

  // ── POST /auth/refresh ───────────────────────────────────────────────────
  /** Rotate. Reusing an already-rotated token revokes the whole family. */
  async refresh(rawToken: string): Promise<TokenPair> {
    const hash = this.tokens.hashRefresh(rawToken);

    const outcome = await withTransaction(async (c) => {
      const r = await c.query(
        `select id, user_id, device_id, family_id, expires_at, revoked_at
           from refresh_tokens where token_hash=$1 for update`,
        [hash],
      );
      if (r.rowCount === 0) return { kind: 'invalid' as const };
      const row = r.rows[0];

      // REUSE DETECTION: a token that was already revoked is being replayed →
      // assume theft and revoke every live token in the lineage.
      if (row.revoked_at) {
        await c.query(
          `update refresh_tokens set revoked_at=now(), revoke_reason='reuse_detected'
            where family_id=$1 and revoked_at is null`,
          [row.family_id],
        );
        return { kind: 'reuse' as const, userId: row.user_id as string, familyId: row.family_id as string };
      }
      if (new Date(row.expires_at) <= new Date()) {
        await c.query(`update refresh_tokens set revoked_at=now(), revoke_reason='expired' where id=$1`, [
          row.id,
        ]);
        return { kind: 'expired' as const };
      }

      // Rotate: revoke the presented token, issue its successor in the same family.
      await c.query(`update refresh_tokens set revoked_at=now(), revoke_reason='rotated' where id=$1`, [
        row.id,
      ]);
      const refreshRaw = await this.issueRefresh(
        c,
        row.user_id,
        row.device_id,
        row.family_id,
        row.id,
      );
      return {
        kind: 'rotated' as const,
        userId: row.user_id as string,
        // device-less (admin) refresh rows re-mint with the nil-UUID sentinel.
        deviceId: (row.device_id as string | null) ?? ADMIN_DID,
        refreshRaw,
      };
    }, 'serializable');

    switch (outcome.kind) {
      case 'invalid':
      case 'expired':
        throw new UnauthorizedException('invalid refresh token');
      case 'reuse':
        this.log.warn(`refresh reuse detected; revoked family ${outcome.familyId}`);
        throw new UnauthorizedException('session revoked — please sign in again');
      case 'rotated':
        return this.pair(outcome.userId, outcome.deviceId, outcome.refreshRaw);
    }
  }

  // ── POST /auth/logout (access-token protected) ───────────────────────────
  /**
   * Revoke the presented refresh token's whole family. Requires the caller's
   * access token AND that the refresh token belongs to that same user — so a
   * stolen/phished refresh token cannot be used to revoke a victim's family.
   * Atomic (FOR UPDATE) to avoid racing a concurrent /refresh in the family.
   */
  async logout(userId: string, rawToken: string): Promise<{ ok: true }> {
    const hash = this.tokens.hashRefresh(rawToken);
    await withTransaction(async (c) => {
      const r = await c.query(
        `select family_id, user_id from refresh_tokens where token_hash=$1 for update`,
        [hash],
      );
      if (r.rowCount === 0) return; // unknown token → idempotent no-op
      if (r.rows[0].user_id !== userId) {
        throw new ForbiddenException('refresh token does not belong to caller');
      }
      await c.query(
        `update refresh_tokens set revoked_at=now(), revoke_reason='logout'
          where family_id=$1 and revoked_at is null`,
        [r.rows[0].family_id],
      );
    }, 'serializable');
    return { ok: true };
  }

  // ── helpers ───────────────────────────────────────────────────────────────

  private async issueRefresh(
    c: PoolClient,
    userId: string,
    deviceId: string | null, // null for device-less admin sessions
    familyId: string,
    rotatedFrom: string | null,
  ): Promise<string> {
    const raw = this.tokens.newRefreshRaw();
    await c.query(
      `insert into refresh_tokens (user_id, device_id, family_id, token_hash, expires_at, rotated_from)
       values ($1,$2,$3,$4,$5,$6)`,
      [userId, deviceId, familyId, this.tokens.hashRefresh(raw), this.tokens.refreshExpiry(), rotatedFrom],
    );
    return raw;
  }

  private async findOrCreateDevice(
    c: PoolClient,
    userId: string,
    input: { platform: Platform; installId: string; appVersion?: string },
  ): Promise<string> {
    const existing = await c.query(`select id from devices where user_id=$1 and install_id=$2`, [
      userId,
      input.installId,
    ]);
    if (existing.rowCount && existing.rowCount > 0) return existing.rows[0].id as string;
    const d = await c.query(
      `insert into devices (user_id, platform, install_id, app_version)
       values ($1,$2,$3,$4) returning id`,
      [userId, input.platform, input.installId, input.appVersion ?? null],
    );
    return d.rows[0].id as string;
  }

  private async recordFailedLogin(userId: string): Promise<void> {
    // Atomic increment + conditional lock. No read-modify-write race.
    await pool.query(
      `update users
          set failed_login_count = failed_login_count + 1,
              locked_until = case when failed_login_count + 1 >= $2
                                  then now() + ($3::int * interval '1 millisecond')
                                  else locked_until end
        where id = $1`,
      [userId, MAX_FAILED, LOCKOUT_MS],
    );
  }

  private async verifyDummy(password: string): Promise<void> {
    if (!this.dummyHash) this.dummyHash = argon2.hash('dummy-password-for-timing', ARGON_OPTS);
    try {
      await argon2.verify(await this.dummyHash, password);
    } catch {
      /* timing only */
    }
  }

  private pair(userId: string, deviceId: string, refreshRaw: string): TokenPair {
    return {
      accessToken: this.tokens.signAccess(userId, deviceId),
      refreshToken: refreshRaw,
      tokenType: 'Bearer',
      expiresIn: this.tokens.accessTtl,
    };
  }
}
