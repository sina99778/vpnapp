import { ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { randomUUID } from 'crypto';
import * as argon2 from 'argon2';
import { pool } from '../db/pool';
import { TokenService, ADMIN_DID } from '../auth/token.service';

export interface AdminTokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: string;
}

/**
 * Dedicated admin login. Unlike the VPN /auth/login it creates NO device and
 * does NO attestation binding — admins drive the dashboard, not the tunnel.
 *
 * The access JWT carries a nil-UUID `did` sentinel (so it's rejected on VPN
 * routes), and the refresh token is stored with device_id = NULL. The existing
 * /auth/refresh rotates it transparently (re-minting with the sentinel `did`).
 */
@Injectable()
export class AdminAuthService {
  private dummyHash?: Promise<string>;

  constructor(private readonly tokens: TokenService) {}

  async login(email: string, password: string): Promise<AdminTokenPair> {
    const { rows } = await pool.query(
      `select id, password_hash, role, is_banned, status from users where email = $1`,
      [email.toLowerCase()],
    );
    const u = rows[0];

    // Always spend argon2 time (dummy for unknown emails) → no timing oracle.
    const passwordOk =
      u && u.password_hash && u.status === 'active'
        ? await argon2.verify(u.password_hash, password)
        : (await this.verifyDummy(password), false);

    if (!passwordOk) throw new UnauthorizedException('invalid credentials');

    // STRICT: only an active, non-banned admin. (Checked after the password so a
    // non-admin can't enumerate via the response — they already proved the pw.)
    if (u.role !== 'admin' || u.is_banned === true) {
      throw new ForbiddenException('not an administrator');
    }

    // Device-less refresh token, fresh family.
    const refreshRaw = this.tokens.newRefreshRaw();
    await pool.query(
      `insert into refresh_tokens (user_id, device_id, family_id, token_hash, expires_at)
       values ($1, NULL, $2, $3, $4)`,
      [u.id, randomUUID(), this.tokens.hashRefresh(refreshRaw), this.tokens.refreshExpiry()],
    );

    return {
      accessToken: this.tokens.signAccess(u.id, ADMIN_DID),
      refreshToken: refreshRaw,
      tokenType: 'Bearer',
      expiresIn: this.tokens.accessTtl,
    };
  }

  private async verifyDummy(password: string): Promise<void> {
    if (!this.dummyHash) this.dummyHash = argon2.hash('dummy-password-for-timing', { type: argon2.argon2id });
    try {
      await argon2.verify(await this.dummyHash, password);
    } catch {
      /* timing only */
    }
  }
}
