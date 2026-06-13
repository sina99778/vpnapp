import { Injectable } from '@nestjs/common';
import { createHash, randomBytes } from 'crypto';
import jwt, { Algorithm } from 'jsonwebtoken';

/**
 * Mints the two token types. Kept separate from AuthService so the crypto is in
 * one auditable place and matches what JwtAuthGuard verifies (sub=userId,
 * did=deviceId).
 *
 *   • Access token  — short-lived JWT (15 min). Signed HS256 (JWT_SECRET) or
 *     RS256 (JWT_PRIVATE_KEY); the guard verifies with JWT_SECRET / JWT_PUBLIC_KEY.
 *   • Refresh token — opaque 256-bit random string. Only its SHA-256 is stored;
 *     the raw value is shown to the client exactly once.
 */
const PRIVATE_KEY = process.env.JWT_PRIVATE_KEY;
const SECRET = process.env.JWT_SECRET;
const SIGN_ALG: Algorithm = PRIVATE_KEY ? 'RS256' : 'HS256';
const SIGN_KEY = PRIVATE_KEY ?? SECRET ?? '';
const ISSUER = process.env.JWT_ISSUER;
const AUDIENCE = process.env.JWT_AUDIENCE;
const ACCESS_TTL = process.env.ACCESS_TOKEN_TTL ?? '15m';
const REFRESH_TTL_MS = Number(process.env.REFRESH_TOKEN_TTL_MS ?? 30 * 24 * 60 * 60_000); // 30d

/**
 * Sentinel `did` for device-less ADMIN tokens. It is a valid-but-nonexistent
 * UUID, so the AttestedGuard's device lookup returns no rows (clean 403) — an
 * admin token therefore can never be used on a VPN route like /connect.
 */
export const ADMIN_DID = '00000000-0000-0000-0000-000000000000';

@Injectable()
export class TokenService {
  /** Access JWT bound to (userId, deviceId). */
  signAccess(userId: string, deviceId: string): string {
    if (!SIGN_KEY) throw new Error('JWT signing key not configured');
    const options: jwt.SignOptions = {
      algorithm: SIGN_ALG,
      subject: userId, // → sub
      // @types/jsonwebtoken v9 types this as a template-literal union; the env
      // string ('15m', '900s', …) is parsed by `ms` at runtime.
      expiresIn: ACCESS_TTL as jwt.SignOptions['expiresIn'],
      ...(ISSUER ? { issuer: ISSUER } : {}),
      ...(AUDIENCE ? { audience: AUDIENCE } : {}),
    };
    return jwt.sign({ did: deviceId }, SIGN_KEY, options);
  }

  /** A fresh opaque refresh token (raw value — return to client, never store). */
  newRefreshRaw(): string {
    return randomBytes(32).toString('base64url');
  }

  /** What we persist: sha256(raw) as bytea. Lookups hash the presented token. */
  hashRefresh(raw: string): Buffer {
    return createHash('sha256').update(raw).digest();
  }

  refreshExpiry(): Date {
    return new Date(Date.now() + REFRESH_TTL_MS);
  }

  get accessTtl(): string {
    return ACCESS_TTL;
  }
}
