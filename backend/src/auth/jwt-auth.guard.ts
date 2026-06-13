import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import jwt, { Algorithm } from 'jsonwebtoken';
import type { Request } from 'express';
import type { AuthUser } from './current-user.decorator';

/**
 * Verifies the access-JWT SIGNATURE server-side on every protected route — never
 * trusting TLS/pinning alone (a pinning bypass on a rooted device must not let an
 * attacker mint a principal). The verified { userId, deviceId } is attached to
 * request.user for @CurrentUser() and the AttestedGuard.
 *
 * Claims contract: `sub` = userId, `did` = deviceId. Configure either
 * JWT_PUBLIC_KEY (RS256/ES256) or JWT_SECRET (HS256) via env.
 */
const PUBLIC_KEY = process.env.JWT_PUBLIC_KEY;
const SECRET = process.env.JWT_SECRET;
const ALGS: Algorithm[] = PUBLIC_KEY ? ['RS256', 'ES256'] : ['HS256'];
const KEY = PUBLIC_KEY ?? SECRET ?? '';
const ISSUER = process.env.JWT_ISSUER;
const AUDIENCE = process.env.JWT_AUDIENCE;

@Injectable()
export class JwtAuthGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request & { user?: AuthUser }>();
    const header = req.headers['authorization'];
    if (!header || !header.startsWith('Bearer ')) {
      throw new UnauthorizedException('missing bearer token');
    }
    if (!KEY) throw new UnauthorizedException('auth not configured');

    try {
      const payload = jwt.verify(header.slice(7), KEY, {
        algorithms: ALGS,
        ...(ISSUER ? { issuer: ISSUER } : {}),
        ...(AUDIENCE ? { audience: AUDIENCE } : {}),
      }) as { sub?: string; did?: string };

      if (!payload.sub || !payload.did) throw new Error('missing sub/did');
      req.user = { userId: payload.sub, deviceId: payload.did };
      return true;
    } catch (e) {
      // Never leak why (expired vs malformed vs wrong-key) to the caller.
      throw new UnauthorizedException('invalid token');
    }
  }
}
