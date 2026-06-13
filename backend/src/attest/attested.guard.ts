import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { timingSafeEqual } from 'crypto';
import { pool } from '../db/pool';
import type { AuthUser } from '../auth/current-user.decorator';

/**
 * Gate for /connect. Enforces BOTH halves of the attestation guarantee:
 *   1. the device passed attestation and the window has not lapsed, AND
 *   2. the `clientPublicKey` in THIS request is the exact key that attestation
 *      bound (devices.attested_client_public_key).
 *
 * Without (2) the binding is only verified at /verify time and an attacker could
 * attest key A then connect with key B. Apply AFTER JwtAuthGuard:
 *   @UseGuards(JwtAuthGuard, AttestedGuard)
 *   @Post('connect') ...
 *
 * NOTE: /connect MUST carry `clientPublicKey` (base64) in its body — the Phase-2
 * client always sends it. A request without it is rejected.
 */
@Injectable()
export class AttestedGuard implements CanActivate {
  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx
      .switchToHttp()
      .getRequest<{
        user?: AuthUser;
        body?: { clientPublicKey?: string };
        attestedClientPublicKey?: Buffer;
      }>();
    const deviceId = req.user?.deviceId;
    if (!deviceId) throw new ForbiddenException('unauthenticated');

    const clientPubB64 = req.body?.clientPublicKey;
    if (!clientPubB64) throw new ForbiddenException('missing clientPublicKey');
    let presented: Buffer;
    try {
      presented = Buffer.from(clientPubB64, 'base64');
    } catch {
      throw new ForbiddenException('bad clientPublicKey');
    }

    const { rows } = await pool.query(
      `select d.is_attested, d.attested_until, d.attested_client_public_key, d.status,
              u.is_banned, u.status as user_status
         from devices d join users u on u.id = d.user_id
        where d.id = $1`,
      [deviceId],
    );
    const dev = rows[0];

    // (0) banned / non-active user → hard stop (also enforced when sessions are
    //     revoked at ban time; this prevents a banned user from reconnecting).
    if (dev && (dev.is_banned === true || dev.user_status !== 'active')) {
      throw new ForbiddenException('account suspended');
    }

    // (1) coarse gate: attested, not expired, device active.
    if (
      !dev ||
      dev.status !== 'active' ||
      dev.is_attested !== true ||
      !dev.attested_until ||
      new Date(dev.attested_until) <= new Date()
    ) {
      throw new ForbiddenException('device attestation required');
    }

    // (2) binding: the presented key MUST equal the attested key (constant time).
    const bound = dev.attested_client_public_key as Buffer | null;
    if (!bound || bound.length !== presented.length || !timingSafeEqual(bound, presented)) {
      throw new ForbiddenException('key not bound to attestation');
    }
    // Hand the canonical attested key to downstream handlers (used for ECDH).
    req.attestedClientPublicKey = bound;
    return true;
  }
}
