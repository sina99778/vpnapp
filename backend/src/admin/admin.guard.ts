import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { pool } from '../db/pool';
import type { AuthUser } from '../auth/current-user.decorator';

/**
 * Admin authorization. Apply AFTER JwtAuthGuard. Resolves role + ban status
 * with a FRESH DB read (never from the JWT) so a demotion or ban takes effect
 * on the very next request — no waiting for the 15-min access token to expire.
 *
 *   @UseGuards(JwtAuthGuard, AdminGuard)
 */
@Injectable()
export class AdminGuard implements CanActivate {
  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<{ user?: AuthUser & { role?: string } }>();
    const userId = req.user?.userId;
    if (!userId) throw new ForbiddenException('unauthenticated');

    const { rows } = await pool.query(
      `select role, is_banned, status from users where id = $1`,
      [userId],
    );
    const u = rows[0];
    if (!u || u.is_banned === true || u.status !== 'active' || u.role !== 'admin') {
      throw new ForbiddenException('admin access required');
    }
    req.user!.role = 'admin';
    return true;
  }
}
