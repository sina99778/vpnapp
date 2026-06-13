import { Controller, Get, ServiceUnavailableException } from '@nestjs/common';
import { pool } from './db/pool';

/**
 * GET /api/v1/health — unauthenticated liveness+readiness probe for the load
 * balancer / compose / k8s. Pings the DB so a pod with a dead pool is taken out
 * of rotation. Not rate-limited (the throttler is scoped to AuthController).
 */
@Controller('health')
export class HealthController {
  @Get()
  async health(): Promise<{ status: string; db: string }> {
    try {
      await pool.query('select 1');
      return { status: 'ok', db: 'up' };
    } catch {
      throw new ServiceUnavailableException({ status: 'degraded', db: 'down' });
    }
  }
}
