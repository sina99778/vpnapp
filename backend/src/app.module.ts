import { Module } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { ThrottlerModule, ThrottlerModuleOptions } from '@nestjs/throttler';
import { ThrottlerStorageRedisService } from 'nestjs-throttler-storage-redis';
import Redis from 'ioredis';
import { CoreModule } from './core/core.module';
import { AuthModule } from './auth/auth.module';
import { AttestModule } from './attest/attest.module';
import { ConnectionModule } from './connection/connection.module';
import { AdsModule } from './ads/ads.module';
import { AdminModule } from './admin/admin.module';
import { AdminAuthModule } from './admin-auth/admin-auth.module';
import { TelegramModule } from './telegram/telegram.module';
import { WorkersModule } from './workers/workers.module';
import { HealthController } from './health.controller';

// The Telegram Ops bot launches a live connection on boot, so only wire it when
// a token is configured — the app boots fine without it.
const optionalModules = process.env.TELEGRAM_BOT_TOKEN ? [TelegramModule] : [];

/**
 * Throttler config: shared across instances via Redis when REDIS_URL is set
 * (so per-IP limits hold when horizontally scaled), else in-memory for local
 * dev. lazyConnect → no Redis connection attempt until the first throttle check.
 */
function throttlerOptions(): ThrottlerModuleOptions {
  const base: ThrottlerModuleOptions = { throttlers: [{ ttl: 60_000, limit: 60 }] };
  if (process.env.REDIS_URL) {
    const redis = new Redis(process.env.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 3 });
    return { ...base, storage: new ThrottlerStorageRedisService(redis) };
  }
  return base;
}

/**
 * Root module. Wires:
 *   • ScheduleModule.forRoot()  — enables @Cron/@Interval for the workers.
 *   • CoreModule (@Global)      — the shared Rebecca panel client.
 *   • AttestModule              — /device/attest/* + the AttestedGuard.
 *   • ConnectionModule          — /connect + payload cipher.
 *   • AdsModule                 — /ads/* (request-ad-token, verify, SSV).
 *   • WorkersModule             — reaper + outbox drainer.
 *
 * The DB pool is a module-level singleton (db/pool.ts), shared by all of the
 * above; there is no Nest provider to wire for it.
 */
@Module({
  imports: [
    ScheduleModule.forRoot(),
    // Per-IP backstop; AuthController applies tighter per-route limits. Redis-
    // backed when REDIS_URL is set so limits hold across horizontally-scaled
    // instances.
    ThrottlerModule.forRoot(throttlerOptions()),
    CoreModule,
    AuthModule,
    AttestModule,
    ConnectionModule,
    AdsModule,
    AdminModule,
    AdminAuthModule,
    WorkersModule,
    ...optionalModules,
  ],
  controllers: [HealthController],
})
export class AppModule {}
