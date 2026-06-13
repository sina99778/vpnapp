// MUST be first — enables decorator metadata for @Injectable/@UseGuards/etc.
import 'reflect-metadata';
import { Logger, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { json, urlencoded } from 'express';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './common/all-exceptions.filter';

async function bootstrap(): Promise<void> {
  const log = new Logger('Bootstrap');

  // Disable Nest's built-in parser and install explicit, bounded ones. These run
  // as global middleware — i.e. BEFORE any guard — so AttestedGuard can read
  // req.body.clientPublicKey. (The AdMob SSV route reads the raw query string,
  // not the body.) When store webhooks are added, register a `raw` parser scoped
  // to those routes BEFORE these, to verify JWS signatures byte-exactly.
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bodyParser: false });
  app.use(json({ limit: '64kb' }));
  app.use(urlencoded({ extended: false, limit: '64kb' }));

  // All routes under /api/v1 (matches the Flutter client's base path).
  app.setGlobalPrefix('api/v1');

  // ── Global validation: strip unknown fields, reject extras, coerce types. ──
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      // Don't echo the offending value back (could contain a token/secret).
      validationError: { target: false, value: false },
    }),
  );

  // ── Global exception filter: clean JSON out, NO stack traces to the client. ──
  app.useGlobalFilters(new AllExceptionsFilter());

  // Behind a TLS-terminating proxy: trust EXACTLY the number of proxy hops so
  // the throttler sees the real client IP via X-Forwarded-For. Tune per topology
  // (Nginx=1; WAF→LB→proxy=3; a CIDR string also works). NEVER set this to a
  // value larger than your real hop count — a client could then spoof X-F-F and
  // evade per-IP limits. Default 1.
  const tp = process.env.TRUST_PROXY_HOPS;
  app.getHttpAdapter().getInstance().set('trust proxy', tp && /^\d+$/.test(tp) ? Number(tp) : tp || 1);

  // Run OnModuleDestroy (workers stop their timers, pool drains) on SIGTERM.
  app.enableShutdownHooks();

  const port = Number(process.env.PORT ?? 3000);
  await app.listen(port);
  log.log(`middleware listening on :${port} (prefix /api/v1)`);
}

bootstrap().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('fatal bootstrap error', err);
  process.exit(1);
});
