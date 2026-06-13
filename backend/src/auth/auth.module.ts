import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { TokenService } from './token.service';

/**
 * Identity distribution (anonymous-first freemium funnel). Mints the access
 * JWTs (sub=userId, did=deviceId) that JwtAuthGuard verifies across the app, and
 * the rotating refresh tokens with family-based reuse detection.
 *
 * ThrottlerModule is registered in AppModule; AuthController applies
 * ThrottlerGuard at its own level so only auth routes are rate-limited.
 */
@Module({
  controllers: [AuthController],
  providers: [AuthService, TokenService],
  exports: [AuthService, TokenService],
})
export class AuthModule {}
