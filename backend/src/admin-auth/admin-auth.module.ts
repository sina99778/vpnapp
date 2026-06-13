import { Module } from '@nestjs/common';
import { AdminAuthController } from './admin-auth.controller';
import { AdminAuthService } from './admin-auth.service';
import { AuthModule } from '../auth/auth.module';

/**
 * Device-less admin authentication for the web dashboard. Reuses TokenService
 * (exported by AuthModule) to mint the same JWT/refresh shapes the rest of the
 * app verifies — without creating a device or attestation record.
 */
@Module({
  imports: [AuthModule],
  controllers: [AdminAuthController],
  providers: [AdminAuthService],
})
export class AdminAuthModule {}
