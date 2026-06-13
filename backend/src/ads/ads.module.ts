import { Module } from '@nestjs/common';
import { AdsController } from './ads.controller';
import { AdsService } from './ads.service';
import { AdMobSsvVerifier } from './admob-ssv.verifier';
import { ConnectionModule } from '../connection/connection.module';

/**
 * Wires the time-based reward feature. PANEL_CLIENT is resolved from the global
 * CoreModule. The outbox drainer now lives in WorkersModule. Imports
 * ConnectionModule for the SessionConfigService that builds the free-tier
 * encrypted payload delivered at verify-ad-reward.
 */
@Module({
  imports: [ConnectionModule],
  controllers: [AdsController],
  providers: [AdsService, AdMobSsvVerifier],
  exports: [AdsService],
})
export class AdsModule {}
