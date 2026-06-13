import { Module } from '@nestjs/common';
import { ConnectionController } from './connection.controller';
import { ConnectionService } from './connection.service';
import { PayloadCipher } from './payload-cipher';
import { SessionConfigService } from './session-config.service';
import { AttestModule } from '../attest/attest.module';

/**
 * The /connect endpoint. Depends on AttestModule for the AttestedGuard;
 * PANEL_CLIENT is resolved from the global CoreModule. Exports the payload
 * cipher + session config builder so the ads module can deliver the free-tier
 * payload at verify-ad-reward via the SAME crypto.
 */
@Module({
  imports: [AttestModule],
  controllers: [ConnectionController],
  providers: [ConnectionService, PayloadCipher, SessionConfigService],
  exports: [PayloadCipher, SessionConfigService],
})
export class ConnectionModule {}
