import { Module } from '@nestjs/common';
import { AttestController } from './attest.controller';
import { AttestService } from './attest.service';
import { PlayIntegrityVerifier } from './play-integrity.verifier';
import { AppAttestVerifier } from './app-attest.verifier';
import { AttestConfig, loadAttestConfig } from './attest.config';
import { AttestedGuard } from './attested.guard';

export const ATTEST_CONFIG = Symbol('ATTEST_CONFIG');

/**
 * Device attestation. Verifies Play Integrity / App Attest server-side and
 * gates /connect via AttestedGuard. Config is loaded once at boot so a missing
 * credential fails fast rather than on the first request.
 */
@Module({
  controllers: [AttestController],
  providers: [
    { provide: ATTEST_CONFIG, useFactory: (): AttestConfig => loadAttestConfig() },
    {
      provide: PlayIntegrityVerifier,
      useFactory: (cfg: AttestConfig) => new PlayIntegrityVerifier(cfg),
      inject: [ATTEST_CONFIG],
    },
    {
      provide: AppAttestVerifier,
      useFactory: (cfg: AttestConfig) => new AppAttestVerifier(cfg),
      inject: [ATTEST_CONFIG],
    },
    AttestService,
    AttestedGuard,
  ],
  exports: [AttestedGuard, AttestService],
})
export class AttestModule {}
