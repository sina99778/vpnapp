import { Injectable, Logger } from '@nestjs/common';
import { randomBytes } from 'crypto';
import { pool, withTransaction } from '../db/pool';
import { AttestConfig, AttestationError, loadAttestConfig } from './attest.config';
import { PlayIntegrityVerifier } from './play-integrity.verifier';
import { AppAttestVerifier } from './app-attest.verifier';

export type Platform = 'android' | 'ios';

export interface ChallengeResult {
  challengeId: string;
  challenge: string; // base64
}

export interface AndroidAttestation {
  platform: 'android';
  integrityToken: string;
}
export interface IosAttestation {
  platform: 'ios';
  mode: 'attest' | 'assert';
  keyId: string;
  attestation?: string; // base64 (mode=attest)
  assertion?: string; // base64 (mode=assert)
}
export type AttestationPayload = AndroidAttestation | IosAttestation;

/**
 * Orchestrates the device attestation loop. Fail-closed throughout: any verifier
 * error, missing/expired/used challenge, or state inconsistency rejects.
 *
 * Lock discipline (per pool.ts INVARIANT): the slow external calls (Google
 * decode / cert work) run with NO DB transaction open. We consume the challenge
 * in a short tx, do the off-box verification with locks released, then flip
 * is_attested in a final short tx.
 */
@Injectable()
export class AttestService {
  private readonly log = new Logger(AttestService.name);
  private readonly cfg: AttestConfig;

  constructor(
    private readonly playIntegrity: PlayIntegrityVerifier,
    private readonly appAttest: AppAttestVerifier,
  ) {
    this.cfg = loadAttestConfig();
  }

  /** POST /device/attest/challenge — issue a single-use 32-byte challenge. */
  async createChallenge(deviceId: string): Promise<ChallengeResult> {
    const challenge = randomBytes(32);
    const { rows } = await pool.query(
      `insert into attestation_challenges (device_id, purpose, challenge, expires_at)
       values ($1, 'connect', $2, now() + ($3::int * interval '1 millisecond'))
       returning id`,
      [deviceId, challenge, this.cfg.challengeTtlMs],
    );
    return { challengeId: rows[0].id as string, challenge: challenge.toString('base64') };
  }

  /**
   * POST /device/attest/verify — the full loop.
   * Returns the verified device id on success; throws AttestationError otherwise.
   */
  async verify(input: {
    deviceId: string;
    challengeId: string;
    clientPubKey: Buffer;
    attestation: AttestationPayload;
  }): Promise<void> {
    if (input.clientPubKey.length !== 32) throw new AttestationError('bad_pubkey_len');

    // ── Phase A (short tx): atomically consume the challenge. ──
    const challenge = await withTransaction(async (c) => {
      const { rows } = await c.query(
        `select id, device_id, challenge, expires_at, consumed_at
           from attestation_challenges
          where id = $1 and device_id = $2 and purpose = 'connect'
          for update`,
        [input.challengeId, input.deviceId],
      );
      if (rows.length === 0) throw new AttestationError('challenge_not_found');
      const ch = rows[0];
      if (ch.consumed_at) throw new AttestationError('challenge_used');
      if (new Date(ch.expires_at) <= new Date()) throw new AttestationError('challenge_expired');
      await c.query(`update attestation_challenges set consumed_at = now() where id = $1`, [ch.id]);
      return ch.challenge as Buffer; // bytea → Buffer
    });

    const markAttested = (c: import('pg').PoolClient) =>
      c.query(
        `update devices
            set is_attested = true,
                attested_until = now() + ($2::int * interval '1 millisecond'),
                last_attested_at = now(),
                -- Persist the EXACT key this attestation bound. /connect must
                -- check the clientPublicKey it receives equals this value.
                attested_client_public_key = $3
          where id = $1`,
        [input.deviceId, this.cfg.attestationTtlMs, input.clientPubKey],
      );

    if (input.attestation.platform === 'android') {
      // Play Integrity decode is EXTERNAL I/O → must run with NO transaction open.
      const snapshot = await this.playIntegrity.verify(
        input.attestation.integrityToken,
        input.clientPubKey,
        challenge,
      );
      // Then a short tx to persist the verdict + attestation flag.
      await withTransaction(async (c) => {
        await c.query(`update devices set last_integrity_verdict = $2 where id = $1`, [
          input.deviceId,
          JSON.stringify(snapshot),
        ]);
        await markAttested(c);
      });
      return;
    }

    // iOS App Attest is PURE CPU (no external I/O), so the device read + verify +
    // counter write can all run inside ONE FOR UPDATE transaction. This closes
    // the counter/stale-key race without violating lock discipline.
    const ios = input.attestation;
    await withTransaction(async (c) => {
      const { rows } = await c.query(
        `select app_attest_key_id, app_attest_public_key, app_attest_counter
           from devices where id = $1 for update`,
        [input.deviceId],
      );
      if (rows.length === 0) throw new AttestationError('device_not_found');
      const dev = rows[0];

      if (ios.mode === 'attest') {
        if (!ios.attestation) throw new AttestationError('missing_attestation');
        // Reject a public key already bound to ANOTHER device (Apple replay rule).
        const dup = await c.query(
          `select 1 from devices where app_attest_key_id = $1 and id <> $2`,
          [ios.keyId, input.deviceId],
        );
        if (dup.rows.length > 0) throw new AttestationError('keyid_bound_elsewhere');

        const res = await this.appAttest.verifyAttestation(
          ios.attestation,
          ios.keyId,
          input.clientPubKey,
          challenge,
        );
        await c.query(
          `update devices set app_attest_key_id = $2,
                              app_attest_public_key = $3,
                              app_attest_counter = $4
            where id = $1`,
          [input.deviceId, ios.keyId, res.publicKeyDer, res.signCount],
        );
      } else {
        if (!ios.assertion) throw new AttestationError('missing_assertion');
        if (!dev.app_attest_public_key || dev.app_attest_key_id !== ios.keyId) {
          throw new AttestationError('key_not_registered');
        }
        const res = await this.appAttest.verifyAssertion(
          ios.assertion,
          dev.app_attest_public_key as Buffer, // stored SPKI DER
          Number(dev.app_attest_counter),
          input.clientPubKey,
          challenge,
        );
        await c.query(`update devices set app_attest_counter = $2 where id = $1`, [
          input.deviceId,
          res.newSignCount,
        ]);
      }

      await markAttested(c);
    });
  }

  /** Record an attestation attempt for audit (called by the controller). */
  async audit(
    deviceId: string | null,
    platform: Platform | null,
    outcome: 'passed' | 'rejected',
    reason: string | null,
    ip: string | null,
  ): Promise<void> {
    await pool
      .query(
        `insert into attestation_attempts (device_id, platform, outcome, reason, ip)
         values ($1, $2, $3, $4, $5)`,
        [deviceId, platform, outcome, reason, ip],
      )
      .catch((e) => this.log.warn(`audit insert failed: ${(e as Error).message}`));
  }
}
