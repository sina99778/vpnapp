import { Injectable } from '@nestjs/common';
import { pool } from '../db/pool';
import { PayloadCipher, EncryptedPayloadDto } from './payload-cipher';
import { buildSingboxConfig } from './config-builder';

const VLESS_FLOW = process.env.VLESS_FLOW ?? 'xtls-rprx-vision';

export class SessionConfigError extends Error {}

/**
 * Builds + encrypts the config for an EXISTING live session, addressed only by
 * its id. Used by verify-ad-reward to deliver the free-tier payload AFTER the
 * ads are verified (the Provisioning Model defers the payload to that point).
 *
 * The config is encrypted to the session's device's attested_client_public_key —
 * the same key the AttestedGuard bound at /connect — so only that genuine,
 * attested device can decrypt it.
 */
@Injectable()
export class SessionConfigService {
  constructor(private readonly cipher: PayloadCipher) {}

  async encryptedPayloadForSession(sessionId: string): Promise<EncryptedPayloadDto> {
    const { rows } = await pool.query(
      `select s.status, s.credential_ref, s.protocol, s.client_public_key,
              ne.address, ne.port, ne.security
         from vpn_sessions s
         join node_endpoints ne
           on ne.node_id = s.node_id and ne.inbound_tag = s.inbound_tag and ne.is_active
        where s.id = $1
        limit 1`,
      [sessionId],
    );
    if (rows.length === 0) throw new SessionConfigError('session_endpoint_unavailable');
    const r = rows[0];

    // Only build a payload for a LIVE session — never hand out config for one
    // that was revoked/closed between the original verify and a retry.
    if (!['provisioning', 'active', 'limited'].includes(r.status)) {
      throw new SessionConfigError('session_not_live');
    }

    // Encrypt to the key the SESSION was created with (captured at /connect), not
    // the device's current attested key, which may have rotated since.
    const clientPub = r.client_public_key as Buffer | null;
    if (!clientPub || clientPub.length !== 32) throw new SessionConfigError('no_session_key');

    const configJson = buildSingboxConfig({
      protocol: r.protocol ?? 'vless',
      address: r.address,
      port: r.port,
      uuid: r.credential_ref,
      flow: VLESS_FLOW,
      security: r.security ?? {},
    });
    return this.cipher.encryptFor(configJson, sessionId, clientPub);
  }
}
