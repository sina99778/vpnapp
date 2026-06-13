import { Injectable } from '@nestjs/common';
import {
  generateKeyPairSync,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  createCipheriv,
  randomBytes,
} from 'crypto';

/**
 * Server half of the per-session payload encryption. MUST stay byte-compatible
 * with the Flutter client's PayloadCrypto (lib/core/crypto/payload_crypto.dart):
 *
 *   ikm  = X25519(serverEphPriv, clientPub)            // ECDH
 *   key  = HKDF-SHA256(ikm, salt = utf8(sessionId), info = "vpncfg|v1", 32)
 *   ct   = AES-256-GCM(key, iv=12B random) over the config JSON  → ciphertext+tag
 *
 * The client public key is the ATTESTED key (the AttestedGuard proved the
 * request's clientPublicKey equals devices.attested_client_public_key), so the
 * payload can only be decrypted by the genuine, attested device — a substituted
 * key was already rejected at attestation time.
 */
export interface EncryptedPayloadDto {
  alg: 'x25519-hkdf-sha256-aes256gcm';
  keyRef: string; // base64 of the server ephemeral X25519 public key (32 raw bytes)
  iv: string; // base64, 12 bytes
  ciphertext: string; // base64
  tag: string; // base64, 16 bytes
}

// DER SPKI prefix for an X25519 public key; prepend to 32 raw bytes to import.
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const HKDF_INFO = Buffer.from('vpncfg|v1');

@Injectable()
export class PayloadCipher {
  /**
   * Encrypt [plaintext] for the holder of [clientPubRaw] (32-byte X25519 key),
   * binding the HKDF salt to [sessionId]. Forward-secret: the server keypair is
   * ephemeral and discarded when this returns.
   */
  encryptFor(plaintext: string, sessionId: string, clientPubRaw: Buffer): EncryptedPayloadDto {
    if (clientPubRaw.length !== 32) throw new Error('client public key must be 32 bytes');

    const serverEph = generateKeyPairSync('x25519');
    const clientKey = createPublicKey({
      key: Buffer.concat([X25519_SPKI_PREFIX, clientPubRaw]),
      format: 'der',
      type: 'spki',
    });

    const ikm = diffieHellman({ privateKey: serverEph.privateKey, publicKey: clientKey });
    const key = Buffer.from(hkdfSync('sha256', ikm, Buffer.from(sessionId, 'utf8'), HKDF_INFO, 32));

    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Export the server ephemeral PUBLIC key as 32 raw bytes (JWK 'x' is base64url).
    const jwk = serverEph.publicKey.export({ format: 'jwk' }) as { x?: string };
    if (!jwk.x) throw new Error('failed to export server ephemeral public key');
    const serverPubRaw = Buffer.from(jwk.x, 'base64url');

    return {
      alg: 'x25519-hkdf-sha256-aes256gcm',
      keyRef: serverPubRaw.toString('base64'),
      iv: iv.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: tag.toString('base64'),
    };
  }
}
