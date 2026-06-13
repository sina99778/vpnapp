import { Injectable, Logger } from '@nestjs/common';
import { createHash, createPublicKey, verify as cryptoVerify, webcrypto, timingSafeEqual, KeyObject } from 'crypto';
import { decode as cborDecode } from 'cbor2';
import * as x509 from '@peculiar/x509';
import { AttestConfig, AttestationError } from './attest.config';

// Node's webcrypto implements the WebCrypto API @peculiar/x509 expects; the
// `Crypto` global type isn't in the Node lib, so cast through any.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
x509.cryptoProvider.set(webcrypto as any);

const OID_APPLE_NONCE = '1.2.840.113635.100.8.2';
const AAGUID_PROD = Buffer.concat([Buffer.from('appattest'), Buffer.alloc(7)]);
const AAGUID_DEV = Buffer.from('appattestdevelop');
const FLAG_AT = 0x40; // "attested credential data included"

export interface AttestationResult {
  publicKeyDer: Buffer; // SPKI DER of the attested P-256 key (stored verbatim)
  signCount: number; // 0 after attestation
}
export interface AssertionResult {
  newSignCount: number;
}

/**
 * Apple App Attest server verification, hand-rolled for explicit control over
 * THE binding: clientDataHash = SHA-256(clientPubKey ‖ challenge). The client
 * passes this exact value to attestKey/generateAssertion, so reconstructing it
 * here and feeding it into the nonce is what binds the ephemeral ECDH key.
 *
 * No external I/O — entirely CPU-bound (CBOR + cert math + crypto), so the
 * caller may run it INSIDE a DB transaction (needed to make the counter check
 * race-free). Cert-chain trust is pinned to Apple's root; every step fails closed.
 */
@Injectable()
export class AppAttestVerifier {
  private readonly log = new Logger(AppAttestVerifier.name);
  private rootCert: x509.X509Certificate;

  constructor(private readonly cfg: AttestConfig) {
    this.rootCert = new x509.X509Certificate(cfg.appleRootCaPem);
  }

  private clientDataHash(clientPubKey: Buffer, challenge: Buffer): Buffer {
    return sha256(Buffer.concat([clientPubKey, challenge]));
  }
  private appIdHash(): Buffer {
    return sha256(Buffer.from(`${this.cfg.appleTeamId}.${this.cfg.appleBundleId}`));
  }

  // ── First-time registration ────────────────────────────────────────────
  async verifyAttestation(
    attestationB64: string,
    keyIdB64: string,
    clientPubKey: Buffer,
    challenge: Buffer,
  ): Promise<AttestationResult> {
    if (clientPubKey.length !== 32) throw new AttestationError('bad_pubkey_len');

    let obj: { fmt?: string; attStmt?: { x5c?: Uint8Array[] }; authData?: Uint8Array };
    try {
      obj = cborDecode(Buffer.from(attestationB64, 'base64')) as typeof obj;
    } catch (e) {
      throw new AttestationError('cbor_decode_failed', (e as Error).message);
    }
    if (obj.fmt !== 'apple-appattest') throw new AttestationError('bad_fmt');
    const x5c = obj.attStmt?.x5c;
    const authData = obj.authData ? Buffer.from(obj.authData) : undefined;
    if (!x5c || x5c.length < 2 || !authData) throw new AttestationError('bad_attestation_shape');

    // 1) Cert chain: leaf ← intermediate ← pinned Apple root, dates valid, and
    //    the CA constraints are what they must be (leaf NOT a CA, intermediate IS).
    const leaf = new x509.X509Certificate(Buffer.from(x5c[0]));
    const intermediate = new x509.X509Certificate(Buffer.from(x5c[1]));
    const now = new Date();
    const chainOk =
      (await leaf.verify({ publicKey: intermediate.publicKey, date: now })) &&
      (await intermediate.verify({ publicKey: this.rootCert.publicKey, date: now }));
    if (!chainOk) throw new AttestationError('cert_chain_invalid');
    this.assertCaConstraints(leaf, intermediate);

    // 2) nonce = SHA256(authData ‖ clientDataHash); compare to the leaf's OID ext
    //    (strict DER parse, no loose byte scanning).
    const clientDataHash = this.clientDataHash(clientPubKey, challenge);
    const expectedNonce = sha256(Buffer.concat([authData, clientDataHash]));
    const certNonce = extractAppleNonce(leaf);
    if (!certNonce || !ctEqual(expectedNonce, certNonce)) throw new AttestationError('nonce_mismatch');

    // 3) keyId == SHA256(leaf public key, X9.62 uncompressed). Extract the point
    //    robustly via the parsed key's JWK coordinates (no manual DER offsets).
    const leafPubDer = Buffer.from(leaf.publicKey.rawData);
    if (leafPubDer.length === 0) throw new AttestationError('bad_public_key');
    const computedKeyId = sha256(uncompressedPoint(leafPubDer));
    if (!ctEqual(computedKeyId, Buffer.from(keyIdB64, 'base64'))) throw new AttestationError('keyid_mismatch');

    // 4) authData fields. AT flag MUST be set (attestation carries credential data).
    const ad = parseAuthData(authData);
    if (!ad.hasAttestedCredentialData) throw new AttestationError('at_flag_unset');
    if (!ctEqual(ad.rpIdHash, this.appIdHash())) throw new AttestationError('rpid_mismatch');
    if (ad.signCount !== 0) throw new AttestationError('counter_not_zero');
    const expectedAaguid = this.cfg.appleAttestEnv === 'production' ? AAGUID_PROD : AAGUID_DEV;
    if (!ad.aaguid || !ctEqual(ad.aaguid, expectedAaguid)) throw new AttestationError('aaguid_mismatch');

    return { publicKeyDer: leafPubDer, signCount: 0 };
  }

  // ── Per-connect assertion ──────────────────────────────────────────────
  async verifyAssertion(
    assertionB64: string,
    storedPublicKeyDer: Buffer,
    storedSignCount: number,
    clientPubKey: Buffer,
    challenge: Buffer,
  ): Promise<AssertionResult> {
    if (clientPubKey.length !== 32) throw new AttestationError('bad_pubkey_len');

    let obj: { signature?: Uint8Array; authenticatorData?: Uint8Array };
    try {
      obj = cborDecode(Buffer.from(assertionB64, 'base64')) as typeof obj;
    } catch (e) {
      throw new AttestationError('cbor_decode_failed', (e as Error).message);
    }
    const signature = obj.signature ? Buffer.from(obj.signature) : undefined;
    const authData = obj.authenticatorData ? Buffer.from(obj.authenticatorData) : undefined;
    if (!signature || !authData) throw new AttestationError('bad_assertion_shape');

    const clientDataHash = this.clientDataHash(clientPubKey, challenge);

    // nonce = SHA256(authenticatorData ‖ clientDataHash). crypto.verify('sha256',
    // preimage) computes SHA256(preimage)=nonce then ECDSA-verifies the DER sig.
    const pubKey: KeyObject = createPublicKey({ key: storedPublicKeyDer, format: 'der', type: 'spki' });
    const preimage = Buffer.concat([authData, clientDataHash]);
    const sigOk = cryptoVerify('sha256', preimage, { key: pubKey, dsaEncoding: 'der' }, signature);
    if (!sigOk) throw new AttestationError('assertion_signature_invalid');

    const ad = parseAuthData(authData);
    // Assertions carry NO attested credential data.
    if (ad.hasAttestedCredentialData) throw new AttestationError('at_flag_set');
    if (!ctEqual(ad.rpIdHash, this.appIdHash())) throw new AttestationError('rpid_mismatch');
    if (ad.signCount <= storedSignCount) throw new AttestationError('counter_replay');

    return { newSignCount: ad.signCount };
  }

  private assertCaConstraints(leaf: x509.X509Certificate, intermediate: x509.X509Certificate): void {
    const leafBc = leaf.getExtension(x509.BasicConstraintsExtension);
    if (leafBc?.ca === true) throw new AttestationError('leaf_is_ca');
    const intBc = intermediate.getExtension(x509.BasicConstraintsExtension);
    if (intBc?.ca !== true) throw new AttestationError('intermediate_not_ca');
  }
}

// ── helpers ────────────────────────────────────────────────────────────────

function sha256(b: Buffer): Buffer {
  return createHash('sha256').update(b).digest();
}
function ctEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

interface AuthData {
  rpIdHash: Buffer;
  flags: number;
  hasAttestedCredentialData: boolean;
  signCount: number;
  aaguid?: Buffer;
}
/** authData = rpIdHash(32) | flags(1) | signCount(4) | [aaguid(16) | credIdLen(2) | credId | credPubKey]. */
function parseAuthData(b: Buffer): AuthData {
  if (b.length < 37) throw new AttestationError('authdata_too_short');
  const flags = b[32];
  const hasAttestedCredentialData = (flags & FLAG_AT) !== 0;
  let aaguid: Buffer | undefined;
  if (hasAttestedCredentialData) {
    if (b.length < 55) throw new AttestationError('authdata_missing_cred_data');
    aaguid = b.subarray(37, 53);
  }
  return {
    rpIdHash: b.subarray(0, 32),
    flags,
    hasAttestedCredentialData,
    signCount: b.readUInt32BE(33),
    aaguid,
  };
}

/**
 * Strict DER parse of the Apple nonce extension value:
 *   SEQUENCE(0x30) { [1](0xA1) { OCTET STRING(0x04) length 0x20 <32 bytes> } }
 * Anything that deviates is rejected — no loose scanning for `04 20`.
 */
function extractAppleNonce(cert: x509.X509Certificate): Buffer | undefined {
  const ext = cert.getExtension(OID_APPLE_NONCE);
  if (!ext) return undefined;
  const raw = Buffer.from(ext.value);
  let i = 0;
  const tag = (t: number) => raw[i++] === t;
  if (!tag(0x30)) return undefined; // SEQUENCE
  i++; // seq length (short form for this tiny structure)
  if (!tag(0xa1)) return undefined; // context [1]
  i++; // ctx length
  if (!tag(0x04)) return undefined; // OCTET STRING
  if (raw[i++] !== 0x20) return undefined; // length must be exactly 32
  if (i + 32 !== raw.length) return undefined; // and nothing trailing
  return raw.subarray(i, i + 32);
}

/**
 * P-256 SPKI(DER) → 65-byte uncompressed point (0x04 ‖ X ‖ Y). Parse the key
 * with Node and read its JWK coordinates rather than slicing DER by offset.
 */
function uncompressedPoint(spkiDer: Buffer): Buffer {
  const jwk = createPublicKey({ key: spkiDer, format: 'der', type: 'spki' }).export({ format: 'jwk' }) as {
    kty?: string;
    crv?: string;
    x?: string;
    y?: string;
  };
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
    throw new AttestationError('bad_public_key');
  }
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  if (x.length !== 32 || y.length !== 32) throw new AttestationError('bad_public_key');
  return Buffer.concat([Buffer.from([0x04]), x, y]);
}
