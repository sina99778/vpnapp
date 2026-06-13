import { Injectable, Logger } from '@nestjs/common';
import { createHash, timingSafeEqual } from 'crypto';
import { google, playintegrity_v1 } from 'googleapis';
import { AttestConfig, AttestationError } from './attest.config';

/**
 * Server-side Play Integrity STANDARD verification.
 *
 * Standard tokens are encrypted and CANNOT be decoded locally — we MUST call
 * Google's decodeIntegrityToken with a service-account credential. The decoded
 * verdict carries requestDetails.requestHash, which is exactly the base64url of
 * the bindingHash the client set. We recompute bindingHash from the submitted
 * public key + our stored challenge and require a byte-exact match — that is
 * what stops a swapped ECDH key.
 *
 * All checks fail closed: any missing field, wrong verdict, stale timestamp, or
 * hash mismatch throws AttestationError.
 */
@Injectable()
export class PlayIntegrityVerifier {
  private readonly log = new Logger(PlayIntegrityVerifier.name);
  private clientPromise?: Promise<playintegrity_v1.Playintegrity>;

  constructor(private readonly cfg: AttestConfig) {}

  private api(): Promise<playintegrity_v1.Playintegrity> {
    // Memoize the PROMISE so concurrent callers share one initialization.
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        const auth = new google.auth.GoogleAuth({
          keyFile: this.cfg.googleCredentialsFile,
          scopes: ['https://www.googleapis.com/auth/playintegrity'],
        });
        return google.playintegrity({ version: 'v1', auth });
      })().catch((e) => {
        this.clientPromise = undefined; // allow retry on next call
        throw e;
      });
    }
    return this.clientPromise;
  }

  /**
   * @param integrityToken the encrypted token from the client
   * @param clientPubKey   the X25519 public key the client also sent to us
   * @param challenge      the one-time challenge we issued
   * Returns the decoded verdict (for audit) on success; throws otherwise.
   */
  async verify(
    integrityToken: string,
    clientPubKey: Buffer,
    challenge: Buffer,
  ): Promise<playintegrity_v1.Schema$TokenPayloadExternal> {
    let decoded: playintegrity_v1.Schema$TokenPayloadExternal | undefined;
    try {
      const api = await this.api();
      const res = await api.v1.decodeIntegrityToken({
        packageName: this.cfg.androidPackageName,
        requestBody: { integrityToken },
      });
      // NB: googleapis exposes this as `playintegrity.v1.decodeIntegrityToken` in
      // recent typings; older majors used the top-level `decodeIntegrityToken`.
      // Pin the googleapis version and adjust this one call if typings differ.
      decoded = res.data.tokenPayloadExternal ?? undefined;
    } catch (e) {
      // Distinguish a BAD TOKEN (Google replies 4xx) from a TRANSIENT failure
      // (network / auth / Google 5xx). A forged token must reject (403), not be
      // masked as a retryable 503.
      const status = (e as { code?: number; response?: { status?: number } }).response?.status
        ?? (e as { code?: number }).code;
      if (typeof status === 'number' && status >= 400 && status < 500) {
        throw new AttestationError('invalid_token', (e as Error).message);
      }
      throw new AttestationError('transient', (e as Error).message);
    }
    if (!decoded) throw new AttestationError('empty_payload');

    const rd = decoded.requestDetails;
    const ai = decoded.appIntegrity;
    const di = decoded.deviceIntegrity;

    // 1) requestHash binding — THE crux. Byte-exact, base64url no-pad.
    const expected = base64UrlNoPad(sha256(Buffer.concat([clientPubKey, challenge])));
    if (!rd?.requestHash || !constTimeEqualStr(rd.requestHash, expected)) {
      throw new AttestationError('request_hash_mismatch');
    }

    // 2) Package name must be ours.
    if (rd.requestPackageName !== this.cfg.androidPackageName) {
      throw new AttestationError('package_mismatch');
    }

    // 3) App recognised by Play (not tampered/sideloaded).
    if (ai?.appRecognitionVerdict !== 'PLAY_RECOGNIZED') {
      throw new AttestationError('app_not_recognized');
    }

    // 4) Signing certificate digest (if configured) — defends against a repackaged
    //    app signed with a different key that Play still "recognises" in another track.
    if (this.cfg.androidCertDigests.length > 0) {
      const got = ai.certificateSha256Digest ?? [];
      const ok = got.some((d) => this.cfg.androidCertDigests.includes(d));
      if (!ok) throw new AttestationError('cert_digest_mismatch');
    }

    // 5) Device integrity. Empty array == compromised/emulated (or a replayed
    //    token, which Google clears). Require MEETS_DEVICE_INTEGRITY.
    const verdicts = di?.deviceRecognitionVerdict ?? [];
    if (!verdicts.includes('MEETS_DEVICE_INTEGRITY')) {
      throw new AttestationError('device_integrity_failed');
    }

    // 6) Token freshness — Google does NOT enforce this; we must.
    const ts = Number(rd.timestampMillis ?? 0);
    if (!Number.isFinite(ts) || Date.now() - ts > this.cfg.androidTokenMaxAgeMs) {
      throw new AttestationError('token_stale');
    }

    return decoded;
  }
}

function sha256(b: Buffer): Buffer {
  return createHash('sha256').update(b).digest();
}
function base64UrlNoPad(b: Buffer): string {
  return b.toString('base64url'); // Node base64url is URL-safe AND unpadded
}
function constTimeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
