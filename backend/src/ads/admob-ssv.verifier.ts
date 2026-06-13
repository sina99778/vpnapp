import { Injectable, Logger } from '@nestjs/common';
import { createVerify } from 'crypto';
import { base64UrlToBase64, fetchWithTimeout } from '../common/http';

/**
 * Verifies Google AdMob rewarded-ad Server-Side Verification (SSV) callbacks.
 *
 * AdMob's servers (NOT the client) call our SSV URL after a user finishes a
 * rewarded ad. The callback is signed with AdMob's private key; we verify it
 * against the public keys at the verifier-key endpoint. Because the signature
 * is produced by Google and the client never possesses the key, a patched
 * client (Lucky Patcher et al.) cannot forge a "reward granted" event.
 *
 * Verification rule (per AdMob docs):
 *   - `signature` and `key_id` are ALWAYS the last two query params, in order.
 *   - The signed content is the raw query string up to (not including)
 *     "&signature=".
 *   - `signature` is web-safe-base64; the key is ECDSA P-256; hash is SHA-256.
 */
const KEY_SERVER_URL = 'https://www.gstatic.com/admob/reward/verifier-keys.json';
const KEY_TTL_MS = 6 * 60 * 60 * 1000;
const MAX_CALLBACK_AGE_MS = 10 * 60 * 1000; // reject callbacks older than 10 min
const MAX_CLOCK_SKEW_MS = 60 * 1000; // tolerate 1 min of future skew

interface VerifierKey {
  keyId: number;
  pem: string;
  base64: string;
}

export interface AdMobReward {
  customData: string; // our grant nonce (we set it via the ad SDK)
  transactionId: string; // AdMob txn id — replay/idempotency key
  adNetwork?: string;
  adUnit?: string;
  rewardItem?: string;
  rewardAmount?: number;
  userId?: string;
  timestampMs?: number;
  keyId: string;
  raw: Record<string, string>;
}

export class SsvVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SsvVerificationError';
  }
}

@Injectable()
export class AdMobSsvVerifier {
  private readonly log = new Logger(AdMobSsvVerifier.name);
  private keys = new Map<string, string>(); // keyId -> PEM
  private fetchedAt = 0;
  private inflight: Promise<void> | null = null;

  /**
   * Verify a raw SSV query string (everything after `?`). Returns the parsed,
   * trusted reward on success; throws SsvVerificationError otherwise.
   *
   * Does network I/O (key fetch on cache miss). Call this BEFORE opening any DB
   * transaction so no row locks are held while we talk to the key server.
   */
  async verify(rawQuery: string): Promise<AdMobReward> {
    const sigMarker = '&signature=';
    const sigIdx = rawQuery.lastIndexOf(sigMarker);
    if (sigIdx < 0) throw new SsvVerificationError('missing signature/key_id');

    const signedContent = rawQuery.slice(0, sigIdx);
    const tail = new URLSearchParams(rawQuery.slice(sigIdx + 1)); // "signature=..&key_id=.."
    const signatureB64Url = tail.get('signature');
    const keyId = tail.get('key_id');
    if (!signatureB64Url || !keyId) throw new SsvVerificationError('missing signature/key_id');

    const pem = await this.getKey(keyId);
    if (!pem) throw new SsvVerificationError(`unknown key_id ${keyId}`);

    const signature = Buffer.from(base64UrlToBase64(signatureB64Url), 'base64');
    // ECDSA-P256 + SHA-256. createVerify expects DER-encoded ECDSA, which is
    // what AdMob sends. Verify over the EXACT raw bytes that were signed.
    const ok = createVerify('SHA256').update(signedContent, 'utf8').verify(pem, signature);
    if (!ok) throw new SsvVerificationError('signature verification failed');

    // Signature is valid — now parse the trusted content.
    const p = new URLSearchParams(signedContent);
    const customData = p.get('custom_data');
    const transactionId = p.get('transaction_id');
    if (!customData) throw new SsvVerificationError('missing custom_data (grant nonce)');
    if (!transactionId) throw new SsvVerificationError('missing transaction_id');

    // Freshness: reject a validly-signed but stale callback. transaction_id +
    // the grant window are the primary replay defenses; this caps the window an
    // attacker could exploit by sitting on an old, signed callback. AdMob's
    // `timestamp` is epoch MILLISECONDS.
    const timestampMs = p.get('timestamp') ? Number(p.get('timestamp')) : undefined;
    if (timestampMs !== undefined && Number.isFinite(timestampMs)) {
      const age = Date.now() - timestampMs;
      if (age > MAX_CALLBACK_AGE_MS || age < -MAX_CLOCK_SKEW_MS) {
        throw new SsvVerificationError(`callback timestamp out of window (age ${Math.round(age / 1000)}s)`);
      }
    }

    const raw: Record<string, string> = {};
    p.forEach((v, k) => (raw[k] = v));

    return {
      customData,
      transactionId,
      adNetwork: p.get('ad_network') ?? undefined,
      adUnit: p.get('ad_unit') ?? undefined,
      rewardItem: p.get('reward_item') ?? undefined,
      rewardAmount: p.get('reward_amount') ? Number(p.get('reward_amount')) : undefined,
      userId: p.get('user_id') ?? undefined,
      timestampMs,
      keyId,
      raw,
    };
  }

  private async getKey(keyId: string): Promise<string | undefined> {
    const stale = Date.now() - this.fetchedAt > KEY_TTL_MS;
    if (this.keys.has(keyId) && !stale) return this.keys.get(keyId);
    await this.refreshKeys();
    if (this.keys.has(keyId)) return this.keys.get(keyId);
    // Unknown key id with fresh cache: one forced refresh already happened.
    return undefined;
  }

  /** Single-flight key refresh. */
  private async refreshKeys(): Promise<void> {
    if (this.inflight) return this.inflight;
    this.inflight = (async () => {
      const res = await fetchWithTimeout(KEY_SERVER_URL, {}, 5_000);
      if (!res.ok) throw new SsvVerificationError(`verifier keys fetch failed: ${res.status}`);
      const body = (await res.json()) as { keys: VerifierKey[] };
      const next = new Map<string, string>();
      for (const k of body.keys ?? []) next.set(String(k.keyId), k.pem);
      if (next.size === 0) throw new SsvVerificationError('verifier key set was empty');
      this.keys = next;
      this.fetchedAt = Date.now();
      this.log.log(`refreshed ${next.size} AdMob verifier keys`);
    })();
    try {
      await this.inflight;
    } finally {
      this.inflight = null;
    }
  }
}
