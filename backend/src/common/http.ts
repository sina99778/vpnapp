/**
 * fetch() with a hard timeout via AbortController. Node 18+ global fetch.
 * Every off-box call in this service goes through a bounded timeout so a slow
 * upstream (panel or ad-network key server) can never become an unbounded wait.
 */
export async function fetchWithTimeout(
  url: string,
  init: RequestInit = {},
  timeoutMs = 5_000,
): Promise<Response> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(new Error(`timeout after ${timeoutMs}ms`)), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ac.signal });
  } finally {
    clearTimeout(timer);
  }
}

/** URL-safe base64 → standard base64 (with padding) for Buffer.from(..., 'base64'). */
export function base64UrlToBase64(input: string): string {
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  return b64 + pad;
}

/** Random URL-safe token, `bytes` of entropy. Used for ad-grant nonces. */
export function randomUrlToken(bytes = 32): string {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { randomBytes } = require('crypto') as typeof import('crypto');
  return randomBytes(bytes).toString('base64url');
}
