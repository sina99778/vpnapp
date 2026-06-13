/**
 * Attestation verification configuration. All from env so no secrets/identifiers
 * are baked into the image.
 */
export interface AttestConfig {
  // ── Android / Play Integrity ──
  androidPackageName: string;
  // Path to the service-account JSON with the playintegrity scope.
  googleCredentialsFile: string;
  // Accepted signing-cert SHA-256 digests (base64). Empty = skip the check.
  androidCertDigests: string[];
  // Max age of the integrity token (timestampMillis freshness).
  androidTokenMaxAgeMs: number;

  // ── iOS / App Attest ──
  appleTeamId: string;
  appleBundleId: string;
  // 'production' or 'development' — controls the accepted AAGUID.
  appleAttestEnv: 'production' | 'development';
  // PEM of Apple's App Attest Root CA (pinned trust anchor).
  appleRootCaPem: string;

  // ── Common ──
  challengeTtlMs: number; // how long a challenge is valid
  attestationTtlMs: number; // how long a device stays attested before re-attest
}

export function loadAttestConfig(env = process.env): AttestConfig {
  const required = (k: string): string => {
    const v = env[k];
    if (!v) throw new Error(`missing required env ${k}`);
    return v;
  };
  return {
    androidPackageName: required('ANDROID_PACKAGE_NAME'),
    googleCredentialsFile: required('GOOGLE_APPLICATION_CREDENTIALS'),
    androidCertDigests: (env.ANDROID_CERT_SHA256_B64 ?? '').split(',').filter(Boolean),
    androidTokenMaxAgeMs: Number(env.ANDROID_TOKEN_MAX_AGE_MS ?? 5 * 60_000),
    appleTeamId: required('APPLE_TEAM_ID'),
    appleBundleId: required('APPLE_BUNDLE_ID'),
    appleAttestEnv: (env.APPLE_ATTEST_ENV as 'production' | 'development') ?? 'production',
    // Accept either an inline PEM or a file PATH to one.
    appleRootCaPem: resolvePem(required('APPLE_APPATTEST_ROOT_CA_PEM')),
    challengeTtlMs: Number(env.ATTEST_CHALLENGE_TTL_MS ?? 5 * 60_000),
    attestationTtlMs: Number(env.ATTEST_TTL_MS ?? 24 * 60 * 60_000),
  };
}

/** If the value is a PEM, use it; otherwise treat it as a file path and read it. */
function resolvePem(value: string): string {
  if (value.includes('-----BEGIN')) return value;
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { readFileSync } = require('fs') as typeof import('fs');
  return readFileSync(value, 'utf8');
}

/** Thrown by any verifier when attestation is invalid. Carries a short reason. */
export class AttestationError extends Error {
  constructor(
    public readonly reason: string,
    message?: string,
  ) {
    super(message ?? reason);
    this.name = 'AttestationError';
  }
}
