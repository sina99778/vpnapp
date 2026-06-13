-- =============================================================================
-- Phase 4 backend — device attestation gate.
-- Adds the `is_attested` flag (+ a TTL) the /connect endpoint checks. Attestation
-- is NOT permanent: a device must re-attest before `attested_until` lapses, so a
-- once-clean device that is later rooted loses access on the next window.
-- =============================================================================

alter table devices
  add column if not exists is_attested    boolean not null default false,
  add column if not exists attested_until timestamptz,
  -- The exact X25519 public key the successful attestation was BOUND to. /connect
  -- must check the clientPublicKey it receives equals this — otherwise the
  -- cross-HTTP-boundary binding is unenforced and a swapped key slips through.
  add column if not exists attested_client_public_key bytea;

-- Fast gate lookup for /connect: only currently-attested devices.
create index if not exists devices_attested_idx
  on devices (id) where is_attested;

-- Audit every verify attempt (pass and fail) so anomalies are queryable. The
-- generic audit_events table already exists; this is a typed, queryable record
-- of attestation outcomes specifically.
create table if not exists attestation_attempts (
  id           bigint generated always as identity primary key,
  device_id    uuid references devices(id) on delete set null,
  platform     device_platform,
  outcome      text not null,                 -- 'passed' | 'rejected'
  reason       text,                          -- failure reason (no secrets)
  ip           inet,
  created_at   timestamptz not null default now()
);
create index attestation_attempts_device_idx
  on attestation_attempts (device_id, created_at);
create index attestation_attempts_rejected_idx
  on attestation_attempts (created_at) where outcome = 'rejected';
