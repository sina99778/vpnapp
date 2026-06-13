-- =============================================================================
-- /connect needs the session to remember WHICH inbound it was provisioned on,
-- so the encrypted payload (built at /connect for premium, or at
-- verify-ad-reward for free) reconstructs the exact same config.
-- =============================================================================

alter table vpn_sessions
  add column if not exists inbound_tag text,
  add column if not exists protocol    text,
  -- The exact attested client X25519 pubkey this session's payload is encrypted
  -- to. Captured at /connect so verify-ad-reward (free tier) encrypts to the
  -- SESSION's key, not the device's possibly-changed current attested key.
  add column if not exists client_public_key bytea;
