-- =============================================================================
-- Brute-force lockout state for password login. Per-user counters: a wrong
-- password increments failed_login_count; past a threshold the account is
-- locked until locked_until. A successful login resets both.
-- =============================================================================

alter table users
  add column if not exists failed_login_count integer not null default 0,
  add column if not exists locked_until        timestamptz;
