-- =============================================================================
-- 0002 — Time-Based Reward Model (ads → connection time)
-- Replaces the daily data cap. Connection time is now earned by watching
-- rewarded ads, proven by SERVER-SIDE VERIFICATION (SSV), never by the client.
-- The server owns absolute `vpn_sessions.expires_at`; the panel mirrors it as
-- the per-user `expire` so Xray drops the connection when time runs out.
-- =============================================================================

begin;

-- 1. Retire the data-cap model entirely.
drop table if exists daily_usage;
alter table plans drop column if exists daily_data_limit_bytes;

-- 2. Reward-model enums.
create type ad_grant_purpose as enum ('connect','extend','disconnect');
create type ad_grant_status  as enum ('pending','fulfilled','consumed','expired','revoked');
create type ad_reward_status as enum ('verified','consumed','rejected');
create type ad_network       as enum ('admob','applovin','unity','ironsource');

-- 3. Plan knobs (defaults encode the product rules).
alter table plans
  add column ads_required_connect smallint not null default 2,   -- 2 ads → 1 hour
  add column ads_required_extend  smallint not null default 2,
  add column ads_required_disconnect smallint not null default 1,
  add column grant_minutes        smallint not null default 60,   -- exactly 1 hour
  add column max_session_minutes  integer  not null default 1440; -- absolute safety ceiling

-- 4. A unit of intent: "I will watch N ads to earn time." Created by
--    POST /ads/request-ad-token. `nonce` is the opaque custom_data we hand the
--    ad SDK; the SSV callback echoes it back so we can bind the reward to this
--    grant. Single-use, short-lived.
create table ad_reward_grants (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null references users(id)   on delete cascade,
  device_id     uuid not null references devices(id) on delete cascade,
  session_id    uuid references vpn_sessions(id)     on delete set null,
  purpose       ad_grant_purpose not null,
  nonce         text not null unique,                -- custom_data handed to the ad SDK
  required_ads  smallint not null,
  verified_ads  smallint not null default 0,         -- bumped only by verified SSV callbacks
  grant_minutes smallint not null,                   -- minutes this grant is worth (0 for disconnect)
  status        ad_grant_status not null default 'pending',
  issued_at     timestamptz not null default now(),
  expires_at    timestamptz not null,                -- window to finish watching ads
  fulfilled_at  timestamptz,
  consumed_at   timestamptz,
  -- A real grant can NEVER hold the closing-ad sentinel, so the SSV guard that
  -- ignores that nonce can never accidentally swallow a genuine grant.
  constraint nonce_not_closing_sentinel check (nonce <> 'closing-session-no-grant')
);
create index ad_reward_grants_user_idx on ad_reward_grants (user_id, status);
create index ad_reward_grants_open_idx
  on ad_reward_grants (expires_at) where status in ('pending','fulfilled');

-- 5. One row per *verified* rewarded-ad SSV callback — the trust anchor.
--    A modded client cannot create rows here: insertion requires a valid
--    ad-network signature verified server-side.
create table ad_rewards (
  id               uuid primary key default gen_random_uuid(),
  grant_id         uuid not null references ad_reward_grants(id) on delete cascade,
  network          ad_network not null,
  transaction_id   text not null,                    -- ad-network txn id
  ad_unit          text,
  reward_item      text,
  reward_amount    integer,
  signature_key_id text,
  status           ad_reward_status not null default 'verified',
  verified_at      timestamptz not null default now(),
  raw              jsonb,
  -- (network, transaction_id) is the replay/idempotency guard: the same SSV
  -- callback delivered twice cannot be counted twice.
  unique (network, transaction_id)
);
create index ad_rewards_grant_idx on ad_rewards (grant_id);

-- 6. vpn_sessions: absolute expiry is already present; track funding lineage.
alter table vpn_sessions
  add column last_ad_grant_id   uuid references ad_reward_grants(id),
  add column extensions_count   integer not null default 0,
  add column last_panel_sync_at timestamptz;
-- NOTE: vpn_sessions.expires_at (from 0001) is the single source of truth for
-- "is this session still allowed to be connected". The panel `expire` is a
-- mirror kept convergent via the panel_operations outbox.

comment on column vpn_sessions.expires_at is
  'Absolute server-authoritative expiry. Extended by exactly grant_minutes per fulfilled ad grant. Mirrored to the panel user''s expire; reaper enforces as backstop.';

commit;
