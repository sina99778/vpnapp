-- =============================================================================
-- VPN Middleware — Phase 1 schema (PostgreSQL 16+)
-- The middleware DB is the single source of truth for identity, entitlement,
-- and session state. The Rebecca panel holds only ephemeral, per-session
-- VPN credentials that this backend creates and destroys.
-- =============================================================================

create extension if not exists citext;
create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- Enums
-- ---------------------------------------------------------------------------
create type user_status          as enum ('active','suspended','deleted');
create type plan_tier            as enum ('free','premium');
create type subscription_status  as enum ('active','in_grace','on_hold','paused','canceled','expired','revoked');
create type subscription_source  as enum ('google_play','app_store','promo','internal');
create type device_platform      as enum ('android','ios');
create type device_status        as enum ('active','blocked');
create type session_status       as enum ('provisioning','active','limited','expired','revoked','closed','failed');
create type node_status          as enum ('active','draining','disabled');
create type panel_op_status      as enum ('pending','in_flight','succeeded','failed','dead');
create type attestation_purpose  as enum ('device_register','connect','iap_link');

-- ---------------------------------------------------------------------------
-- Identity
-- ---------------------------------------------------------------------------
-- Freemium funnel: a user row is created on first app launch (anonymous,
-- bound to a device). Adding email+password later "claims" the account.
create table users (
  id            uuid primary key default gen_random_uuid(),
  email         citext unique,
  password_hash text,                          -- argon2id; null while anonymous
  is_anonymous  boolean not null default true,
  status        user_status not null default 'active',
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  deleted_at    timestamptz,
  constraint email_required_unless_anon
    check (is_anonymous or email is not null)
);

create table devices (
  id                   uuid primary key default gen_random_uuid(),
  user_id              uuid not null references users(id) on delete cascade,
  platform             device_platform not null,
  install_id           text not null,          -- client-generated install UUID (informational, not trusted)
  app_version          text,
  status               device_status not null default 'active',
  -- Android / Play Integrity (server-decoded verdict snapshot)
  integrity_level      smallint,               -- 0 none, 1 basic, 2 device, 3 strong
  last_integrity_verdict jsonb,
  -- iOS / App Attest
  app_attest_key_id    text,
  app_attest_public_key bytea,                 -- verified P-256 public key
  app_attest_counter   bigint not null default 0,  -- must be strictly increasing (trigger below)
  app_attest_receipt   bytea,                  -- for Apple fraud-risk endpoint
  -- false when the platform cannot attest (iOS simulator, Mac Catalyst, some
  -- extensions). Such devices are capped to free tier with extra rate-limiting
  -- rather than hard-rejected. Android sets this from Play Integrity support.
  attestation_capable  boolean not null default true,
  rooted_indicator     boolean,               -- set when Play Integrity lacks MEETS_DEVICE_INTEGRITY
  last_attested_at     timestamptz,
  created_at           timestamptz not null default now(),
  updated_at           timestamptz not null default now(),
  unique (user_id, install_id)
);
create index devices_user_idx on devices (user_id);
-- Apple guidance: a public key already bound to another user is a replay.
create unique index devices_app_attest_key_uq
  on devices (app_attest_key_id) where app_attest_key_id is not null;

-- App Attest assertion counter must never go backward (replay defense at the
-- DB layer, in addition to the application check).
create or replace function enforce_attest_counter_monotonic()
returns trigger language plpgsql as $$
begin
  if new.app_attest_counter <= old.app_attest_counter and old.app_attest_counter > 0 then
    raise exception 'app_attest_counter must be strictly increasing (% -> %)',
      old.app_attest_counter, new.app_attest_counter;
  end if;
  return new;
end;
$$;
create trigger devices_attest_counter_monotonic
  before update on devices
  for each row
  when (new.app_attest_counter is distinct from old.app_attest_counter)
  execute function enforce_attest_counter_monotonic();

-- One-time server-issued challenges for Play Integrity requestHash / App
-- Attest clientDataHash. Single use, short expiry.
create table attestation_challenges (
  id          uuid primary key default gen_random_uuid(),
  device_id   uuid references devices(id) on delete cascade,
  purpose     attestation_purpose not null,
  challenge   bytea not null,                  -- >= 16 random bytes
  expires_at  timestamptz not null,
  consumed_at timestamptz,
  created_at  timestamptz not null default now()
);
create index attestation_challenges_open_idx
  on attestation_challenges (device_id, purpose) where consumed_at is null;

-- Opaque rotating refresh tokens; only the hash is stored.
-- family_id groups a rotation lineage: on reuse-detection of any token in the
-- family, the whole family is revoked atomically (stolen-token containment).
create table refresh_tokens (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references users(id) on delete cascade,
  device_id    uuid not null references devices(id) on delete cascade,
  family_id    uuid not null,                 -- constant across a rotation chain
  token_hash   bytea not null unique,          -- sha256(raw token)
  issued_at    timestamptz not null default now(),
  expires_at   timestamptz not null,
  rotated_from uuid references refresh_tokens(id),
  revoked_at   timestamptz,
  revoke_reason text
);
create index refresh_tokens_live_idx on refresh_tokens (user_id) where revoked_at is null;
create index refresh_tokens_family_idx on refresh_tokens (family_id) where revoked_at is null;
create index refresh_tokens_device_idx on refresh_tokens (device_id) where revoked_at is null;

-- ---------------------------------------------------------------------------
-- Plans & entitlements (store-driven; the client NEVER asserts its tier)
-- ---------------------------------------------------------------------------
create table plans (
  id                       uuid primary key default gen_random_uuid(),
  code                     text not null unique,   -- 'free' | 'premium_monthly' | ...
  tier                     plan_tier not null,
  max_devices              smallint not null default 3,
  max_concurrent_sessions  smallint not null default 1,
  session_ttl_seconds      integer  not null default 900,   -- sliding panel-credential TTL
  daily_data_limit_bytes   bigint,                          -- null = unlimited
  store_product_ids        text[] not null default '{}',    -- Google productId / Apple productId
  is_active                boolean not null default true,
  created_at               timestamptz not null default now()
);

-- One row per store purchase lineage. Updated ONLY by webhook/API
-- verification (RTDN + subscriptionsv2.get; ASSN V2 + App Store Server API).
create table subscriptions (
  id                            uuid primary key default gen_random_uuid(),
  user_id                       uuid not null references users(id) on delete cascade,
  plan_id                       uuid not null references plans(id),
  source                        subscription_source not null,
  status                        subscription_status not null,
  current_period_start          timestamptz,
  current_period_end            timestamptz,    -- expiryTime / expiresDate (grace pushes this out)
  auto_renewing                 boolean,
  google_purchase_token         text,
  google_linked_purchase_token  text,           -- the OLD token this one supersedes on resubscribe
  google_acknowledged_at        timestamptz,    -- must ack within 3 days or Google auto-refunds
  apple_original_transaction_id text,
  apple_app_account_token       uuid,           -- our UUID set at purchase time
  grace_period_end              timestamptz,    -- entitle until here while in_grace
  latest_store_payload          jsonb,          -- last verified store state (audit/debug)
  created_at                    timestamptz not null default now(),
  updated_at                    timestamptz not null default now(),
  constraint store_ref_present check (
    (source = 'google_play' and google_purchase_token is not null)
    or (source = 'app_store' and apple_original_transaction_id is not null)
    or (source in ('promo','internal'))
  )
);
create unique index subscriptions_google_uq
  on subscriptions (google_purchase_token) where google_purchase_token is not null;
create unique index subscriptions_apple_uq
  on subscriptions (apple_original_transaction_id) where apple_original_transaction_id is not null;
create index subscriptions_user_idx on subscriptions (user_id, status);
-- Find the subscription a resubscribe supersedes, to mark it canceled.
create index subscriptions_google_linked_idx
  on subscriptions (google_linked_purchase_token) where google_linked_purchase_token is not null;
-- Worker scan for purchases still needing acknowledgement.
create index subscriptions_unacked_idx
  on subscriptions (created_at)
  where source = 'google_play' and google_acknowledged_at is null;

-- Raw store webhook intake, deduped before processing.
-- Handler pattern: INSERT ... ON CONFLICT (source, dedupe_key) DO NOTHING to
-- absorb redelivery, then SELECT ... FOR UPDATE on the row and re-check
-- processed_at IS NULL before acting (guards concurrent processing).
create table store_notifications (
  id           uuid primary key default gen_random_uuid(),
  source       subscription_source not null,
  dedupe_key   text not null,                  -- Pub/Sub messageId | notificationUUID
  event_type   text not null,
  raw          jsonb not null,
  received_at  timestamptz not null default now(),
  processed_at timestamptz,
  error        text,
  expires_at   timestamptz not null default now() + interval '90 days',  -- cleanup job target
  unique (source, dedupe_key)
);
create index store_notifications_unprocessed_idx
  on store_notifications (received_at) where processed_at is null;

-- The single entitlement rule, in one place. Premium wins explicitly — we do
-- NOT rely on enum sort order. Only 'active' and 'in_grace' subscriptions whose
-- period has not lapsed are entitled; on_hold/paused/canceled/expired/revoked
-- are not. See docs/phase1-architecture-notes.md §7 for the status state machine.
create or replace function effective_tier(p_user_id uuid)
returns plan_tier language sql stable as $$
  select case
    when exists (
      select 1
        from subscriptions s join plans p on p.id = s.plan_id
       where s.user_id = p_user_id
         and p.tier = 'premium'
         and s.status in ('active','in_grace')
         and (s.current_period_end is null or s.current_period_end > now())
    ) then 'premium'::plan_tier
    else 'free'::plan_tier
  end;
$$;

-- ---------------------------------------------------------------------------
-- Node catalog (mirror of the Rebecca panel, synced by a worker)
-- ---------------------------------------------------------------------------
create table nodes (
  id             uuid primary key default gen_random_uuid(),
  panel_node_id  text unique,                  -- Rebecca integer / Remnawave UUID
  name           text not null,
  country_code   char(2) not null,
  city           text,
  tier           plan_tier not null default 'premium',
  status         node_status not null default 'active',
  is_active      boolean not null default true,
  error_streak   integer not null default 0,
  capacity       integer not null default 1000,
  current_load   real not null default 0,      -- 0..1, from sync worker
  sort_weight    integer not null default 100,
  last_synced_at timestamptz,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

-- Which Rebecca inbound tags live on which node, and which tier they serve.
-- Free sessions are ONLY ever provisioned with free-tier inbound tags; the
-- Xray nodes therefore enforce tiering — not the app.
create table node_inbounds (
  id          uuid primary key default gen_random_uuid(),
  node_id     uuid not null references nodes(id) on delete cascade,
  inbound_tag text not null,
  protocol    text not null,                   -- vless | trojan | vmess | shadowsocks
  tier        plan_tier not null default 'premium',
  unique (node_id, inbound_tag)
);

-- Connection endpoints (host/port/SNI/Reality params) mirrored from the
-- panel's hosts config. This is the sensitive table: access restricted to the
-- payload-builder DB role; never exposed by any catalog endpoint.
create table node_endpoints (
  id          uuid primary key default gen_random_uuid(),
  node_id     uuid not null references nodes(id) on delete cascade,
  inbound_tag text not null,
  address     text not null,                   -- IP or domain the client dials
  port        integer not null,
  security    jsonb not null default '{}',     -- sni, reality pbk/sid/fp, alpn, path...
  is_active   boolean not null default true,
  updated_at  timestamptz not null default now(),
  unique (node_id, inbound_tag, address, port)
);
-- Payload builder selects active endpoints for the chosen node.
create index node_endpoints_active_idx on node_endpoints (node_id) where is_active;

-- ---------------------------------------------------------------------------
-- VPN sessions (one ephemeral Rebecca user per session)
-- ---------------------------------------------------------------------------
create table vpn_sessions (
  id                uuid primary key default gen_random_uuid(),
  user_id           uuid not null references users(id),
  device_id         uuid not null references devices(id),
  node_id           uuid not null references nodes(id),
  tier              plan_tier not null,        -- tier at creation (audit)
  status            session_status not null default 'provisioning',
  panel_username    text not null unique,      -- e.g. s_<22-char base62>
  credential_ref    uuid not null,             -- VLESS/VMess UUID handed to the panel
  expires_at        timestamptz not null,      -- sliding; extended by heartbeat
  last_heartbeat_at timestamptz,
  bytes_used        bigint not null default 0, -- from panel usage polling
  created_at        timestamptz not null default now(),
  activated_at      timestamptz,
  closed_at         timestamptz,
  close_reason      text
);
-- One live session per device, no exceptions; per-user concurrency is
-- enforced in the connect transaction against plans.max_concurrent_sessions.
create unique index vpn_sessions_one_live_per_device
  on vpn_sessions (device_id) where status in ('provisioning','active','limited');
create index vpn_sessions_live_user_idx
  on vpn_sessions (user_id) where status in ('provisioning','active','limited');
create index vpn_sessions_reaper_idx
  on vpn_sessions (expires_at, id) where status in ('provisioning','active','limited');

-- Free-tier daily quota accounting. Semantics: bytes_used = bytes actually
-- TRANSMITTED today (reconciled from the panel usage API at heartbeat), NOT
-- bytes pre-allocated. An early disconnect does not refund usage. A new
-- session's panel data_limit is (plan cap - bytes_used so far today).
-- 'day' is a UTC calendar date — quota resets at 00:00 UTC for all users.
create table daily_usage (
  user_id    uuid not null references users(id) on delete cascade,
  day        date not null,            -- UTC date; reset boundary is 00:00 UTC
  bytes_used bigint not null default 0,
  primary key (user_id, day)
);

-- ---------------------------------------------------------------------------
-- Panel operation outbox — revokes/extends/deletes must never be lost,
-- even if the panel is briefly unreachable.
-- ---------------------------------------------------------------------------
create table panel_operations (
  id              bigint generated always as identity primary key,
  session_id      uuid references vpn_sessions(id) on delete set null,
  op              text not null,               -- create_user|extend_user|revoke_user|delete_user
  payload         jsonb not null,
  status          panel_op_status not null default 'pending',
  attempts        integer not null default 0,
  next_attempt_at timestamptz not null default now(),
  last_error      text,
  created_at      timestamptz not null default now(),
  completed_at    timestamptz
);
create index panel_operations_due_idx
  on panel_operations (next_attempt_at, id) where status in ('pending','failed');
create index panel_operations_session_idx on panel_operations (session_id);

-- ---------------------------------------------------------------------------
-- Audit (security events only — never traffic/destination logs)
-- ---------------------------------------------------------------------------
create table audit_events (
  id         bigint generated always as identity primary key,
  user_id    uuid,
  device_id  uuid,
  event      text not null,    -- login_failed, attest_failed, session_revoked, ...
  ip         inet,
  meta       jsonb,
  created_at timestamptz not null default now()
);
create index audit_events_user_idx on audit_events (user_id, created_at);
create index audit_events_event_idx on audit_events (event, created_at);
