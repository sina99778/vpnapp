-- =============================================================================
-- Admin audit trail. Append-only record of every destructive admin action
-- (kick / ban / unban / tier change / panic), from BOTH the HTTP API and the
-- Telegram bot. Writes are best-effort and out-of-band — they must never block
-- or fail the action they record.
-- =============================================================================

do $$ begin
  if not exists (select 1 from pg_type where typname = 'admin_action_type') then
    create type admin_action_type as enum (
      'KICK_SESSION', 'BAN_USER', 'UNBAN_USER', 'CHANGE_TIER', 'PANIC_FREE_SESSIONS'
    );
  end if;
end $$;

create table if not exists admin_audit_logs (
  id          uuid primary key default gen_random_uuid(),
  -- The acting admin's user id. NULL for Telegram-originated ops (the operator
  -- is identified by a Telegram id stored in `details`, not a users row).
  admin_id    uuid references users(id) on delete set null,
  action_type admin_action_type not null,
  -- Polymorphic: a user id (ban/tier) or a session id (kick), NULL for panic.
  target_id   uuid,
  details     jsonb not null default '{}',   -- request intent + outcome / context
  ip_address  inet,
  created_at  timestamptz not null default now()
);

-- Timeseries access. BRIN is ideal for an append-only, time-ordered table: a
-- tiny index that gives fast range scans over created_at.
create index if not exists admin_audit_logs_created_brin
  on admin_audit_logs using brin (created_at);

-- Filtered queries ("all BANs last week", newest-first) use a composite B-tree.
create index if not exists admin_audit_logs_action_time
  on admin_audit_logs (action_type, created_at desc);

-- "What did admin X do" lookups.
create index if not exists admin_audit_logs_admin_time
  on admin_audit_logs (admin_id, created_at desc) where admin_id is not null;
