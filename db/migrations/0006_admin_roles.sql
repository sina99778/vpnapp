-- =============================================================================
-- Phase 5 — admin roles + ban flag on users. role is checked by AdminGuard via
-- a FRESH lookup (not from the JWT), so a demotion/ban takes effect immediately.
-- =============================================================================

do $$ begin
  if not exists (select 1 from pg_type where typname = 'user_role') then
    create type user_role as enum ('user', 'admin');
  end if;
end $$;

alter table users
  add column if not exists role      user_role not null default 'user',
  add column if not exists is_banned boolean   not null default false;

create index if not exists users_admin_idx on users (id) where role = 'admin';
create index if not exists users_banned_idx on users (id) where is_banned;
