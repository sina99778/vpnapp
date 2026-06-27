-- Migration: Create system_settings table for dynamic configuration
create table if not exists system_settings (
  key text primary key,
  value jsonb not null,
  updated_at timestamptz not null default now()
);
