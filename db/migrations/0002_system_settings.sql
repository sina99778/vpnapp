-- Migration: Create system_settings table for dynamic configuration
create table system_settings (
  key text primary key,
  value jsonb not null,
  updated_at timestamptz not null default now()
);
