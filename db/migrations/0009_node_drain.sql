-- =============================================================================
-- Node draining. `is_active` is an ADMIN-controlled flag (separate from
-- `status`, which the sync worker derives from panel health). When false, the
-- /connect node picker skips the node — new sessions go elsewhere while existing
-- sessions on it run to expiry. The sync worker never touches this column.
-- =============================================================================

alter table nodes add column if not exists is_active boolean not null default true;
create index if not exists nodes_active_idx on nodes (id) where is_active;

-- Audit action for node drain/enable (IF NOT EXISTS → idempotent re-runs).
alter type admin_action_type add value if not exists 'SET_NODE_STATUS';
