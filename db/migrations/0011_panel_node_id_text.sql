-- =============================================================================
-- Support panels whose node identifiers are not integers. Rebecca (Marzban fork)
-- numbers its nodes; Remnawave identifies them by UUID. Widen panel_node_id to
-- text so one column holds either. Existing integer values cast losslessly and
-- the UNIQUE constraint is preserved across the type change.
-- =============================================================================

alter table nodes
  alter column panel_node_id type text using panel_node_id::text;

comment on column nodes.panel_node_id is
  'Panel node id as text — Rebecca integer or Remnawave UUID; null = master node';
