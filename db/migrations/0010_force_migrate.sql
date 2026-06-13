-- =============================================================================
-- Emergency node evacuation. FORCE_MIGRATE_NODE drains a node AND revokes every
-- live session on it (mobile clients then failover to a healthy node). The whole
-- thing — drain flag, session revocations, outbox enqueues, and the audit row —
-- commits atomically in one serializable transaction.
-- =============================================================================

alter type admin_action_type add value if not exists 'FORCE_MIGRATE_NODE';
