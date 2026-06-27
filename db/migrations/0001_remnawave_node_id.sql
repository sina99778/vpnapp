-- Migration: Change panel_node_id from integer to text
-- Reason: Remnawave uses UUID strings for node IDs instead of Marzban's integers.
ALTER TABLE nodes ALTER COLUMN panel_node_id TYPE text;
