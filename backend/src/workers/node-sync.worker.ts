import { Inject, Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { pool } from '../db/pool';
import { IPanelClient, PANEL_CLIENT } from '../panel/IPanelClient';

/**
 * Periodically reconciles the `nodes` table with the Rebecca panel: refreshes
 * each node's live status/last_synced_at from panel.listNodes().
 *
 * CRITICAL: the UPDATE never touches `is_active` — that flag is ADMIN-owned
 * (drain/enable) and must survive every sync. We only write panel-derived
 * fields. Nodes the panel reports that we don't have a row for are logged, not
 * auto-inserted (country_code/tier are admin-configured).
 *
 * Pure status reconciliation; no DB locks held across the panel call.
 */
@Injectable()
export class NodeSyncWorker implements OnModuleDestroy {
  private readonly log = new Logger(NodeSyncWorker.name);
  private running = false;
  private shuttingDown = false;

  constructor(@Inject(PANEL_CLIENT) private readonly panel: IPanelClient) {}

  onModuleDestroy(): void {
    this.shuttingDown = true;
  }

  @Cron(CronExpression.EVERY_5_MINUTES, { name: 'node-sync' })
  async sync(): Promise<void> {
    if (this.running || this.shuttingDown) return;
    this.running = true;
    try {
      // Network call — NOT inside any transaction.
      const live = await this.panel.listNodes();
      for (const n of live) {
        // Map the panel's free-form status to our node_status enum.
        const status = isOnline(n.status) ? 'active' : 'disabled';
        // NOTE: `is_active` is deliberately absent from the SET clause.
        const r = await pool.query(
          `update nodes
              set status = $2::node_status, 
                  last_synced_at = now(), 
                  updated_at = now(),
                  error_streak = case when $2::node_status = 'active' then 0 else error_streak end
            where panel_node_id = $1`,
          [n.panelNodeId, status],
        );
        if (r.rowCount === 0) {
          this.log.warn(
            `panel node ${n.panelNodeId} (${n.name}) is not configured locally — add it with a country_code/tier to use it`,
          );
        }
      }
    } catch (e) {
      this.log.warn(`node sync skipped: ${(e as Error).message}`);
    } finally {
      this.running = false;
    }
  }
}

function isOnline(status: string): boolean {
  const s = status.toLowerCase();
  return /(online|connected|active|healthy|running)/.test(s) && !s.includes('disconn');
}
