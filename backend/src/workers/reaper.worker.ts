import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { withTransaction } from '../db/pool';

/**
 * Sweeps vpn_sessions and closes anything past its deadline:
 *   • active/limited sessions whose expires_at has passed (time ran out), and
 *   • provisioning sessions whose 5-min window lapsed without ads (dead free
 *     attempts — the client never finished the reward flow).
 *
 * It marks them 'expired' and enqueues a `delete_user` into panel_operations to
 * reclaim the ephemeral panel user. It performs ZERO panel/network I/O itself —
 * the OutboxDrainerWorker makes the actual panel calls. So the whole sweep is a
 * short DB-only transaction; no lock is ever held across external I/O.
 *
 * FOR UPDATE SKIP LOCKED makes it safe to run on multiple app instances.
 */
const REAP_BATCH = Number(process.env.REAPER_BATCH ?? 500);

@Injectable()
export class ReaperWorker implements OnModuleDestroy {
  private readonly log = new Logger(ReaperWorker.name);
  private running = false;
  private shuttingDown = false;

  onModuleDestroy(): void {
    this.shuttingDown = true;
  }

  @Cron(CronExpression.EVERY_MINUTE, { name: 'session-reaper' })
  async reap(): Promise<void> {
    if (this.running || this.shuttingDown) return;
    this.running = true;
    try {
      let total = 0;
      // Drain in batches so one tick can clear a backlog without a huge tx.
      for (;;) {
        const reaped = await this.sweepOnce();
        total += reaped;
        if (reaped < REAP_BATCH) break;
      }
      if (total > 0) this.log.log(`reaped ${total} expired/dead session(s)`);
    } catch (e) {
      this.log.error(`reaper tick failed: ${(e as Error).message}`);
    } finally {
      this.running = false;
    }
  }

  /** One batch: mark expired + enqueue delete_user ops, atomically. Returns count. */
  private async sweepOnce(): Promise<number> {
    return withTransaction(async (c) => {
      const r = await c.query(
        `update vpn_sessions
            set status='expired',
                closed_at=now(),
                close_reason=coalesce(close_reason, 'reaped_expired')
          where id in (
            select id from vpn_sessions
             where status in ('provisioning','active','limited')
               and expires_at <= now()
             order by expires_at
             for update skip locked
             limit $1)
        returning id, panel_username`,
        [REAP_BATCH],
      );

      // Queue the panel cleanup (the drainer executes it). One op per reaped
      // session; the row is now 'expired' so it can't be swept again.
      for (const row of r.rows as Array<{ id: string; panel_username: string }>) {
        await c.query(
          `insert into panel_operations (session_id, op, payload, status, next_attempt_at)
           values ($1, 'delete_user', $2, 'pending', now())`,
          [row.id, { panel_username: row.panel_username }],
        );
      }
      return r.rowCount ?? 0;
    });
  }
}
