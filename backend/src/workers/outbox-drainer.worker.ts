import { Inject, Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { Interval } from '@nestjs/schedule';
import { pool, withTransaction } from '../db/pool';
import { IPanelClient, PANEL_CLIENT } from '../panel/IPanelClient';
import { PanelError } from '../panel/panel.types';

/**
 * Drains the panel_operations outbox — the durable guarantee that the Rebecca
 * panel eventually mirrors our authoritative DB state (extend/revoke/delete),
 * even if an inline push failed (panel down, timeout) or the process crashed
 * mid-flight.
 *
 * Lock discipline (the system's core invariant): the CLAIM is a short
 * transaction that flips due rows to 'in_flight' under FOR UPDATE SKIP LOCKED
 * and COMMITS. Only AFTER that commit (locks released) do we call the panel. The
 * lease (next_attempt_at) lets a crashed worker's in_flight rows be reclaimed.
 * SKIP LOCKED makes it safe to run multiple instances concurrently.
 */
const BATCH = Number(process.env.OUTBOX_BATCH ?? 20);
const TICK_MS = Number(process.env.OUTBOX_TICK_MS ?? 5_000);
const LEASE_MIN = Number(process.env.OUTBOX_LEASE_MIN ?? 2);
const MAX_ATTEMPTS = Number(process.env.OUTBOX_MAX_ATTEMPTS ?? 12);

interface OutboxRow {
  id: string;
  op: string;
  payload: { panel_username: string; expire_epoch?: number };
  attempts: number;
}

@Injectable()
export class OutboxDrainerWorker implements OnModuleDestroy {
  private readonly log = new Logger(OutboxDrainerWorker.name);
  private running = false;
  private shuttingDown = false;

  constructor(@Inject(PANEL_CLIENT) private readonly panel: IPanelClient) {}

  onModuleDestroy(): void {
    this.shuttingDown = true; // stop starting new ticks during shutdown
  }

  // @nestjs/schedule two-arg overload is (name: string, milliseconds: number).
  @Interval('outbox-drain', TICK_MS)
  async drain(): Promise<void> {
    if (this.running || this.shuttingDown) return; // no overlap; quiesce on shutdown
    this.running = true;
    try {
      await this.tick();
    } catch (e) {
      this.log.error(`outbox tick failed: ${(e as Error).message}`);
    } finally {
      this.running = false;
    }
  }

  private async tick(): Promise<void> {
    // --- claim (short tx, locks released on commit) ---
    const claimed: OutboxRow[] = await withTransaction(async (c) => {
      const r = await c.query(
        `update panel_operations p
            set status='in_flight',
                attempts = attempts + 1,
                next_attempt_at = now() + ($2 * interval '1 minute')      -- lease
          where p.id in (
            select id from panel_operations
             where (status in ('pending','failed')
                    or (status='in_flight' and next_attempt_at <= now()))  -- reclaim crashed
               and next_attempt_at <= now()
             order by next_attempt_at, id
             for update skip locked
             limit $1)
        returning p.id, p.op, p.payload, p.attempts`,
        [BATCH, LEASE_MIN],
      );
      return r.rows as OutboxRow[];
    });

    // --- dispatch (NO locks held) ---
    for (const op of claimed) {
      try {
        await this.dispatch(op);
        // `and status='in_flight'` so we never clobber a row another worker
        // reclaimed after our lease expired (idempotent ops make that safe).
        await pool.query(
          `update panel_operations set status='succeeded', completed_at=now()
             where id=$1 and status='in_flight'`,
          [op.id],
        );
        if (op.op === 'extend_user') {
          await pool
            .query(`update vpn_sessions set last_panel_sync_at=now() where panel_username=$1`, [
              op.payload.panel_username,
            ])
            .catch((e) =>
              this.log.warn(`last_panel_sync_at update failed for ${op.payload.panel_username}: ${(e as Error).message}`),
            );
        }
      } catch (err) {
        const retryable = !(err instanceof PanelError) || err.retryable;
        const dead = !retryable || op.attempts >= MAX_ATTEMPTS;
        const backoffSec = Math.min(300, 2 ** Math.min(op.attempts, 8)); // capped exp backoff
        await pool.query(
          `update panel_operations
              set status = $2,
                  last_error = $3,
                  next_attempt_at = now() + ($4 * interval '1 second')
            where id = $1 and status='in_flight'`,
          [op.id, dead ? 'dead' : 'failed', (err as Error).message.slice(0, 500), backoffSec],
        );
        if (dead) {
          this.log.error(`outbox op ${op.id} (${op.op}) is DEAD after ${op.attempts} attempts`);
        }
      }
    }
  }

  private async dispatch(op: OutboxRow): Promise<void> {
    switch (op.op) {
      case 'extend_user':
        if (!op.payload.expire_epoch) {
          throw new PanelError('extend_user missing expire_epoch', undefined, false);
        }
        await this.panel.setUserExpiry(op.payload.panel_username, new Date(op.payload.expire_epoch * 1000));
        return;
      case 'revoke_user':
        // Disable then delete to reclaim. Both are idempotent on the panel.
        await this.panel.disableUser(op.payload.panel_username);
        await this.panel.deleteUser(op.payload.panel_username);
        return;
      case 'delete_user':
        await this.panel.deleteUser(op.payload.panel_username);
        return;
      default:
        throw new PanelError(`unknown outbox op ${op.op}`, undefined, false);
    }
  }
}
