import { Injectable, Logger } from '@nestjs/common';
import type { PoolClient } from 'pg';
import { pool } from '../db/pool';

const INSERT_SQL = `insert into admin_audit_logs (admin_id, action_type, target_id, details, ip_address)
   values ($1, $2, $3, $4, $5)`;

export type AdminActionType =
  | 'KICK_SESSION'
  | 'BAN_USER'
  | 'UNBAN_USER'
  | 'CHANGE_TIER'
  | 'PANIC_FREE_SESSIONS'
  | 'SET_NODE_STATUS'
  | 'FORCE_MIGRATE_NODE';

export interface AuditEntry {
  adminId?: string | null;
  actionType: AdminActionType;
  targetId?: string | null;
  details?: Record<string, unknown>;
  ip?: string | null;
}

export interface AuditLogRow {
  id: string;
  adminId: string | null;
  actionType: AdminActionType;
  targetId: string | null;
  details: Record<string, unknown>;
  ipAddress: string | null;
  createdAt: string;
}

/**
 * Append-only admin audit trail.
 *
 * INVARIANT: `record()` NEVER throws. Auditing must not break — or even slow —
 * the destructive action it documents, so every write is wrapped and a failure
 * is logged, not propagated. Callers fire it post-response (out of band).
 */
@Injectable()
export class AuditService {
  private readonly log = new Logger(AuditService.name);

  /**
   * Fire-and-forget path (used by the interceptor for kick/unban/tier and by
   * the Telegram bot). NEVER throws — a failed write must not break the action.
   */
  async record(entry: AuditEntry): Promise<void> {
    try {
      await pool.query(INSERT_SQL, params(entry));
    } catch (e) {
      // Swallow: a failed audit write must never surface to the client or crash
      // the worker. Alert on these log lines in production.
      this.log.error(`audit write failed (${entry.actionType}): ${(e as Error).message}`);
    }
  }

  /**
   * DURABLE path for highly-destructive actions (BAN_USER, PANIC). Writes the
   * audit row on the CALLER'S transaction client so it commits atomically with
   * the mutation. It does NOT swallow — if the audit can't be written the whole
   * action rolls back. Accountability over availability, by design.
   */
  async recordInTx(c: PoolClient, entry: AuditEntry): Promise<void> {
    await c.query(INSERT_SQL, params(entry));
  }

  /** Paginated, timeseries-friendly read for the dashboard. */
  async list(opts: {
    actionType?: AdminActionType;
    adminId?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ total: number; logs: AuditLogRow[] }> {
    const limit = Math.min(Math.max(opts.limit ?? 50, 1), 200);
    const offset = Math.max(opts.offset ?? 0, 0);
    const action = opts.actionType ?? null;
    const admin = opts.adminId ?? null;

    const totalQ = await pool.query(
      `select count(*)::int n from admin_audit_logs
        where ($1::admin_action_type is null or action_type = $1)
          and ($2::uuid is null or admin_id = $2)`,
      [action, admin],
    );
    const rowsQ = await pool.query(
      `select id, admin_id, action_type, target_id, details, ip_address::text as ip, created_at
         from admin_audit_logs
        where ($1::admin_action_type is null or action_type = $1)
          and ($2::uuid is null or admin_id = $2)
        order by created_at desc
        limit $3 offset $4`,
      [action, admin, limit, offset],
    );
    return {
      total: totalQ.rows[0].n,
      logs: rowsQ.rows.map((r) => ({
        id: r.id,
        adminId: r.admin_id,
        actionType: r.action_type,
        targetId: r.target_id,
        details: r.details,
        ipAddress: r.ip,
        createdAt: new Date(r.created_at).toISOString(),
      })),
    };
  }
}

function params(entry: AuditEntry): unknown[] {
  return [
    entry.adminId ?? null,
    entry.actionType,
    entry.targetId ?? null,
    entry.details ?? {},
    normalizeIp(entry.ip),
  ];
}

/** inet rejects an empty/garbage string; pass null instead, and strip the
 *  IPv4-mapped IPv6 prefix express produces (::ffff:1.2.3.4). */
function normalizeIp(ip?: string | null): string | null {
  if (!ip) return null;
  const v = ip.startsWith('::ffff:') ? ip.slice(7) : ip;
  return v.length > 0 ? v : null;
}
