import { Inject, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { pool, withTransaction } from '../db/pool';
import { IPanelClient, PANEL_CLIENT } from '../panel/IPanelClient';
import { AuditService } from './audit.service';

/** Who is performing a destructive action (for the durable in-tx audit). */
export interface AdminActor {
  adminId?: string | null;
  ip?: string | null;
}

const ADMIN_GRANT_DAYS = Number(process.env.ADMIN_GRANT_DAYS ?? 30);

export interface AdminStats {
  activeSessions: number;
  adsWatchedToday: number;
  totalUsers: number;
  premiumUsers: number;
}

export interface AdminSessionBrief {
  id: string;
  status: string;
  tier: string;
  expiresAt: string;
}
export interface AdminUserRow {
  id: string;
  email: string | null;
  isAnonymous: boolean;
  role: string;
  isBanned: boolean;
  status: string;
  createdAt: string;
  activeSessions: AdminSessionBrief[];
}

/**
 * Admin operations, shared by the HTTP AdminController (behind AdminGuard) and
 * the Telegram bot (behind the env whitelist). Every state mutation follows the
 * SAME discipline as the core flow: do the DB work (mark sessions revoked +
 * enqueue outbox ops) inside a short transaction; the panel calls are made by
 * the OutboxDrainerWorker — never under a held DB lock.
 */
@Injectable()
export class AdminService {
  private readonly log = new Logger(AdminService.name);

  constructor(
    @Inject(PANEL_CLIENT) private readonly panel: IPanelClient,
    private readonly audit: AuditService,
  ) {}

  // ── stats ──────────────────────────────────────────────────────────────
  async stats(): Promise<AdminStats> {
    const [active, ads, users, premium] = await Promise.all([
      pool.query(
        `select count(*)::int n from vpn_sessions where status in ('provisioning','active','limited')`,
      ),
      pool.query(`select count(*)::int n from ad_rewards where created_at >= date_trunc('day', now())`),
      pool.query(`select count(*)::int n from users where status <> 'deleted'`),
      pool.query(
        `select count(distinct s.user_id)::int n
           from subscriptions s join plans p on p.id = s.plan_id
          where p.tier = 'premium' and s.status in ('active','in_grace')
            and (s.current_period_end is null or s.current_period_end > now())`,
      ),
    ]);
    return {
      activeSessions: active.rows[0].n,
      adsWatchedToday: ads.rows[0].n,
      totalUsers: users.rows[0].n,
      premiumUsers: premium.rows[0].n,
    };
  }

  // ── user list (paginated + search) ──────────────────────────────────────
  async listUsers(opts: { search?: string; limit?: number; offset?: number }): Promise<{
    total: number;
    users: AdminUserRow[];
  }> {
    const limit = Math.min(Math.max(opts.limit ?? 25, 1), 100);
    const offset = Math.max(opts.offset ?? 0, 0);
    // Escape ILIKE metacharacters (%, _, \) so a search of "%" can't enumerate
    // all users or "%_%" trigger a pathological scan. Backslash is ILIKE's
    // default escape char, so no explicit ESCAPE clause is needed.
    const raw = opts.search?.trim();
    const search = raw ? escapeLike(raw) : null;

    const totalQ = await pool.query(
      `select count(*)::int n from users
        where status <> 'deleted' and ($1::text is null or email ilike '%'||$1||'%')`,
      [search],
    );
    const rowsQ = await pool.query(
      `select u.id, u.email, u.is_anonymous, u.role, u.is_banned, u.status, u.created_at,
              coalesce(
                json_agg(json_build_object(
                  'id', s.id, 'status', s.status, 'tier', s.tier, 'expiresAt', s.expires_at
                )) filter (where s.id is not null), '[]') as active_sessions
         from users u
         left join vpn_sessions s
           on s.user_id = u.id and s.status in ('provisioning','active','limited')
        where u.status <> 'deleted' and ($1::text is null or u.email ilike '%'||$1||'%')
        group by u.id
        order by u.created_at desc
        limit $2 offset $3`,
      [search, limit, offset],
    );
    return {
      total: totalQ.rows[0].n,
      users: rowsQ.rows.map(mapUserRow),
    };
  }

  /**
   * For the Telegram /find command. EXACT email match only — never a substring
   * fallback (which would let an operator typo enumerate the user base). email
   * is citext, so the equality is already case-insensitive.
   */
  async findUserByEmail(email: string): Promise<AdminUserRow | null> {
    const { rows } = await pool.query(
      `select u.id, u.email, u.is_anonymous, u.role, u.is_banned, u.status, u.created_at,
              coalesce(
                json_agg(json_build_object(
                  'id', s.id, 'status', s.status, 'tier', s.tier, 'expiresAt', s.expires_at
                )) filter (where s.id is not null), '[]') as active_sessions
         from users u
         left join vpn_sessions s
           on s.user_id = u.id and s.status in ('provisioning','active','limited')
        where u.email = $1 and u.status <> 'deleted'
        group by u.id
        limit 1`,
      [email.trim()],
    );
    return rows.length ? mapUserRow(rows[0]) : null;
  }

  // ── mutate: tier grant/revoke and ban toggle ────────────────────────────
  /**
   * Update a user's promo tier and/or ban flag. Banning instantly revokes every
   * live session (marked revoked + enqueued to the outbox in the SAME tx).
   */
  async mutateUser(
    userId: string,
    changes: { tier?: 'free' | 'premium'; isBanned?: boolean },
    actor: AdminActor = {},
  ): Promise<{ ok: true; revokedSessions: number }> {
    return withTransaction(async (c) => {
      const u = await c.query(`select id from users where id=$1 for update`, [userId]);
      if (u.rowCount === 0) throw new NotFoundException('user not found');

      let revoked = 0;
      if (changes.isBanned !== undefined) {
        await c.query(`update users set is_banned=$2, updated_at=now() where id=$1`, [
          userId,
          changes.isBanned,
        ]);
        if (changes.isBanned === true) {
          revoked = await this.revokeUserSessions(c, userId, 'banned');
          // DURABLE in-tx audit: ban + session revocation + this log commit
          // together. If the audit write fails, the ban rolls back. (UNBAN and
          // tier changes are audited asynchronously by the interceptor.)
          await this.audit.recordInTx(c, {
            adminId: actor.adminId,
            ip: actor.ip,
            actionType: 'BAN_USER',
            targetId: userId,
            details: { revokedSessions: revoked },
          });
        }
      }

      if (changes.tier === 'premium') {
        await this.grantInternalPremium(c, userId);
      } else if (changes.tier === 'free') {
        await c.query(
          `update subscriptions set status='expired', updated_at=now()
             from plans p
            where subscriptions.plan_id = p.id
              and subscriptions.user_id = $1
              and subscriptions.source = 'internal'
              and p.tier = 'premium'
              and subscriptions.status in ('active','in_grace')`,
          [userId],
        );
      }

      return { ok: true as const, revokedSessions: revoked };
    }, 'serializable');
  }

  // ── kick a single session ───────────────────────────────────────────────
  async kickSession(sessionId: string): Promise<{ ok: true }> {
    await withTransaction(async (c) => {
      const s = await c.query(
        `select id, panel_username, status from vpn_sessions where id=$1 for update`,
        [sessionId],
      );
      if (s.rowCount === 0) throw new NotFoundException('session not found');
      const row = s.rows[0];
      if (!['provisioning', 'active', 'limited'].includes(row.status)) {
        return; // already closed — idempotent no-op
      }
      await c.query(
        `update vpn_sessions set status='revoked', closed_at=now(), close_reason='admin_kick' where id=$1`,
        [sessionId],
      );
      await this.enqueueRevoke(c, sessionId, row.panel_username);
    }, 'serializable');
    return { ok: true };
  }

  // ── panic: revoke ALL free-tier live sessions ───────────────────────────
  /**
   * Emergency: revoke every free-tier live session AND write the audit log in
   * ONE atomic transaction. (We deliberately drop the SKIP-LOCKED batching used
   * elsewhere: the action and its accountability record must commit together,
   * and during a panic we WANT to block concurrent free connects until it lands.
   * Acceptable as a rare, deliberate emergency override.)
   */
  async panicRevokeFreeSessions(actor: AdminActor = {}): Promise<{ ok: true; revoked: number }> {
    const revoked = await withTransaction(async (c) => {
      const r = await c.query(
        `update vpn_sessions
            set status='revoked', closed_at=now(), close_reason='panic_revoke_free'
          where tier='free' and status in ('provisioning','active','limited')
        returning id, panel_username`,
      );
      for (const row of r.rows as Array<{ id: string; panel_username: string }>) {
        await this.enqueueRevoke(c, row.id, row.panel_username);
      }
      // DURABLE in-tx audit — commits atomically with the mass revocation.
      await this.audit.recordInTx(c, {
        adminId: actor.adminId,
        ip: actor.ip,
        actionType: 'PANIC_FREE_SESSIONS',
        targetId: null,
        details: { revoked: r.rowCount ?? 0 },
      });
      return r.rowCount ?? 0;
    }, 'serializable');
    this.log.warn(`PANIC: revoked ${revoked} free session(s)`);
    return { ok: true, revoked };
  }

  // ── node health (panel + our synced load) ───────────────────────────────
  async nodesHealth(): Promise<{
    panelReachable: boolean;
    nodes: Array<{
      id: string;
      name: string;
      status: string;
      isActive: boolean;
      loadPct: number | null;
      activeConnections: number;
      countryCode?: string;
    }>;
  }> {
    // DB view (current_load from the sync worker) + live connection count per
    // node — no lock, no external call.
    const db = await pool.query(
      `select n.id, n.panel_node_id, n.name, n.status, n.is_active, n.current_load, n.country_code,
              count(s.id) filter (where s.status in ('provisioning','active','limited')) as active_conns
         from nodes n
         left join vpn_sessions s on s.node_id = n.id
        group by n.id
        order by n.sort_weight asc, n.name asc`,
    );
    const byId = new Map<string, { status: string }>();
    let panelReachable = true;
    try {
      // Network call — NOT inside any transaction.
      const live = await this.panel.listNodes();
      for (const n of live) byId.set(n.panelNodeId, { status: n.status });
    } catch (e) {
      panelReachable = false;
      this.log.warn(`nodesHealth: panel unreachable: ${(e as Error).message}`);
    }
    return {
      panelReachable,
      nodes: db.rows.map((r) => ({
        id: r.id,
        name: r.name,
        // Prefer the live panel status; fall back to our last-synced status.
        status: byId.get(r.panel_node_id)?.status ?? r.status,
        isActive: r.is_active,
        loadPct: r.current_load != null ? Math.round(Number(r.current_load) * 100) : null,
        activeConnections: Number(r.active_conns),
        countryCode: r.country_code,
      })),
    };
  }

  /** Admin drain/enable. is_active=false → /connect places no new sessions here. */
  async setNodeActive(nodeId: string, isActive: boolean): Promise<{ ok: true; isActive: boolean }> {
    const r = await pool.query(
      `update nodes set is_active=$2, updated_at=now() where id=$1`,
      [nodeId, isActive],
    );
    if (r.rowCount === 0) throw new NotFoundException('node not found');
    this.log.log(`node ${nodeId} ${isActive ? 'enabled' : 'drained'}`);
    return { ok: true, isActive };
  }

  // ── force-migrate: emergency node evacuation ─────────────────────────────
  /**
   * Catastrophic-failure handling (dead host / IP-blocked). In ONE serializable
   * transaction: drain the node (is_active=false → no new connects), revoke
   * EVERY live session bound to it (so mobile clients fail over to a healthy
   * node), enqueue the panel de-provisioning to the outbox, and write the audit
   * record. All-or-nothing — if the audit write fails the entire evacuation
   * rolls back. Lock discipline holds: only DB work runs in the tx; the panel
   * calls are made later by the OutboxDrainerWorker, never under a held lock.
   */
  async forceMigrateNode(
    nodeId: string,
    actor: AdminActor = {},
  ): Promise<{ ok: true; evicted: number }> {
    const evicted = await withTransaction(async (c) => {
      // Lock the node row so a concurrent drain/enable can't interleave with it.
      const n = await c.query(`select id from nodes where id=$1 for update`, [nodeId]);
      if (n.rowCount === 0) throw new NotFoundException('node not found');

      // 1. Stop NEW connections immediately.
      await c.query(`update nodes set is_active=false, updated_at=now() where id=$1`, [nodeId]);

      // 2. Revoke every live session on this node (bulk) ...
      const r = await c.query(
        `update vpn_sessions
            set status='revoked', closed_at=now(), close_reason='force_migrate'
          where node_id=$1 and status in ('provisioning','active','limited')
        returning id, panel_username`,
        [nodeId],
      );
      // 3. ... and enqueue panel de-provisioning for each (drained by the worker).
      for (const row of r.rows as Array<{ id: string; panel_username: string }>) {
        await this.enqueueRevoke(c, row.id, row.panel_username);
      }

      // 4. DURABLE in-tx audit — commits atomically with the evacuation.
      await this.audit.recordInTx(c, {
        adminId: actor.adminId,
        ip: actor.ip,
        actionType: 'FORCE_MIGRATE_NODE',
        targetId: nodeId,
        details: { evicted: r.rowCount ?? 0 },
      });
      return r.rowCount ?? 0;
    }, 'serializable');
    this.log.warn(`FORCE MIGRATE node ${nodeId}: drained + evicted ${evicted} session(s)`);
    return { ok: true, evicted };
  }

  // ── helpers ──────────────────────────────────────────────────────────────

  private async revokeUserSessions(
    c: import('pg').PoolClient,
    userId: string,
    reason: string,
  ): Promise<number> {
    const r = await c.query(
      `update vpn_sessions set status='revoked', closed_at=now(), close_reason=$2
        where user_id=$1 and status in ('provisioning','active','limited')
      returning id, panel_username`,
      [userId, reason],
    );
    for (const row of r.rows as Array<{ id: string; panel_username: string }>) {
      await this.enqueueRevoke(c, row.id, row.panel_username);
    }
    return r.rowCount ?? 0;
  }

  private async enqueueRevoke(
    c: import('pg').PoolClient,
    sessionId: string,
    panelUsername: string,
  ): Promise<void> {
    await c.query(
      `insert into panel_operations (session_id, op, payload, status, next_attempt_at)
       values ($1, 'revoke_user', $2, 'pending', now())`,
      [sessionId, { panel_username: panelUsername }],
    );
  }

  private async grantInternalPremium(c: import('pg').PoolClient, userId: string): Promise<void> {
    // Ensure a premium plan to attach the grant to (idempotent).
    await c.query(
      `insert into plans (code, tier, max_devices, max_concurrent_sessions, store_product_ids)
       values ('admin_grant_premium','premium',5,3,'{}') on conflict (code) do nothing`,
    );
    const plan = await c.query(`select id from plans where code='admin_grant_premium'`);
    const planId = plan.rows[0].id as string;
    const periodEnd = new Date(Date.now() + ADMIN_GRANT_DAYS * 24 * 60 * 60_000);

    // Extend ALL existing internal grants for this user+plan (handles the case
    // where more than one exists); if none was updated, insert a fresh grant.
    const upd = await c.query(
      `update subscriptions set current_period_end=$3, status='active', updated_at=now()
        where user_id=$1 and source='internal' and plan_id=$2 and status in ('active','in_grace')`,
      [userId, planId, periodEnd],
    );
    if ((upd.rowCount ?? 0) === 0) {
      await c.query(
        `insert into subscriptions (user_id, plan_id, source, status, current_period_start, current_period_end)
         values ($1,$2,'internal','active', now(), $3)`,
        [userId, planId, periodEnd],
      );
    }
  }
}

/** Escape LIKE/ILIKE metacharacters (backslash is ILIKE's default escape). */
function escapeLike(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/%/g, '\\%').replace(/_/g, '\\_');
}

/** Map a users-with-active-sessions row to the API shape. */
function mapUserRow(r: {
  id: string;
  email: string | null;
  is_anonymous: boolean;
  role: string;
  is_banned: boolean;
  status: string;
  created_at: string | Date;
  active_sessions: AdminSessionBrief[];
}): AdminUserRow {
  return {
    id: r.id,
    email: r.email,
    isAnonymous: r.is_anonymous,
    role: r.role,
    isBanned: r.is_banned,
    status: r.status,
    createdAt: new Date(r.created_at).toISOString(),
    activeSessions: r.active_sessions,
  };
}
