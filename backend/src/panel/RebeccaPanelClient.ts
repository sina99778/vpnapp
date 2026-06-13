import { Injectable, Logger, Optional } from '@nestjs/common';
import { fetchWithTimeout } from '../common/http';
import { IPanelClient } from './IPanelClient';
import {
  CreateUserParams,
  PanelError,
  PanelNode,
  PanelUser,
  PanelUserStatus,
} from './panel.types';

interface RebeccaConfig {
  baseUrl: string; // e.g. https://panel.internal:8000  (PRIVATE network only)
  username: string;
  password: string;
  requestTimeoutMs?: number;
}

/** Shape of Rebecca's /api/user response (subset we rely on). */
interface RebeccaUserDto {
  username: string;
  status: string;
  expire: number | null; // UNIX SECONDS (Marzban convention) or null = unlimited
  data_limit: number | null;
  used_traffic: number;
  subscription_url?: string;
}

const EXPIRE_DRIFT_TOLERANCE_MS = 2_000;

/**
 * Rebecca (Marzban-fork) implementation of IPanelClient.
 *
 * - Holds exactly one admin identity; the JWT lives only in memory.
 * - Single-flight token refresh (no thundering herd on expiry / 401).
 * - Round-trips `expire` after every write to catch a seconds-vs-ms mismatch.
 */
@Injectable()
export class RebeccaPanelClient implements IPanelClient {
  private readonly log = new Logger(RebeccaPanelClient.name);
  private readonly cfg: RebeccaConfig;
  private token: string | null = null;
  private tokenExpiresAt = 0;
  private inflightAuth: Promise<string> | null = null;

  // @Optional so Nest injects nothing (the param exists only for tests); config
  // comes from env. Without it, Nest tries to resolve the `Object`-typed param.
  constructor(@Optional() cfg?: Partial<RebeccaConfig>) {
    this.cfg = {
      baseUrl: cfg?.baseUrl ?? process.env.PANEL_BASE_URL ?? '',
      username: cfg?.username ?? process.env.PANEL_ADMIN_USER ?? '',
      password: cfg?.password ?? process.env.PANEL_ADMIN_PASS ?? '',
      requestTimeoutMs: cfg?.requestTimeoutMs ?? Number(process.env.PANEL_TIMEOUT_MS ?? 8_000),
    };
    if (!this.cfg.baseUrl) throw new Error('PANEL_BASE_URL is required');
  }

  // ---- auth ---------------------------------------------------------------

  /** Returns a valid bearer token, refreshing if needed. Single-flight. */
  private async getToken(): Promise<string> {
    if (this.token && Date.now() < this.tokenExpiresAt - 60_000) return this.token;
    if (this.inflightAuth) return this.inflightAuth;

    this.inflightAuth = (async () => {
      const body = new URLSearchParams({
        username: this.cfg.username,
        password: this.cfg.password,
        grant_type: 'password',
      });
      const res = await fetchWithTimeout(
        `${this.cfg.baseUrl}/api/admin/token`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body,
        },
        this.cfg.requestTimeoutMs,
      );
      if (!res.ok) {
        throw new PanelError(`panel auth failed: ${res.status}`, res.status, res.status >= 500);
      }
      const json = (await res.json()) as { access_token: string };
      this.token = json.access_token;
      // Refresh well before the panel's JWT_ACCESS_TOKEN_EXPIRE_MINUTES (1440 default).
      this.tokenExpiresAt = Date.now() + 60 * 60 * 1000;
      return this.token;
    })();

    try {
      return await this.inflightAuth;
    } finally {
      this.inflightAuth = null;
    }
  }

  /** Authenticated JSON request with one transparent re-auth on 401. */
  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    retryOn401 = true,
  ): Promise<T> {
    const token = await this.getToken();
    const res = await fetchWithTimeout(
      `${this.cfg.baseUrl}${path}`,
      {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      },
      this.cfg.requestTimeoutMs,
    );

    if (res.status === 401 && retryOn401) {
      this.token = null;
      this.tokenExpiresAt = 0;
      return this.request<T>(method, path, body, false);
    }
    if (res.status === 404) {
      return undefined as unknown as T;
    }
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new PanelError(
        `panel ${method} ${path} -> ${res.status}: ${text.slice(0, 300)}`,
        res.status,
        res.status >= 500 || res.status === 429,
      );
    }
    if (res.status === 204) return undefined as unknown as T;
    return (await res.json()) as T;
  }

  // ---- mapping ------------------------------------------------------------

  private toPanelUser(dto: RebeccaUserDto): PanelUser {
    const statusMap: Record<string, PanelUserStatus> = {
      active: 'active',
      disabled: 'disabled',
      limited: 'limited',
      expired: 'expired',
      on_hold: 'on_hold',
    };
    return {
      username: dto.username,
      // expire is UNIX SECONDS; 0/null => unlimited (null here).
      expireAt: dto.expire ? new Date(dto.expire * 1000) : null,
      dataLimitBytes: dto.data_limit ?? null,
      status: statusMap[dto.status] ?? 'active',
      usedTrafficBytes: dto.used_traffic ?? 0,
      subscriptionToken: dto.subscription_url,
    };
  }

  private static toEpochSeconds(d: Date): number {
    return Math.floor(d.getTime() / 1000);
  }

  // ---- IPanelClient -------------------------------------------------------

  async createUser(params: CreateUserParams): Promise<PanelUser> {
    const inbounds = params.inboundsByProtocol;
    const protocols = Object.keys(inbounds);
    if (protocols.length === 0 || protocols.every((p) => (inbounds[p] ?? []).length === 0)) {
      // Hard fail: an empty allow-list would grant ALL inbounds on the node.
      throw new PanelError('refusing to create user with empty inbounds allow-list', undefined, false);
    }

    const payload = {
      username: params.username,
      expire: RebeccaPanelClient.toEpochSeconds(params.expireAt),
      data_limit: params.dataLimitBytes ?? 0,
      data_limit_reset_strategy: 'no_reset',
      status: 'active',
      proxies: params.proxies,
      inbounds: params.inboundsByProtocol,
    };

    const created = await this.request<RebeccaUserDto>('POST', '/api/user', payload);
    const user = this.toPanelUser(created);
    this.assertExpiryRoundTrip(user, params.expireAt, 'createUser');
    return user;
  }

  async setUserExpiry(username: string, expireAt: Date): Promise<PanelUser> {
    // Marzban-family PUT (UserModify) is a PARTIAL update — sending only the
    // fields we want to change is safe and does NOT blank proxies/inbounds.
    // (See docs/phase1-panel-contract.md; verify against your /docs once.)
    await this.request<RebeccaUserDto>('PUT', `/api/user/${encodeURIComponent(username)}`, {
      expire: RebeccaPanelClient.toEpochSeconds(expireAt),
    });
    // Read-back: the write is only trusted once the panel echoes the expiry.
    const user = await this.getUser(username);
    if (!user) throw new PanelError(`user ${username} vanished after expiry update`);
    this.assertExpiryRoundTrip(user, expireAt, 'setUserExpiry');
    return user;
  }

  async getUser(username: string): Promise<PanelUser | null> {
    const dto = await this.request<RebeccaUserDto | undefined>(
      'GET',
      `/api/user/${encodeURIComponent(username)}`,
    );
    return dto ? this.toPanelUser(dto) : null;
  }

  async disableUser(username: string): Promise<void> {
    await this.request('PUT', `/api/user/${encodeURIComponent(username)}`, { status: 'disabled' });
  }

  async deleteUser(username: string): Promise<void> {
    await this.request('DELETE', `/api/user/${encodeURIComponent(username)}`);
  }

  async getUserUsage(username: string, start?: Date, end?: Date): Promise<number> {
    const qs = new URLSearchParams();
    if (start) qs.set('start', start.toISOString());
    if (end) qs.set('end', end.toISOString());
    const suffix = qs.toString() ? `?${qs}` : '';
    const dto = await this.request<{ usages?: Array<{ used_traffic: number }>; used_traffic?: number }>(
      'GET',
      `/api/user/${encodeURIComponent(username)}/usage${suffix}`,
    );
    if (!dto) return 0;
    if (typeof dto.used_traffic === 'number') return dto.used_traffic;
    return (dto.usages ?? []).reduce((sum, u) => sum + (u.used_traffic ?? 0), 0);
  }

  async listNodes(): Promise<PanelNode[]> {
    const nodes = await this.request<
      Array<{ id: number; name: string; status: string; address?: string }>
    >('GET', '/api/nodes');
    return (nodes ?? []).map((n) => ({
      panelNodeId: n.id,
      name: n.name,
      status: n.status,
      address: n.address,
    }));
  }

  private assertExpiryRoundTrip(user: PanelUser, sent: Date, op: string): void {
    const got = user.expireAt?.getTime();
    if (got === undefined || Math.abs(got - sent.getTime()) > EXPIRE_DRIFT_TOLERANCE_MS) {
      // Almost always a seconds-vs-milliseconds encoding bug. Fail loud, never
      // ship a session whose real expiry we can't trust.
      throw new PanelError(
        `${op}: expire round-trip mismatch (sent ${sent.toISOString()}, ` +
          `panel stored ${user.expireAt?.toISOString() ?? 'null'})`,
        undefined,
        false,
      );
    }
  }
}
