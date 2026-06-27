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

interface RemnawaveConfig {
  baseUrl: string; // panel origin, e.g. https://panel.example.com (we append /api)
  token: string; // panel API token, sent as `Authorization: Bearer <token>`
  /** Optional X-Api-Key for the caddy-with-auth reverse proxy in front of the panel. */
  caddyToken?: string;
  /**
   * Internal-squad UUID(s) to assign on user creation. In Remnawave a user's
   * node/inbound access is scoped by squad membership — this is the equivalent
   * of Rebecca's inbound allow-list. MUST be non-empty (fail-closed).
   */
  squadUuids: string[];
  requestTimeoutMs?: number;
}

/** Remnawave's UserResponseDto (the subset we rely on). expireAt is ISO-8601. */
interface RemnawaveUserDto {
  uuid: string;
  shortUuid: string;
  username: string;
  status: string; // ACTIVE | DISABLED | LIMITED | EXPIRED
  trafficLimitBytes: number;
  expireAt: string; // ISO datetime
  subscriptionUrl: string;
  userTraffic?: { usedTrafficBytes?: number };
}

/** Remnawave's NodeResponseDto (subset). Node id is a UUID, not an integer. */
interface RemnawaveNodeDto {
  uuid: string;
  name: string;
  address: string;
  isConnected: boolean;
  isDisabled: boolean;
  isConnecting: boolean;
}

const EXPIRE_DRIFT_TOLERANCE_MS = 2_000;

/**
 * Remnawave implementation of IPanelClient (https://docs.rw).
 *
 * Differences from Rebecca that this client absorbs so the rest of the service
 * never sees them:
 *  - Auth is a STATIC API token (Bearer), not an admin login → no token refresh.
 *  - Every response is wrapped in `{ "response": <data> }` — we unwrap it.
 *  - expireAt is an ISO-8601 datetime (not Marzban's UNIX-seconds), so the
 *    seconds-vs-ms footgun is gone — but we still round-trip-validate.
 *  - Node ids are UUIDs (text), surfaced through PanelNode.panelNodeId.
 *  - Access is scoped by internal SQUAD membership, not a per-user inbound tag
 *    list; we map the (required) allow-list to configured squad UUIDs.
 *  - User credentials the middleware generates are honoured by passing
 *    vlessUuid / trojanPassword / ssPassword on create (keeps zero-trust: the
 *    middleware, not the panel, owns the secret material).
 */
@Injectable()
export class RemnawavePanelClient implements IPanelClient {
  private readonly log = new Logger(RemnawavePanelClient.name);
  private readonly cfg: RemnawaveConfig;
  private readonly apiBase: string; // normalised `<origin>/api`

  // @Optional so Nest injects nothing (param exists for tests); config from env.
  constructor(@Optional() cfg?: Partial<RemnawaveConfig>) {
    const rawSquads = cfg?.squadUuids ?? splitCsv(process.env.REMNAWAVE_SQUAD_UUIDS);
    this.cfg = {
      baseUrl: cfg?.baseUrl ?? process.env.REMNAWAVE_BASE_URL ?? '',
      token: cfg?.token ?? process.env.REMNAWAVE_TOKEN ?? '',
      caddyToken: cfg?.caddyToken ?? process.env.REMNAWAVE_CADDY_TOKEN,
      squadUuids: rawSquads,
      requestTimeoutMs: cfg?.requestTimeoutMs ?? Number(process.env.PANEL_TIMEOUT_MS ?? 8_000),
    };
    if (!this.cfg.baseUrl) throw new Error('REMNAWAVE_BASE_URL is required');
    if (!this.cfg.token) throw new Error('REMNAWAVE_TOKEN is required');
    // Mirror the SDK: strip trailing slash, ensure exactly one `/api` suffix.
    const origin = this.cfg.baseUrl.replace(/\/+$/, '');
    this.apiBase = origin.endsWith('/api') ? origin : `${origin}/api`;
  }

  // ---- transport ----------------------------------------------------------

  private headers(hasBody: boolean): Record<string, string> {
    const h: Record<string, string> = {
      authorization: this.cfg.token.startsWith('Bearer ')
        ? this.cfg.token
        : `Bearer ${this.cfg.token}`,
    };
    if (hasBody) h['content-type'] = 'application/json';
    if (this.cfg.caddyToken) h['x-api-key'] = this.cfg.caddyToken;
    // The panel rejects plain-http origins unless told it is proxied as https.
    if (this.apiBase.startsWith('http://')) {
      h['x-forwarded-proto'] = 'https';
      h['x-forwarded-for'] = '127.0.0.1';
    }
    return h;
  }

  /**
   * Authenticated JSON request. Returns the UNWRAPPED `response` payload.
   * 404 → undefined (so callers can treat "missing" as null without throwing).
   */
  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetchWithTimeout(
      `${this.apiBase}${path}`,
      {
        method,
        headers: this.headers(body !== undefined),
        body: body !== undefined ? JSON.stringify(body) : undefined,
      },
      this.cfg.requestTimeoutMs,
    );

    if (res.status === 404) return undefined as unknown as T;
    if (res.status === 204) return undefined as unknown as T;
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new PanelError(
        `remnawave ${method} ${path} -> ${res.status}: ${text.slice(0, 300)}`,
        res.status,
        res.status >= 500 || res.status === 429,
      );
    }
    const json = (await res.json().catch(() => ({}))) as { response?: T } | T;
    // Remnawave wraps everything in { response: ... }; unwrap when present.
    return (json && typeof json === 'object' && 'response' in (json as object)
      ? (json as { response: T }).response
      : (json as T));
  }

  // ---- mapping ------------------------------------------------------------

  private toPanelUser(dto: RemnawaveUserDto): PanelUser {
    const statusMap: Record<string, PanelUserStatus> = {
      ACTIVE: 'active',
      DISABLED: 'disabled',
      LIMITED: 'limited',
      EXPIRED: 'expired',
    };
    return {
      username: dto.username,
      expireAt: dto.expireAt ? new Date(dto.expireAt) : null,
      dataLimitBytes: dto.trafficLimitBytes ? dto.trafficLimitBytes : null,
      status: statusMap[dto.status] ?? 'active',
      usedTrafficBytes: Math.round(dto.userTraffic?.usedTrafficBytes ?? 0),
      subscriptionToken: dto.subscriptionUrl,
    };
  }

  // ---- IPanelClient -------------------------------------------------------

  async createUser(params: CreateUserParams): Promise<PanelUser> {
    if (this.cfg.squadUuids.length === 0) {
      // Fail-closed, same intent as Rebecca's empty-inbounds guard: with no
      // squad the user would have no scoped access (or, worse, a default one).
      throw new PanelError(
        'refusing to create user: REMNAWAVE_SQUAD_UUIDS is empty (no access scope)',
        undefined,
        false,
      );
    }

    const vless = params.proxies.vless ?? params.proxies.vmess;
    const trojan = params.proxies.trojan;
    const ss = params.proxies.shadowsocks ?? params.proxies.ss;

    const payload: Record<string, unknown> = {
      username: params.username,
      status: 'ACTIVE',
      expireAt: params.expireAt.toISOString(),
      trafficLimitBytes: params.dataLimitBytes ?? 0,
      trafficLimitStrategy: 'NO_RESET',
      activeInternalSquads: this.cfg.squadUuids,
    };
    // Pass middleware-owned credentials so the panel honours OUR secret material.
    if (vless?.id) payload.vlessUuid = vless.id;
    if (trojan?.password) payload.trojanPassword = trojan.password;
    if (ss?.password) payload.ssPassword = ss.password;

    const created = await this.request<RemnawaveUserDto>('POST', '/users', payload);
    if (!created) throw new PanelError('remnawave createUser returned no body', undefined, false);
    const user = this.toPanelUser(created);
    this.assertExpiryRoundTrip(user, params.expireAt, 'createUser');
    return user;
  }

  async setUserExpiry(username: string, expireAt: Date): Promise<PanelUser> {
    // Remnawave's PATCH /users REJECTS a past expireAt (contract refine
    // "Expiration date cannot be in the past") with a non-retryable 400 — unlike
    // Marzban, which accepts it as immediate expiry. If a delayed outbox retry
    // carries an instant that has since elapsed, treat it as a no-op: the panel
    // enforces expiry on its own clock and our DB is authoritative, so returning
    // current state keeps the op idempotent instead of letting it die. (We also
    // skip re-activation here, which is correct for an already-elapsed expiry.)
    if (expireAt.getTime() <= Date.now() + EXPIRE_DRIFT_TOLERANCE_MS) {
      this.log.warn(
        `setUserExpiry: target ${expireAt.toISOString()} for ${username} is in the past; ` +
          `no-op (panel enforces expiry on its own clock)`,
      );
      const current = await this.getUser(username);
      if (!current) throw new PanelError(`user ${username} vanished during past-expiry no-op`);
      return current;
    }
    // PATCH /users accepts username (uuid optional). Re-activate on extend so a
    // re-grant after a lapse flips EXPIRED/DISABLED back to ACTIVE atomically.
    const updated = await this.request<RemnawaveUserDto>('PATCH', '/users', {
      username,
      status: 'ACTIVE',
      expireAt: expireAt.toISOString(),
    });
    if (!updated) throw new PanelError(`user ${username} vanished after expiry update`);
    const user = this.toPanelUser(updated);
    this.assertExpiryRoundTrip(user, expireAt, 'setUserExpiry');
    return user;
  }

  async getUser(username: string): Promise<PanelUser | null> {
    const dto = await this.request<RemnawaveUserDto | undefined>(
      'GET',
      `/users/by-username/${encodeURIComponent(username)}`,
    );
    return dto ? this.toPanelUser(dto) : null;
  }

  async disableUser(username: string): Promise<void> {
    // Status flip via PATCH-by-username — no uuid lookup needed for the fast path.
    await this.request('PATCH', '/users', { username, status: 'DISABLED' });
  }

  async deleteUser(username: string): Promise<void> {
    // Delete is by UUID only; resolve it first. Already-gone → idempotent no-op.
    const dto = await this.request<RemnawaveUserDto | undefined>(
      'GET',
      `/users/by-username/${encodeURIComponent(username)}`,
    );
    if (!dto?.uuid) return;
    await this.request('DELETE', `/users/${encodeURIComponent(dto.uuid)}`);
  }

  async getUserUsage(username: string, _start?: Date, _end?: Date): Promise<number> {
    // The user object carries cumulative usedTrafficBytes — enough for the
    // reaper/heartbeat reconciliation the interface needs. (Range-scoped usage
    // would use /bandwidth-stats/user/{uuid}; not required by callers today.)
    const dto = await this.request<RemnawaveUserDto | undefined>(
      'GET',
      `/users/by-username/${encodeURIComponent(username)}`,
    );
    return Math.round(dto?.userTraffic?.usedTrafficBytes ?? 0);
  }

  async listNodes(): Promise<PanelNode[]> {
    const nodes = await this.request<RemnawaveNodeDto[]>('GET', '/nodes');
    return (nodes ?? []).map((n) => ({
      panelNodeId: n.uuid,
      name: n.name,
      address: n.address,
      // Collapse Remnawave's three booleans into a word the sync worker's
      // isOnline() regex understands ("connected" → online; "disabled"/
      // "disconnected"/"connecting" → not online).
      status: n.isDisabled
        ? 'disabled'
        : n.isConnected
          ? 'connected'
          : n.isConnecting
            ? 'connecting'
            : 'disconnected',
    }));
  }

  private assertExpiryRoundTrip(user: PanelUser, sent: Date, op: string): void {
    const got = user.expireAt?.getTime();
    if (got === undefined || Math.abs(got - sent.getTime()) > EXPIRE_DRIFT_TOLERANCE_MS) {
      throw new PanelError(
        `${op}: expire round-trip mismatch (sent ${sent.toISOString()}, ` +
          `panel stored ${user.expireAt?.toISOString() ?? 'null'})`,
        undefined,
        false,
      );
    }
  }
}

/** Split a comma/space-separated env list into trimmed non-empty tokens. */
function splitCsv(v?: string): string[] {
  return (v ?? '')
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}
