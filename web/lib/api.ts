import axios, { AxiosInstance, InternalAxiosRequestConfig } from 'axios';
import type { AdminActionType, AdminStats, AdminUserRow, AuditLogRow, NodeHealth } from './types';

const TOKEN_KEY = 'admin.accessToken';

/**
 * Where the admin JWT lives. Centralised so swapping localStorage → an httpOnly
 * cookie (read via a BFF) is a one-place change. (See README security note.)
 */
const REFRESH_KEY = 'admin.refreshToken';

export const tokenStore = {
  get: (): string | null => (typeof window === 'undefined' ? null : localStorage.getItem(TOKEN_KEY)),
  set: (t: string) => localStorage.setItem(TOKEN_KEY, t),
  getRefresh: (): string | null =>
    typeof window === 'undefined' ? null : localStorage.getItem(REFRESH_KEY),
  setRefresh: (t: string) => localStorage.setItem(REFRESH_KEY, t),
  clear: () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
  },
};

const baseURL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:3000/api/v1';

/** Bounce to /login (browser-only, never when already there). */
function toLogin(): void {
  tokenStore.clear();
  if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
    window.location.href = '/login';
  }
}

/** Requests whose own 401 must NOT trigger a refresh attempt (they ARE auth). */
function isAuthEndpoint(url?: string): boolean {
  return !!url && (url.includes('/auth/refresh') || url.includes('/auth/login'));
}

// ── Concurrency-safe refresh mutex ─────────────────────────────────────────
// A single in-flight refresh promise shared by ALL requests that 401 at once:
// the first creates it, the rest await the same one, then everyone replays with
// the new token. Exactly one POST /auth/refresh ever fires per wave.
let refreshPromise: Promise<string> | null = null;

/** Refresh via a BARE axios (no interceptors) so it can't recurse. */
async function performRefresh(): Promise<string> {
  const refresh = tokenStore.getRefresh();
  if (!refresh) throw new Error('no refresh token');
  const { data } = await axios.post<{ accessToken: string; refreshToken: string }>(
    `${baseURL}/auth/refresh`,
    { refreshToken: refresh },
    { timeout: 15_000 },
  );
  tokenStore.set(data.accessToken);
  tokenStore.setRefresh(data.refreshToken);
  return data.accessToken;
}

function refreshOnce(): Promise<string> {
  if (!refreshPromise) {
    refreshPromise = performRefresh().finally(() => {
      // Clear so the NEXT 401 wave (after this token also expires) can refresh.
      refreshPromise = null;
    });
  }
  return refreshPromise;
}

type RetriableConfig = InternalAxiosRequestConfig & { _retry?: boolean };

function createClient(): AxiosInstance {
  const client = axios.create({ baseURL, timeout: 15_000 });

  // Inject the current admin JWT on every request (incl. replays, which re-run
  // this interceptor and therefore automatically pick up the refreshed token).
  client.interceptors.request.use((config) => {
    const token = tokenStore.get();
    if (token) config.headers.Authorization = `Bearer ${token}`;
    return config;
  });

  client.interceptors.response.use(
    (r) => r,
    async (error) => {
      const status = error?.response?.status;
      const original = error?.config as RetriableConfig | undefined;

      // 403 = authenticated but not authorized (e.g. demoted/banned admin).
      // Refreshing won't help — sign out.
      if (status === 403) {
        toLogin();
        return Promise.reject(error);
      }

      // 401 → try ONE refresh, unless this request already retried or it IS an
      // auth call (a failing /auth/refresh means the family is gone).
      if (status === 401 && original && !original._retry && !isAuthEndpoint(original.url)) {
        original._retry = true;
        try {
          await refreshOnce(); // shared across the whole 401 wave
          return client(original); // replay; request interceptor attaches new token
        } catch {
          toLogin(); // refresh failed → token family revoked/expired
          return Promise.reject(error);
        }
      }

      if (status === 401) {
        // Already retried, or an auth endpoint itself 401'd → give up cleanly.
        toLogin();
      }
      return Promise.reject(error);
    },
  );

  return client;
}

const http = createClient();

/** Typed admin API surface. */
export const adminApi = {
  stats: () => http.get<AdminStats>('/admin/stats').then((r) => r.data),

  listUsers: (params: { search?: string; limit?: number; offset?: number }) =>
    http.get<{ total: number; users: AdminUserRow[] }>('/admin/users', { params }).then((r) => r.data),

  mutateUser: (id: string, changes: { tier?: 'free' | 'premium'; isBanned?: boolean }) =>
    http.post(`/admin/users/${id}/mutate`, changes).then((r) => r.data),

  kickSession: (id: string) => http.post(`/admin/sessions/${id}/kick`).then((r) => r.data),

  nodesHealth: () => http.get<NodeHealth>('/admin/nodes/health').then((r) => r.data),

  /** Drain (isActive=false) or enable (true) a node — no new sessions placed when draining. */
  setNodeStatus: (id: string, isActive: boolean) =>
    http.patch(`/admin/nodes/${id}/status`, { isActive }).then((r) => r.data),

  /** Emergency: drain a node AND instantly evict every live session on it. */
  forceMigrateNode: (id: string) =>
    http
      .post<{ ok: true; evicted: number }>(`/admin/nodes/${id}/migrate`)
      .then((r) => r.data),

  /** Emergency: revoke every free-tier live session. */
  panicRevokeFree: () =>
    http
      .post<{ ok: true; revoked: number }>('/admin/panic/revoke-free-sessions')
      .then((r) => r.data),

  listAudit: (params: { actionType?: AdminActionType; adminId?: string; limit?: number; offset?: number }) =>
    http.get<{ total: number; logs: AuditLogRow[] }>('/admin/audit', { params }).then((r) => r.data),
};

/**
 * Sign in via the DEDICATED device-less admin endpoint, which itself asserts
 * role==='admin' (and not banned) server-side — no fake device, no separate
 * verify call. A non-admin gets a 403 the interceptor surfaces as an error.
 */
export async function loginAsAdmin(email: string, password: string): Promise<void> {
  try {
    const { data } = await http.post<{ accessToken: string; refreshToken: string }>(
      '/admin/auth/login',
      { email, password },
    );
    tokenStore.set(data.accessToken);
    tokenStore.setRefresh(data.refreshToken);
  } catch (e) {
    const status = (e as { response?: { status?: number } }).response?.status;
    if (status === 403) throw new Error('This account is not an administrator.');
    if (status === 401) throw new Error('Invalid email or password.');
    throw new Error('Login failed. Please try again.');
  }
}
