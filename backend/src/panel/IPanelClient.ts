import { CreateUserParams, PanelNode, PanelUser } from './panel.types';

/**
 * The middleware's only view of the Rebecca panel. Swapping to Marzneshin /
 * PasarGuard / Remnawave means a new implementation of THIS interface and
 * nothing else — the ad/session logic depends only on the abstraction.
 *
 * Every method performs network I/O against the panel and therefore MUST be
 * called with no database transaction open / no row locks held.
 */
export interface IPanelClient {
  /** Mint an ephemeral panel user (one per VPN session). */
  createUser(params: CreateUserParams): Promise<PanelUser>;

  /**
   * Set the user's ABSOLUTE expiry (the core of the time-based model).
   * Idempotent: calling with the same instant twice is a no-op on the panel.
   * Returns the panel's stored user so the caller can round-trip-validate the
   * expiry encoding (seconds-vs-ms is a silent footgun on Marzban forks).
   */
  setUserExpiry(username: string, expireAt: Date): Promise<PanelUser>;

  getUser(username: string): Promise<PanelUser | null>;

  /** Fast revoke: flip to disabled (does not guarantee instant TCP kick). */
  disableUser(username: string): Promise<void>;

  /** Reclaim: remove the ephemeral user entirely. */
  deleteUser(username: string): Promise<void>;

  /** Used-traffic bytes, for stats/heartbeat reconciliation. */
  getUserUsage(username: string, start?: Date, end?: Date): Promise<number>;

  listNodes(): Promise<PanelNode[]>;
}

/** DI token for Nest. */
export const PANEL_CLIENT = Symbol('IPanelClient');
