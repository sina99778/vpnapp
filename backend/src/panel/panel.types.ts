/** Shared types for the panel abstraction (Rebecca / any Marzban-family panel). */

export type PanelUserStatus = 'active' | 'disabled' | 'limited' | 'expired' | 'on_hold';

export interface ProxyCredential {
  /** VLESS/VMess UUID. */ id?: string;
  /** Trojan/Shadowsocks password. */ password?: string;
  flow?: string;
}

export interface CreateUserParams {
  username: string;
  /** Absolute expiry. The panel enforces the drop when this passes. */
  expireAt: Date;
  /** Time-gated model → usually unlimited. Omit/0 = unlimited. */
  dataLimitBytes?: number;
  /** protocol -> credential. e.g. { vless: { id, flow } }. */
  proxies: Record<string, ProxyCredential>;
  /**
   * protocol -> inbound tag allow-list. MUST be non-empty and tier-scoped.
   * An empty/missing allow-list makes the panel grant ALL inbounds.
   */
  inboundsByProtocol: Record<string, string[]>;
}

export interface PanelUser {
  username: string;
  /** null = no expiry set on the panel (unlimited). */
  expireAt: Date | null;
  dataLimitBytes: number | null;
  status: PanelUserStatus;
  usedTrafficBytes: number;
  subscriptionToken?: string;
}

export interface PanelNode {
  /** Panel-side node id as text — Rebecca integer (stringified) or Remnawave UUID. */
  panelNodeId: string;
  name: string;
  status: string;
  address?: string;
}

/** Typed error so callers can distinguish panel failures from our own bugs. */
export class PanelError extends Error {
  constructor(message: string, readonly status?: number, readonly retryable = true) {
    super(message);
    this.name = 'PanelError';
  }
}
