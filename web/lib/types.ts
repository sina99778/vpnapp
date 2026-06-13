// Mirrors the backend admin DTOs (backend/src/admin/admin.service.ts).

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

export interface NodeInfo {
  id: string;
  name: string;
  status: string;
  isActive: boolean;
  loadPct: number | null;
  activeConnections: number;
  countryCode?: string;
}
export interface NodeHealth {
  panelReachable: boolean;
  nodes: NodeInfo[];
}

export type AdminActionType =
  | 'KICK_SESSION'
  | 'BAN_USER'
  | 'UNBAN_USER'
  | 'CHANGE_TIER'
  | 'PANIC_FREE_SESSIONS';

export interface AuditLogRow {
  id: string;
  adminId: string | null;
  actionType: AdminActionType;
  targetId: string | null;
  details: Record<string, unknown>;
  ipAddress: string | null;
  createdAt: string;
}
