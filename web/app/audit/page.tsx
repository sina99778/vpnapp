'use client';

import { useCallback, useEffect, useState } from 'react';
import Nav from '../../components/Nav';
import { adminApi } from '../../lib/api';
import type { AdminActionType, AuditLogRow } from '../../lib/types';

const PAGE = 50;

// Visual cue per action — scannable at a glance.
const ACTION_STYLE: Record<AdminActionType, { label: string; cls: string }> = {
  BAN_USER: { label: 'BAN', cls: 'bg-red-900/70 text-red-200 border-red-700' },
  PANIC_FREE_SESSIONS: { label: 'PANIC', cls: 'bg-red-800 text-white border-red-500 font-bold' },
  KICK_SESSION: { label: 'KICK', cls: 'bg-amber-900/60 text-amber-200 border-amber-700' },
  UNBAN_USER: { label: 'UNBAN', cls: 'bg-emerald-900/60 text-emerald-200 border-emerald-700' },
  CHANGE_TIER: { label: 'TIER', cls: 'bg-blue-900/60 text-blue-200 border-blue-700' },
};

const FILTERS: Array<{ value?: AdminActionType; label: string }> = [
  { value: undefined, label: 'All' },
  { value: 'BAN_USER', label: 'Bans' },
  { value: 'KICK_SESSION', label: 'Kicks' },
  { value: 'PANIC_FREE_SESSIONS', label: 'Panics' },
  { value: 'CHANGE_TIER', label: 'Tier' },
];

export default function AuditPage() {
  const [logs, setLogs] = useState<AuditLogRow[]>([]);
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState<AdminActionType | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch the first page (on mount + whenever the filter changes).
  const loadFirst = useCallback(async (action?: AdminActionType) => {
    setLoading(true);
    setError(null);
    try {
      const res = await adminApi.listAudit({ actionType: action, limit: PAGE, offset: 0 });
      setLogs(res.logs);
      setTotal(res.total);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed to load audit log');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadFirst(filter);
  }, [filter, loadFirst]);

  const loadMore = async () => {
    setLoadingMore(true);
    try {
      const res = await adminApi.listAudit({ actionType: filter, limit: PAGE, offset: logs.length });
      // Append, de-duping by id in case a row shifted between pages.
      setLogs((prev) => {
        const seen = new Set(prev.map((l) => l.id));
        return [...prev, ...res.logs.filter((l) => !seen.has(l.id))];
      });
      setTotal(res.total);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed to load more');
    } finally {
      setLoadingMore(false);
    }
  };

  const hasMore = logs.length < total;

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-5xl p-6">
        <div className="mb-4 flex items-center justify-between">
          <h1 className="text-xl font-semibold text-white">
            Activity {total ? <span className="text-sm font-normal text-zinc-500">({total})</span> : null}
          </h1>
          <div className="flex gap-1">
            {FILTERS.map((f) => (
              <button
                key={f.label}
                onClick={() => setFilter(f.value)}
                className={`rounded-md px-3 py-1.5 text-xs transition ${
                  filter === f.value ? 'bg-zinc-800 text-white' : 'text-zinc-400 hover:text-white'
                }`}
              >
                {f.label}
              </button>
            ))}
            <button
              onClick={() => loadFirst(filter)}
              className="rounded-md px-3 py-1.5 text-xs text-zinc-400 hover:text-white"
              title="Refresh"
            >
              ↻
            </button>
          </div>
        </div>

        {error && (
          <div className="mb-4 rounded-md border border-red-700 bg-red-950/60 px-4 py-2 text-sm text-red-200">
            {error}
          </div>
        )}

        <ul className="space-y-2">
          {loading && <li className="py-6 text-center text-zinc-500">Loading…</li>}
          {!loading && logs.length === 0 && (
            <li className="py-6 text-center text-zinc-500">No activity.</li>
          )}
          {logs.map((log) => {
            const style = ACTION_STYLE[log.actionType];
            const tg = (log.details as { source?: string }).source === 'telegram';
            return (
              <li
                key={log.id}
                className="flex items-start gap-3 rounded-lg border border-zinc-800 bg-zinc-900/40 px-4 py-3"
              >
                <span className={`mt-0.5 rounded border px-2 py-0.5 text-[11px] font-semibold ${style.cls}`}>
                  {style.label}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-sm text-zinc-200">
                    {describe(log)}
                    {tg && (
                      <span className="ml-2 rounded bg-sky-900/60 px-1.5 py-0.5 text-[10px] text-sky-200">
                        via Telegram
                      </span>
                    )}
                  </div>
                  <div className="mt-0.5 font-mono text-[11px] text-zinc-500">
                    {log.targetId ? `target ${log.targetId.slice(0, 8)} · ` : ''}
                    {log.adminId ? `admin ${log.adminId.slice(0, 8)} · ` : ''}
                    {log.ipAddress ? `${log.ipAddress} · ` : ''}
                    {new Date(log.createdAt).toLocaleString()}
                  </div>
                </div>
              </li>
            );
          })}
        </ul>

        {hasMore && !loading && (
          <div className="mt-4 flex justify-center">
            <button
              onClick={loadMore}
              disabled={loadingMore}
              className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-200 hover:bg-zinc-800 disabled:opacity-50"
            >
              {loadingMore ? 'Loading…' : `Load more (${total - logs.length} left)`}
            </button>
          </div>
        )}
      </main>
    </>
  );
}

function describe(log: AuditLogRow): string {
  const d = log.details as { revoked?: number; revokedSessions?: number; tier?: string };
  switch (log.actionType) {
    case 'BAN_USER':
      return `Banned a user (${d.revokedSessions ?? 0} session(s) revoked)`;
    case 'UNBAN_USER':
      return 'Unbanned a user';
    case 'KICK_SESSION':
      return 'Kicked a session';
    case 'CHANGE_TIER':
      return `Changed tier → ${d.tier ?? '?'}`;
    case 'PANIC_FREE_SESSIONS':
      return `PANIC — revoked ${d.revoked ?? 0} free session(s)`;
    default:
      return log.actionType;
  }
}
