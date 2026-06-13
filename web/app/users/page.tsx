'use client';

import { useCallback, useEffect, useState } from 'react';
import Nav from '../../components/Nav';
import { adminApi } from '../../lib/api';
import type { AdminUserRow } from '../../lib/types';

export default function UsersPage() {
  const [search, setSearch] = useState('');
  const [rows, setRows] = useState<AdminUserRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<AdminUserRow | null>(null);

  const load = useCallback(async (q: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await adminApi.listUsers({ search: q || undefined, limit: 50 });
      setRows(res.users);
      setTotal(res.total);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed to load users');
    } finally {
      setLoading(false);
    }
  }, []);

  // Debounced search.
  useEffect(() => {
    const t = setTimeout(() => load(search), 300);
    return () => clearTimeout(t);
  }, [search, load]);

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-6xl p-6">
        <div className="mb-4 flex items-center justify-between">
          <h1 className="text-xl font-semibold text-white">Users {total ? `(${total})` : ''}</h1>
          <input
            placeholder="Search by email…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-72 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-white outline-none focus:border-emerald-600"
          />
        </div>

        {error && (
          <div className="mb-4 rounded-md border border-red-700 bg-red-950/60 px-4 py-2 text-sm text-red-200">
            {error}
          </div>
        )}

        <div className="overflow-hidden rounded-xl border border-zinc-800">
          <table className="w-full text-left text-sm">
            <thead className="bg-zinc-900/80 text-xs uppercase tracking-wide text-zinc-400">
              <tr>
                <th className="px-4 py-3">Email</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Active sessions</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {loading && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-zinc-500">
                    Loading…
                  </td>
                </tr>
              )}
              {!loading && rows.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-zinc-500">
                    No users.
                  </td>
                </tr>
              )}
              {rows.map((u) => (
                <tr key={u.id} className="hover:bg-zinc-900/40">
                  <td className="px-4 py-3 text-white">
                    {u.email ?? <span className="italic text-zinc-500">anonymous</span>}
                  </td>
                  <td className="px-4 py-3">
                    {u.role === 'admin' ? (
                      <span className="rounded bg-purple-900/60 px-2 py-0.5 text-xs text-purple-200">admin</span>
                    ) : (
                      <span className="text-zinc-400">user</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {u.isBanned ? (
                      <span className="rounded bg-red-900/60 px-2 py-0.5 text-xs text-red-200">banned</span>
                    ) : (
                      <span className="text-emerald-400">active</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {u.activeSessions.length === 0 ? (
                      <span className="text-zinc-600">—</span>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {u.activeSessions.map((s) => (
                          <span
                            key={s.id}
                            title={`${s.tier} · ${s.status}`}
                            className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[11px] text-zinc-300"
                          >
                            {s.id.slice(0, 8)}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => setEditing(u)}
                      className="rounded-md border border-zinc-700 px-3 py-1 text-xs text-zinc-200 hover:bg-zinc-800"
                    >
                      Manage
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>

      {editing && (
        <ManageModal
          user={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            load(search);
          }}
        />
      )}
    </>
  );
}

function ManageModal({
  user,
  onClose,
  onSaved,
}: {
  user: AdminUserRow;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async (changes: { tier?: 'free' | 'premium'; isBanned?: boolean }) => {
    setBusy(true);
    setError(null);
    try {
      await adminApi.mutateUser(user.id, changes);
      onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'action failed');
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="w-full max-w-md rounded-2xl border border-zinc-800 bg-zinc-900 p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-1 text-lg font-semibold text-white">Manage user</h2>
        <p className="mb-4 truncate text-sm text-zinc-400">{user.email ?? user.id}</p>

        {error && (
          <div className="mb-3 rounded-md border border-red-700 bg-red-950/60 px-3 py-2 text-sm text-red-200">
            {error}
          </div>
        )}

        <div className="space-y-3">
          <div className="flex items-center justify-between rounded-lg border border-zinc-800 px-3 py-2">
            <span className="text-sm text-zinc-300">Ban status</span>
            {user.isBanned ? (
              <button
                disabled={busy}
                onClick={() => run({ isBanned: false })}
                className="rounded-md bg-emerald-700 px-3 py-1 text-xs font-semibold text-white hover:bg-emerald-600 disabled:opacity-50"
              >
                Unban
              </button>
            ) : (
              <button
                disabled={busy}
                onClick={() => {
                  if (confirm('Ban this user? All their active sessions are revoked immediately.')) {
                    run({ isBanned: true });
                  }
                }}
                className="rounded-md bg-red-700 px-3 py-1 text-xs font-semibold text-white hover:bg-red-600 disabled:opacity-50"
              >
                Ban
              </button>
            )}
          </div>

          <div className="flex items-center justify-between rounded-lg border border-zinc-800 px-3 py-2">
            <span className="text-sm text-zinc-300">Tier (promo grant)</span>
            <div className="flex gap-2">
              <button
                disabled={busy}
                onClick={() => run({ tier: 'premium' })}
                className="rounded-md bg-amber-600 px-3 py-1 text-xs font-semibold text-white hover:bg-amber-500 disabled:opacity-50"
              >
                Grant premium
              </button>
              <button
                disabled={busy}
                onClick={() => run({ tier: 'free' })}
                className="rounded-md border border-zinc-700 px-3 py-1 text-xs text-zinc-200 hover:bg-zinc-800 disabled:opacity-50"
              >
                Revoke
              </button>
            </div>
          </div>
        </div>

        <div className="mt-6 flex justify-end">
          <button onClick={onClose} className="rounded-md px-3 py-1.5 text-sm text-zinc-400 hover:text-white">
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
