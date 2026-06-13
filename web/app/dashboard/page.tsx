'use client';

import { useCallback, useEffect, useState } from 'react';
import Nav from '../../components/Nav';
import NodeHealth from '../../components/NodeHealth';
import { adminApi } from '../../lib/api';
import type { AdminStats } from '../../lib/types';

export default function DashboardPage() {
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      setError(null);
      setStats(await adminApi.stats());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed to load stats');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 15_000); // live refresh
    return () => clearInterval(t);
  }, [load]);

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-5xl p-6">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-white">Command Center</h1>
        <PanicButton onDone={load} />
      </div>

      {error && (
        <div className="mb-4 rounded-md border border-red-700 bg-red-950/60 px-4 py-2 text-sm text-red-200">
          {error}
        </div>
      )}

      <section className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Active sessions" value={stats?.activeSessions} loading={loading} />
        <StatCard label="Ads watched today" value={stats?.adsWatchedToday} loading={loading} />
        <StatCard label="Total users" value={stats?.totalUsers} loading={loading} />
        <StatCard label="Premium users" value={stats?.premiumUsers} loading={loading} accent />
      </section>

      <NodeHealth />
      </main>
    </>
  );
}

function StatCard({
  label,
  value,
  loading,
  accent,
}: {
  label: string;
  value?: number;
  loading: boolean;
  accent?: boolean;
}) {
  return (
    <div
      className={`rounded-xl border p-5 ${
        accent ? 'border-emerald-700 bg-emerald-950/40' : 'border-zinc-800 bg-zinc-900/60'
      }`}
    >
      <div className="text-xs uppercase tracking-wide text-zinc-400">{label}</div>
      <div className="mt-2 text-3xl font-bold text-white tabular-nums">
        {loading || value === undefined ? '—' : value.toLocaleString()}
      </div>
    </div>
  );
}

/**
 * Emergency control: revokes ALL free-tier live sessions. Double-confirmed
 * (typed phrase) because it disconnects every free user at once.
 */
function PanicButton({ onDone }: { onDone: () => void }) {
  const [busy, setBusy] = useState(false);

  const onClick = async () => {
    const phrase = window.prompt(
      'This revokes EVERY free-tier session immediately.\nType REVOKE FREE to confirm:',
    );
    if (phrase !== 'REVOKE FREE') return;
    setBusy(true);
    try {
      const res = await adminApi.panicRevokeFree();
      window.alert(`Revoked ${res.revoked} free session(s). The panel converges via the outbox.`);
      onDone();
    } catch (e) {
      window.alert(`Panic failed: ${e instanceof Error ? e.message : 'unknown error'}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <button
      onClick={onClick}
      disabled={busy}
      className="rounded-lg border border-red-600 bg-red-700 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-red-600 disabled:opacity-50"
    >
      {busy ? 'Revoking…' : '🛑 Panic: revoke free sessions'}
    </button>
  );
}
