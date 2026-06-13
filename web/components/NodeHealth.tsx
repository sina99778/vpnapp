'use client';

import { useCallback, useEffect, useState } from 'react';
import { adminApi } from '../lib/api';
import type { NodeHealth as NodeHealthData, NodeInfo } from '../lib/types';

const HEALTHY = new Set(['online', 'connected', 'active', 'healthy', 'running']);

function isHealthy(status: string): boolean {
  const s = status.toLowerCase();
  return HEALTHY.has(s) || (s.includes('connect') && !s.includes('dis'));
}

export default function NodeHealth() {
  const [data, setData] = useState<NodeHealthData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      setError(null);
      setData(await adminApi.nodesHealth());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed to load node health');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 15_000);
    return () => clearInterval(t);
  }, [load]);

  return (
    <section className="mt-8">
      <div className="mb-3 flex items-center gap-3">
        <h2 className="text-lg font-semibold text-white">Nodes</h2>
        {data && !data.panelReachable && (
          <span className="rounded bg-amber-900/60 px-2 py-0.5 text-xs text-amber-200">
            panel unreachable — last-synced status
          </span>
        )}
      </div>

      {error && (
        <div className="mb-3 rounded-md border border-red-700 bg-red-950/60 px-4 py-2 text-sm text-red-200">
          {error}
        </div>
      )}

      {loading && <div className="text-sm text-zinc-500">Loading…</div>}

      {!loading && data && data.nodes.length === 0 && (
        <div className="text-sm text-zinc-500">No nodes configured.</div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {data?.nodes.map((n) => (
          <NodeCard key={n.id} node={n} onChanged={load} />
        ))}
      </div>
    </section>
  );
}

function NodeCard({ node, onChanged }: { node: NodeInfo; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [confirmEvac, setConfirmEvac] = useState(false);
  const healthy = isHealthy(node.status);
  const load = node.loadPct ?? 0;
  const loadColor = load >= 85 ? 'bg-red-500' : load >= 60 ? 'bg-amber-500' : 'bg-emerald-500';
  const draining = !node.isActive;

  const toggle = async () => {
    if (node.isActive && !confirm(`Drain "${node.name}"? Existing sessions keep running; no new users are placed here.`)) {
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await adminApi.setNodeStatus(node.id, !node.isActive);
      onChanged();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'failed');
      setBusy(false);
    }
  };

  const evacuate = async () => {
    setBusy(true);
    setErr(null);
    try {
      await adminApi.forceMigrateNode(node.id);
      setConfirmEvac(false);
      onChanged();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'evacuation failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className={`rounded-xl border p-4 ${
        draining ? 'border-amber-700/70 bg-amber-950/20' : 'border-zinc-800 bg-zinc-900/60'
      }`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span
            className={`inline-block h-2.5 w-2.5 rounded-full ${healthy ? 'bg-emerald-500' : 'bg-red-500'}`}
            title={node.status}
          />
          <span className="font-medium text-white">{node.name}</span>
          {node.countryCode && (
            <span className="text-xs text-zinc-500">{node.countryCode.toUpperCase()}</span>
          )}
        </div>
        {draining ? (
          <span className="rounded bg-amber-900/70 px-2 py-0.5 text-[11px] font-semibold text-amber-200">
            DRAINING
          </span>
        ) : (
          <span className={`text-xs ${healthy ? 'text-emerald-400' : 'text-red-400'}`}>
            {healthy ? 'online' : 'offline'}
          </span>
        )}
      </div>

      <div className="mt-3">
        <div className="mb-1 flex justify-between text-xs text-zinc-400">
          <span>Load</span>
          <span className="tabular-nums">{node.loadPct === null ? '—' : `${node.loadPct}%`}</span>
        </div>
        <div className="h-2 w-full overflow-hidden rounded-full bg-zinc-800">
          <div className={`h-full rounded-full ${loadColor}`} style={{ width: `${Math.min(load, 100)}%` }} />
        </div>
      </div>

      <div className="mt-3 flex items-center justify-between gap-2">
        <span className="text-xs text-zinc-400">
          Connections:{' '}
          <span className="font-semibold text-zinc-200 tabular-nums">{node.activeConnections}</span>
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={toggle}
            disabled={busy}
            className={`rounded-md px-3 py-1 text-xs font-semibold transition disabled:opacity-50 ${
              draining
                ? 'bg-emerald-700 text-white hover:bg-emerald-600'
                : 'border border-amber-700 text-amber-300 hover:bg-amber-900/40'
            }`}
          >
            {busy ? '…' : draining ? 'Enable' : 'Drain'}
          </button>
          <button
            onClick={() => {
              setErr(null);
              setConfirmEvac(true);
            }}
            disabled={busy}
            title="Drain and instantly disconnect all active users on this node"
            className="rounded-md bg-red-700 px-3 py-1 text-xs font-semibold text-white transition hover:bg-red-600 disabled:opacity-50"
          >
            Evacuate
          </button>
        </div>
      </div>

      {err && <div className="mt-2 text-xs text-red-400">{err}</div>}

      {confirmEvac && (
        <EvacuateDialog
          nodeName={node.name}
          connections={node.activeConnections}
          busy={busy}
          onCancel={() => setConfirmEvac(false)}
          onConfirm={evacuate}
        />
      )}
    </div>
  );
}

/**
 * Blocking confirmation for the irreversible Force-Migrate. Renders a modal (not
 * a window.confirm) so the strict warning is unmissable and the destructive
 * button is visually distinct from Cancel.
 */
function EvacuateDialog({
  nodeName,
  connections,
  busy,
  onCancel,
  onConfirm,
}: {
  nodeName: string;
  connections: number;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="evac-title"
      onClick={busy ? undefined : onCancel}
    >
      <div
        className="w-full max-w-md rounded-xl border border-red-800 bg-zinc-950 p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2">
          <span className="text-lg">⚠️</span>
          <h3 id="evac-title" className="text-base font-semibold text-red-300">
            Evacuate “{nodeName}”?
          </h3>
        </div>

        <p className="mt-3 text-sm leading-relaxed text-zinc-300">
          This will instantly disconnect all active users on this node and force them to reconnect to
          other servers. This action is audited and irreversible.
        </p>

        {connections > 0 && (
          <p className="mt-2 text-sm font-medium text-amber-300">
            {connections} active connection{connections === 1 ? '' : 's'} will be dropped immediately.
          </p>
        )}

        <div className="mt-5 flex justify-end gap-2">
          <button
            onClick={onCancel}
            disabled={busy}
            className="rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 transition hover:bg-zinc-800 disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={busy}
            className="rounded-md bg-red-700 px-3 py-1.5 text-sm font-semibold text-white transition hover:bg-red-600 disabled:opacity-60"
          >
            {busy ? 'Evacuating…' : 'Evacuate node'}
          </button>
        </div>
      </div>
    </div>
  );
}
