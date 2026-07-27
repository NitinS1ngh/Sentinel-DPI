import { useMemo, useState } from 'react';
import SectionCard from '../components/SectionCard';
import EmptyState from '../components/EmptyState';
import StatusPill from '../components/StatusPill';
import DataTable, { TimestampValue, MonospacedValue } from '../components/DataTable';
import { formatNumber, formatTime } from '../lib/format';

async function sendFirewallAction(method, domain) {
  const endpoint = method === 'delete' ? '/api/firewall/rule' : `/api/firewall/${method}`;
  const response = await fetch(`${endpoint}?domain=${encodeURIComponent(domain)}`, {
    method: method === 'delete' ? 'DELETE' : 'POST',
    headers: { Accept: 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Firewall request failed with status ${response.status}`);
  }
  return response.json();
}

export default function FirewallPage({ firewallStatus = null, firewallRules = [], firewallActions = [], latestFirewallAction = null }) {
  const [domain, setDomain] = useState('');

  const blockedActions = useMemo(() => firewallActions.filter((action) => action.action === 'BLOCK'), [firewallActions]);

  const columns = [
    { key: 'timestamp', label: 'Time', sortable: true, render: (row) => <TimestampValue value={row.timestamp} /> },
    { key: 'domain', label: 'Domain', sortable: true, render: (row) => <span className="font-medium text-slate-900">{row.domain}</span> },
    { key: 'action', label: 'Action', sortable: true, render: (row) => <StatusPill tone={row.action === 'BLOCK' ? 'danger' : 'info'}>{row.action}</StatusPill> },
    { key: 'backend', label: 'Backend', sortable: true, render: (row) => <span className="text-slate-600">{row.backend}</span> },
    { key: 'status', label: 'Status', sortable: true, render: (row) => <StatusPill tone={row.status === 'FAILED' ? 'danger' : 'success'}>{row.status}</StatusPill> },
    { key: 'reason', label: 'Reason', sortable: true, render: (row) => <span className="text-slate-600">{row.reason || 'Policy action'}</span> },
  ];

  const backendLabel = firewallStatus?.backend || 'Mock';
  const healthLabel = firewallStatus?.health || 'Healthy';
  const activeRules = firewallStatus?.active_rules ?? firewallRules.length;

  async function handleSubmit(action) {
    if (!domain.trim()) {
      return;
    }

    await sendFirewallAction(action, domain.trim());
    setDomain('');
  }

  async function handleClearAll() {
    const response = await fetch('/api/firewall/clear', {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      throw new Error(`Clear request failed with status ${response.status}`);
    }
  }

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Firewall Status</div>
          <div className="mt-1 flex items-center gap-2 text-lg font-semibold tracking-tight text-slate-900">
            <StatusPill tone={healthLabel === 'Healthy' ? 'success' : 'danger'}>{healthLabel}</StatusPill>
          </div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Backend</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900">{backendLabel}</div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Active Rules</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900">{formatNumber(activeRules)}</div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Recently Blocked</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900">{formatNumber(blockedActions.length)}</div>
        </section>
      </div>

      <SectionCard
        title="Live Firewall Action"
        description="Immediate enforcement events appear here as soon as a domain is blocked or unblocked."
        action={<StatusPill tone={latestFirewallAction ? 'success' : 'neutral'}>{latestFirewallAction ? latestFirewallAction.action : 'Idle'}</StatusPill>}
      >
        {latestFirewallAction ? (
          <div className="grid gap-4 md:grid-cols-[1.2fr_1fr]">
            <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4">
              <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">🚫 Firewall Action</div>
              <div className="mt-2 text-2xl font-semibold tracking-tight text-slate-900">{latestFirewallAction.domain}</div>
              <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-slate-600">
                <StatusPill tone={latestFirewallAction.action === 'BLOCK' ? 'danger' : 'info'}>{latestFirewallAction.action}</StatusPill>
                <span>{latestFirewallAction.backend}</span>
                <span>{latestFirewallAction.status}</span>
                <span>{formatTime(latestFirewallAction.timestamp)}</span>
              </div>
            </div>
            <div className="grid gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-4 text-sm text-slate-600">
              <div className="flex items-center justify-between gap-4"><span>Backend</span><MonospacedValue value={latestFirewallAction.backend || '-'} /></div>
              <div className="flex items-center justify-between gap-4"><span>Status</span><StatusPill tone={latestFirewallAction.status === 'FAILED' ? 'danger' : 'success'}>{latestFirewallAction.status || 'UNKNOWN'}</StatusPill></div>
              <div className="flex items-center justify-between gap-4"><span>Reason</span><span className="text-right font-medium text-slate-900">{latestFirewallAction.reason || 'Policy action'}</span></div>
            </div>
          </div>
        ) : (
          <EmptyState title="No firewall activity yet" description="Block a domain or trigger a policy match to see live enforcement updates." />
        )}
      </SectionCard>

      <SectionCard title="Firewall Controls" description="Use mock or pf mode without changing the policy engine.">
        <div className="flex flex-col gap-3 md:flex-row md:items-center justify-between">
          <div className="flex flex-1 flex-col gap-3 md:flex-row md:items-center">
            <input
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              placeholder="example.com"
              className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-2.5 text-sm text-slate-900 outline-none transition focus:border-brand-300 focus:ring-4 focus:ring-brand-100 md:max-w-md"
            />
            <div className="flex gap-2">
              <button onClick={() => handleSubmit('block')} className="rounded-full bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 transition-colors">Block</button>
              <button onClick={() => handleSubmit('unblock')} className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-colors">Unblock</button>
              <button onClick={() => handleSubmit('delete')} className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-colors">Remove Rule</button>
            </div>
          </div>
          <button onClick={handleClearAll} className="rounded-full border border-red-200 bg-red-50 px-4 py-2 text-sm font-medium text-red-700 hover:bg-red-100 transition-colors">Clear Active Rules & DB Logs</button>
        </div>
      </SectionCard>

      <div className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
        <SectionCard title="Active Rules" description="Current blocked domains returned by the configured firewall backend.">
          {firewallRules.length ? (
            <div className="overflow-y-auto pr-1" style={{ maxHeight: '370px' }}>
              <div className="space-y-2">
                {firewallRules.map((rule) => (
                  <div key={rule} className="flex items-center justify-between rounded-xl border border-slate-200 bg-white px-4 py-3">
                    <span className="font-medium text-slate-900">{rule}</span>
                    <StatusPill tone="danger">Blocked</StatusPill>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <EmptyState title="No active firewall rules" description="Add a rule from the control panel or wait for a policy match to create one." />
          )}
        </SectionCard>

        <SectionCard title="Firewall Actions" description="Recent enforcement operations stored in SQLite.">
          <DataTable
            columns={columns}
            rows={firewallActions}
            initialSortKey="timestamp"
            maxTableHeight="370px"
            emptyState={<EmptyState title="No firewall actions yet" description="Firewall actions will appear here as they are applied." />}
          />
        </SectionCard>
      </div>
    </div>
  );
}