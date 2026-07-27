import { useMemo, useState, useEffect } from 'react';
import SectionCard from '../components/SectionCard';
import EmptyState from '../components/EmptyState';
import StatusPill from '../components/StatusPill';
import DataTable, { TimestampValue, MonospacedValue, NumericValue } from '../components/DataTable';
import { formatTime } from '../lib/format';
import { summarizeBlockedEvents } from '../lib/metrics';

export default function BlockedEventsPage({ blockedEvents = [], blockStats = null, blockedDomains = [], latestBlockedEvent = null }) {
  const blockSummary = useMemo(() => summarizeBlockedEvents(blockedEvents), [blockedEvents]);
  const blockedToday = blockSummary.blockedToday;
  const blockedDns = blockSummary.blockedDns;
  const blockedTls = blockSummary.blockedTls;
  const mostBlockedDomain = blockSummary.mostBlockedDomains[0]?.domain || blockStats?.most_blocked_domains?.[0]?.domain || blockedDomains[0] || '—';

  const [activeAlert, setActiveAlert] = useState(latestBlockedEvent);

  useEffect(() => {
    setActiveAlert(latestBlockedEvent);

    if (latestBlockedEvent) {
      const timer = setTimeout(() => {
        setActiveAlert(null);
      }, 12000); // 12 seconds
      return () => clearTimeout(timer);
    }
  }, [latestBlockedEvent]);

  const columns = [
    { key: 'timestamp', label: 'Time', sortable: true, render: (row) => <TimestampValue value={row.timestamp} /> },
    { key: 'domain', label: 'Domain', sortable: true, render: (row) => <span className="font-medium text-slate-900">{row.domain}</span> },
    { key: 'protocol', label: 'Protocol', sortable: true, render: (row) => <StatusPill tone={row.protocol === 'TCP' ? 'danger' : 'warning'}>{row.protocol}</StatusPill> },
    { key: 'reason', label: 'Reason', sortable: true, render: (row) => <span className="text-slate-600">{row.reason || 'Policy match'}</span> },
    { key: 'sourceIp', label: 'Source IP', sortable: true, render: (row) => <MonospacedValue value={row.sourceIp || '-'} /> },
    { key: 'destinationIp', label: 'Destination IP', sortable: true, render: (row) => <MonospacedValue value={row.destinationIp || '-'} /> },
  ];

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Blocked Today</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900"><NumericValue value={blockedToday} /></div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Most Blocked Domain</div>
          <div className="mt-1 truncate text-2xl font-semibold tracking-tight text-slate-900">{mostBlockedDomain}</div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Blocked DNS</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900"><NumericValue value={blockedDns} /></div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Blocked TLS</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900"><NumericValue value={blockedTls} /></div>
        </section>
      </div>

      <SectionCard
        title="Live Block Alert"
        description="The latest blocked domain appears here immediately when the policy engine matches a rule."
        action={<StatusPill tone={activeAlert ? 'danger' : 'neutral'}>{activeAlert ? 'Blocked' : 'Waiting'}</StatusPill>}
      >
        {activeAlert ? (
          <div className="grid gap-4 md:grid-cols-[1.4fr_1fr]">
            <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-4">
              <div className="text-xs font-semibold uppercase tracking-wide text-rose-700">Blocked Domain</div>
              <div className="mt-2 text-2xl font-semibold tracking-tight text-slate-900">{activeAlert.domain}</div>
              <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-slate-600">
                <StatusPill tone="danger">{activeAlert.protocol}</StatusPill>
                <span>{formatTime(activeAlert.timestamp)}</span>
              </div>
            </div>
            <div className="grid gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-4 text-sm text-slate-600">
              <div className="flex items-center justify-between gap-4"><span>Source IP</span><MonospacedValue value={activeAlert.sourceIp || '-'} /></div>
              <div className="flex items-center justify-between gap-4"><span>Destination IP</span><MonospacedValue value={activeAlert.destinationIp || '-'} /></div>
              <div className="flex items-center justify-between gap-4"><span>Reason</span><span className="text-right font-medium text-slate-900">{activeAlert.reason || 'Policy match'}</span></div>
            </div>
          </div>
        ) : (
          <EmptyState title="No blocked domains yet" description="Add a domain to blocked_domains.txt, start Sentinel DPI, and visit the matching site to see a live alert." />
        )}
      </SectionCard>

      <SectionCard title="Blocked Events" description="All blocked matches captured by the policy engine and stored in SQLite.">
        <DataTable
          columns={columns}
          rows={blockedEvents}
          initialSortKey="timestamp"
          emptyState={<EmptyState title="No blocked events yet" description="Blocked domains will appear here as soon as they are detected." />}
        />
      </SectionCard>
    </div>
  );
}