import SectionCard from '../components/SectionCard';
import EmptyState from '../components/EmptyState';
import StatusPill from '../components/StatusPill';
import DataTable, { TimestampValue, MonospacedValue } from '../components/DataTable';
import { formatNumber } from '../lib/format';

export default function PoliciesPage({ policyEvents = [] }) {
  const blockedCount = policyEvents.filter((event) => event.policyType === 'BLOCKED').length;
  const monitoredCount = policyEvents.filter((event) => event.policyType === 'MONITORED').length;
  const columns = [
    { key: 'timestamp', label: 'Time', sortable: true, render: (row) => <TimestampValue value={row.timestamp} /> },
    { key: 'policyType', label: 'Policy', sortable: true, render: (row) => <StatusPill tone={row.policyType === 'BLOCKED' ? 'danger' : 'info'}>{row.policyType}</StatusPill> },
    { key: 'domain', label: 'Domain', sortable: true, render: (row) => <span className="font-medium text-slate-900">{row.domain}</span> },
    { key: 'sourceIp', label: 'Source IP', sortable: true, render: (row) => <MonospacedValue value={row.sourceIp || '-'} /> },
  ];

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-3">
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Blocked Matches</div>
          <div className="mt-2 text-2xl font-semibold tracking-tight text-slate-900">{formatNumber(blockedCount)}</div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Monitored Matches</div>
          <div className="mt-2 text-2xl font-semibold tracking-tight text-slate-900">{formatNumber(monitoredCount)}</div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Policy Status</div>
          <div className="mt-2"><StatusPill tone="success">Hot reload</StatusPill></div>
        </section>
      </div>

      <SectionCard title="Recent Policy Matches" description="Blocked and monitored domain detections from the backend policy engine.">
        <DataTable
          columns={columns}
          rows={policyEvents}
          initialSortKey="timestamp"
          emptyState={<EmptyState title="No policy matches yet" description="Add domains to blocked_domains.txt or monitored_domains.txt, then generate DNS or TLS traffic." />}
        />
      </SectionCard>
    </div>
  );
}
