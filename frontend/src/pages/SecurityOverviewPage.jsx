import { useMemo, useState } from 'react';
import SectionCard from '../components/SectionCard';
import DataTable, { NumericValue, TimestampValue, MonospacedValue } from '../components/DataTable';
import EmptyState from '../components/EmptyState';
import StatusPill from '../components/StatusPill';
import { buildSecurityTimeline, buildSuspiciousDomains } from '../lib/metrics';
import { formatNumber } from '../lib/format';

function severityTone(severity) {
  if (severity === 'CRITICAL' || severity === 'HIGH') return 'danger';
  if (severity === 'MEDIUM') return 'info';
  return 'neutral';
}

export default function SecurityOverviewPage({ securityOverview = null, securityIncidents = [], latestSecurityIncident = null }) {
  const [expandedId, setExpandedId] = useState(null);
  const suspiciousDomains = useMemo(() => buildSuspiciousDomains(securityIncidents, 10), [securityIncidents]);
  const timeline = useMemo(() => buildSecurityTimeline(securityIncidents, 50), [securityIncidents]);
  const overview = securityOverview || {};

  const domainColumns = [
    { key: 'domain', label: 'Domain', sortable: true, render: (row) => <span className="font-medium text-slate-900">{row.domain}</span> },
    { key: 'maxScore', label: 'Risk', sortable: true, render: (row) => <NumericValue value={row.maxScore} /> },
    { key: 'severity', label: 'Severity', sortable: true, render: (row) => <StatusPill tone={severityTone(row.severity)}>{row.severity}</StatusPill> },
    { key: 'category', label: 'Category', sortable: true },
    { key: 'count', label: 'Events', sortable: true, render: (row) => <NumericValue value={row.count} /> },
  ];

  return (
    <div className="space-y-6">


      <SectionCard
        title="Raw Feed"
        description="Live view of all captured DNS and TLS network events."
      >
        {timeline.length ? (
          <div className="h-[calc(100vh-14rem)] overflow-y-auto pr-2 space-y-2">
            {timeline.map((incident) => {
              const expanded = expandedId === incident.id;
              return (
                <button
                  key={incident.id || `${incident.timestamp}-${incident.domain}`}
                  type="button"
                  onClick={() => setExpandedId(expanded ? null : incident.id)}
                  className="w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-left shadow-sm transition-colors hover:bg-slate-50"
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <div className="font-medium text-slate-900">{incident.domain || 'Unknown domain'}</div>
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                        <span>{incident.category || 'Uncategorized'}</span>
                        <span>{incident.eventType}</span>
                        <TimestampValue value={incident.timestamp} />
                      </div>
                    </div>

                  </div>
                  {expanded ? (
                    <div className="mt-4 grid gap-2 border-t border-slate-100 pt-3 text-sm text-slate-600 md:grid-cols-2">
                      <div><span className="font-medium text-slate-900">Explanation:</span> {incident.explanation}</div>
                      <div><span className="font-medium text-slate-900">Recommendation:</span> {incident.recommendation}</div>
                      <div className="flex items-center justify-between gap-4"><span>Source</span><MonospacedValue value={incident.sourceIp || '-'} /></div>
                      <div className="flex items-center justify-between gap-4"><span>Destination</span><MonospacedValue value={incident.destinationIp || '-'} /></div>
                    </div>
                  ) : null}
                </button>
              );
            })}
          </div>
        ) : (
          <EmptyState title="No security incidents yet" description="Security analysis will appear as DNS or TLS events are observed." />
        )}
      </SectionCard>


    </div>
  );
}
