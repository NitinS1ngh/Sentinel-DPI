import { useMemo, useState, useEffect } from 'react';
import SectionCard from '../components/SectionCard';
import EmptyState from '../components/EmptyState';
import StatusPill from '../components/StatusPill';
import DataTable, { TimestampValue, MonospacedValue } from '../components/DataTable';
import { formatNumber, formatTime } from '../lib/format';
import { buildThreatCategoryRows, buildThreatSeverityDistribution, buildTopThreatDomains, getRecentThreatEvents, summarizeThreatEvents } from '../lib/metrics';
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid } from 'recharts';

const SEVERITY_COLORS = {
  CRITICAL: '#b91c1c',
  HIGH: '#ea580c',
  MEDIUM: '#ca8a04',
  LOW: '#2563eb',
};

function severityTone(severity) {
  switch (severity) {
    case 'CRITICAL': return 'danger';
    case 'HIGH': return 'danger';
    case 'MEDIUM': return 'info';
    default: return 'success';
  }
}

function isRecentEvent(event, maxAgeSeconds = 30) {
  if (!event || !event.timestamp) return false;
  try {
    const rawTs = event.timestamp.includes('T') ? event.timestamp : event.timestamp.replace(' ', 'T') + 'Z';
    const eventTime = new Date(rawTs).getTime();
    if (isNaN(eventTime)) return false;
    return (Date.now() - eventTime) < (maxAgeSeconds * 1000);
  } catch {
    return false;
  }
}

export default function ThreatIntelligencePage({ threatFeed = [], threatEvents = [], threatStats = null, latestThreatEvent = null }) {
  const [showFeed, setShowFeed] = useState(false);
  const [activeAlert, setActiveAlert] = useState(() => (isRecentEvent(latestThreatEvent) ? latestThreatEvent : null));

  useEffect(() => {
    if (isRecentEvent(latestThreatEvent)) {
      setActiveAlert(latestThreatEvent);
      const timer = setTimeout(() => {
        setActiveAlert(null);
      }, 15000);
      return () => clearTimeout(timer);
    } else {
      setActiveAlert(null);
    }
  }, [latestThreatEvent]);
  const summary = useMemo(() => summarizeThreatEvents(threatEvents), [threatEvents]);
  const categories = useMemo(() => buildThreatCategoryRows(threatEvents), [threatEvents]);
  const severityDistribution = useMemo(() => buildThreatSeverityDistribution(threatEvents), [threatEvents]);
  const topDomains = useMemo(() => buildTopThreatDomains(threatEvents, 10), [threatEvents]);
  const recentThreatEvents = useMemo(() => getRecentThreatEvents(threatEvents, 50), [threatEvents]);

  const threatSource = threatStats || summary;
  const totalThreats = threatSource.totalThreats || threatEvents.length;
  const severityRows = severityDistribution.length ? severityDistribution : (threatSource.severityDistribution || []);

  const detectedColumns = [
    { key: 'timestamp', label: 'Time', sortable: true, render: (row) => <TimestampValue value={row.timestamp} /> },
    { key: 'domain', label: 'Domain', sortable: true, render: (row) => <span className="font-medium text-slate-900">{row.domain}</span> },
    { key: 'category', label: 'Category', sortable: true, render: (row) => <span className="text-slate-600">{row.category}</span> },
    { key: 'severity', label: 'Severity', sortable: true, render: (row) => <StatusPill tone={severityTone(row.severity)}>{row.severity}</StatusPill> },
    { key: 'description', label: 'Description', sortable: true, render: (row) => <span className="text-slate-600">{row.description}</span> },
    { key: 'sourceIp', label: 'Source IP', sortable: true, render: (row) => <MonospacedValue value={row.sourceIp || '-'} /> },
  ];

  const feedColumns = [
    { key: 'domain', label: 'Domain', sortable: true, render: (row) => <span className="font-medium text-slate-900">{row.domain}</span> },
    { key: 'category', label: 'Category', sortable: true, render: (row) => <span className="text-slate-600">{row.category}</span> },
    { key: 'severity', label: 'Severity', sortable: true, render: (row) => <StatusPill tone={severityTone(row.severity)}>{row.severity}</StatusPill> },
    { key: 'description', label: 'Description', sortable: true, render: (row) => <span className="text-slate-600">{row.description}</span> },
  ];

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Total Threats</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900">{formatNumber(totalThreats)}</div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Critical</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900">{formatNumber(summary.critical || 0)}</div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">High</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900">{formatNumber(summary.high || 0)}</div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Medium / Low</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900">{formatNumber((summary.medium || 0) + (summary.low || 0))}</div>
        </section>
      </div>

      <SectionCard
        title="Live Threat Alert"
        description="The newest threat detection appears here immediately when DNS or TLS traffic matches the threat feed."
        action={<StatusPill tone={activeAlert ? severityTone(activeAlert.severity) : 'neutral'}>{activeAlert ? activeAlert.severity : 'Idle'}</StatusPill>}
      >
        {activeAlert ? (
          <div className="grid gap-4 md:grid-cols-[1.2fr_1fr]">
            <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-4">
              <div className="text-xs font-semibold uppercase tracking-wide text-rose-700">[THREAT] Active Threat Alert</div>
              <div className="mt-2 text-2xl font-semibold tracking-tight text-slate-900">{activeAlert.domain}</div>
              <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-slate-600">
                <StatusPill tone={severityTone(activeAlert.severity)}>{activeAlert.category}</StatusPill>
                <span>{activeAlert.severity}</span>
                <span>{formatTime(activeAlert.timestamp)}</span>
              </div>
            </div>
            <div className="grid gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-4 text-sm text-slate-600">
              <div className="flex items-center justify-between gap-4"><span>Description</span><span className="text-right font-medium text-slate-900">{activeAlert.description || 'Threat intelligence match'}</span></div>
              <div className="flex items-center justify-between gap-4"><span>Protocol</span><MonospacedValue value={activeAlert.protocol || '-'} /></div>
              <div className="flex items-center justify-between gap-4"><span>Source IP</span><MonospacedValue value={activeAlert.sourceIp || '-'} /></div>
              <div className="flex items-center justify-between gap-4"><span>Destination IP</span><MonospacedValue value={activeAlert.destinationIp || '-'} /></div>
            </div>
          </div>
        ) : (
          <EmptyState title="No active threat detections" description="Live threat alerts return to Idle 15 seconds after network traffic to the malicious site stops." />
        )}
      </SectionCard>

      <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
        <SectionCard title="Severity Distribution" description="Detected threat counts by severity.">
          <div className="h-72 w-full">
            {severityRows.length ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={severityRows} dataKey="count" nameKey="label" innerRadius={60} outerRadius={100} paddingAngle={4}>
                    {severityRows.map((entry) => (
                      <Cell key={entry.label} fill={SEVERITY_COLORS[entry.label] || '#64748b'} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState title="No severity data yet" description="Threat detections will populate the severity chart." />
            )}
          </div>
        </SectionCard>

        <SectionCard title="Threat Categories" description="Category counts from detected threats.">
          <div className="h-72 w-full">
            {categories.length ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categories} barCategoryGap={16}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                  <XAxis dataKey="label" tick={{ fill: '#64748b', fontSize: 12 }} tickLine={false} axisLine={false} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 12 }} tickLine={false} axisLine={false} allowDecimals={false} width={28} />
                  <Tooltip />
                  <Bar dataKey="count" fill="#0f172a" radius={[8, 8, 0, 0]} isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState title="No category data yet" description="Detected threats will populate this chart." />
            )}
          </div>
        </SectionCard>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
        <SectionCard title="Top Threat Domains" description="The most frequently detected malicious domains.">
          {topDomains.length ? (
            <div className="h-80 overflow-y-auto pr-2 space-y-2">
              {topDomains.map((row) => (
                <div key={row.domain} className="rounded-xl border border-slate-200 bg-white px-4 py-3">
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <div className="font-medium text-slate-900">{row.domain}</div>
                      <div className="mt-1 text-xs text-slate-500">{row.category || 'Unknown'} · {row.severity || 'Unknown'}</div>
                    </div>
                    <StatusPill tone="danger">{formatNumber(row.count)}</StatusPill>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="No top domains yet" description="Threat detections will rank here by frequency." />
          )}
        </SectionCard>

        <SectionCard title="Recent Threat Events" description="A compact recent-feed view for operator triage.">
          {recentThreatEvents.length ? (
            <div className="h-80 overflow-y-auto pr-2">
              <div className="grid gap-3 md:grid-cols-2">
                {recentThreatEvents.map((event) => (
                  <div key={event.id || `${event.timestamp}-${event.domain}`} className="rounded-2xl border border-slate-200 bg-white px-4 py-4 shadow-sm">
                    <div className="flex items-center justify-between gap-3">
                      <div className="font-medium text-slate-900">{event.domain}</div>
                      <StatusPill tone={severityTone(event.severity)}>{event.severity}</StatusPill>
                    </div>
                    <div className="mt-2 text-sm text-slate-600">{event.category}</div>
                    <div className="mt-3 text-xs text-slate-500">{formatTime(event.timestamp)}</div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <EmptyState title="No recent threat events" description="Recent detections will appear here once traffic matches the feed." />
          )}
        </SectionCard>
      </div>

      <SectionCard title="Detected Threats" description="Live threat matches stored in SQLite.">
        <div className="max-h-[460px] overflow-y-auto pr-1">
          <DataTable
            columns={detectedColumns}
            rows={threatEvents}
            initialSortKey="timestamp"
            emptyState={<EmptyState title="No detected threats yet" description="Threat events will appear here as soon as a domain matches threats.json." />}
          />
        </div>
      </SectionCard>

      <SectionCard
        title="Loaded Threat Feed Indicators"
        description="Deterministic threat indicators loaded in memory from local & online feeds."
        action={
          <button
            type="button"
            onClick={() => setShowFeed(!showFeed)}
            className="rounded-full bg-slate-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-slate-800"
          >
            {showFeed ? 'Hide Indicators' : `Show Threat Feed (${formatNumber(threatFeed.length)} indicators)`}
          </button>
        }
      >
        {showFeed ? (
          <DataTable
            columns={feedColumns}
            rows={threatFeed}
            initialSortKey="severity"
            emptyState={<EmptyState title="No threat feed loaded" description="Populate threats.json to enable threat intelligence lookups." />}
          />
        ) : (
          <div className="rounded-2xl border border-dashed border-slate-200 bg-slate-50/50 p-6 text-center text-sm text-slate-500">
            Click the button above to expand and view all {formatNumber(threatFeed.length)} threat indicators loaded from active threat feeds.
          </div>
        )}
      </SectionCard>
    </div>
  );
}