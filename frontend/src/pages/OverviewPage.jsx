import { useState } from 'react';
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import SectionCard from '../components/SectionCard';
import StatCard from '../components/StatCard';
import DataTable, { MonospacedValue, TimestampValue, NumericValue, DomainValue } from '../components/DataTable';
import FeedList from '../components/FeedList';
import StatusPill from '../components/StatusPill';
import EmptyState from '../components/EmptyState';
import { formatNumber, formatPercent } from '../lib/format';

export default function OverviewPage({
  summary,
  minuteSeries,
  topDomains,
  events,
  loading,
  error,
  trendInfo,
  uniqueDomains,
  eventsLastHour,
}) {
  const [rawMode, setRawMode] = useState(false);

  const dnsTrend = formatPercent(trendInfo.trend ?? 0);
  const totalEvents = events.length;
  const dnsCardTrend = formatPercent((summary.totalDns || 0) - (summary.totalTls || 0));
  const tlsCardTrend = formatPercent((summary.totalTls || 0) - (summary.totalDns || 0));
  const uniqueTrend = formatPercent(uniqueDomains ? (uniqueDomains - 1) / uniqueDomains * 100 : 0);
  const lastHourTrend = formatPercent(eventsLastHour ? trendInfo.trend || 0 : 0);

  const columns = [
    { key: 'domain', label: 'Domain', sortable: true, render: (row) => <DomainValue value={row.domain} /> },
    { key: 'count', label: 'Event Count', sortable: true, render: (row) => <NumericValue value={row.count} /> },
    { key: 'dnsCount', label: 'DNS Count', sortable: true, render: (row) => <NumericValue value={row.dnsCount} /> },
    { key: 'tlsCount', label: 'TLS Count', sortable: true, render: (row) => <NumericValue value={row.tlsCount} /> },
    { key: 'lastSeen', label: 'Last Seen', sortable: true, render: (row) => <TimestampValue value={row.lastSeen} /> },
  ];

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total DNS Events" value={formatNumber(summary.totalDns)} icon="dns" tone="accent" />
        <StatCard label="Total TLS Events" value={formatNumber(summary.totalTls)} icon="tls" />
        <StatCard label="Unique Domains" value={formatNumber(uniqueDomains)} icon="domain" />
        <StatCard label="Events Last Hour" value={formatNumber(eventsLastHour)} icon="hour" />
      </div>

      <SectionCard
        title="Traffic Activity"
        description="Events per minute with DNS and TLS breakdown."
        action={<StatusPill tone={loading ? 'neutral' : 'success'}>{loading ? 'Refreshing' : 'Live'}</StatusPill>}
      >
        <div className="h-80 w-full">
          {minuteSeries.length ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={minuteSeries} barCategoryGap={6}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                <XAxis dataKey="label" tick={{ fill: '#64748b', fontSize: 12 }} tickLine={false} axisLine={false} minTickGap={24} />
                <YAxis tick={{ fill: '#64748b', fontSize: 12 }} tickLine={false} axisLine={false} allowDecimals={false} width={32} />
                <Tooltip
                  contentStyle={{ borderRadius: '16px', border: '1px solid #e2e8f0', boxShadow: '0 10px 28px rgba(15, 23, 42, 0.08)' }}
                  labelStyle={{ color: '#0f172a', fontWeight: 600 }}
                />
                <Bar dataKey="dns" name="DNS" fill="#cbd5e1" radius={[8, 8, 0, 0]} isAnimationActive={false} />
                <Bar dataKey="tls" name="TLS" fill="#2563eb" radius={[8, 8, 0, 0]} isAnimationActive={false} />
                <Line type="monotone" dataKey="total" stroke="#0f172a" strokeWidth={2} dot={false} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState
              title="No traffic data yet"
              description="Open a few websites after starting Sentinel DPI to populate the activity chart."
            />
          )}
        </div>
      </SectionCard>

      <div className="grid gap-6 xl:grid-cols-[1.3fr_0.9fr]">
        <SectionCard title="Top Domains" description="Sortable by count, DNS, TLS, and last seen.">
          {topDomains.length ? (
            <div className="max-h-[340px] overflow-y-auto pr-1">
              <DataTable columns={columns} rows={topDomains} initialSortKey="count" />
            </div>
          ) : (
            <EmptyState title="No domain data yet" description="The dashboard will populate once DNS or TLS events arrive." />
          )}
        </SectionCard>

        <SectionCard 
          title="Recent Events" 
          description="Latest events with background noise filtering."
          action={
            <button
              onClick={() => setRawMode(!rawMode)}
              className={`text-xs px-3 py-1.5 rounded-full font-medium transition-colors border ${
                rawMode 
                  ? 'bg-brand-100 text-brand-700 border-brand-200 hover:bg-brand-200' 
                  : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
              }`}
            >
              {rawMode ? 'Raw Feed: ON' : 'Raw Feed: OFF'}
            </button>
          }
        >
          {events.length ? (
            <div className="max-h-[340px] overflow-y-auto pr-1">
              <FeedList events={events.slice(0, 50)} rawMode={rawMode} />
            </div>
          ) : (
            <EmptyState title="No events yet" description="Live captured network events will appear here." />
          )}
        </SectionCard>
      </div>
    </div>
  );
}
