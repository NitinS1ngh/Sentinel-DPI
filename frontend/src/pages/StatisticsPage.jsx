import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import SectionCard from '../components/SectionCard';
import EmptyState from '../components/EmptyState';
import { buildEventDistribution, buildMostActiveHour, buildTopDomains } from '../lib/metrics';
import { formatNumber } from '../lib/format';

const COLORS = ['#cbd5e1', '#2563eb'];

export default function StatisticsPage({ events }) {
  const topDomains = buildTopDomains(events, 10);
  const distribution = buildEventDistribution(events);
  const activeHour = buildMostActiveHour(events).filter((bucket) => bucket.count > 0);
  const dns = distribution.find((item) => item.name === 'DNS')?.value || 0;
  const tls = distribution.find((item) => item.name === 'TLS')?.value || 0;
  const ratio = dns && tls ? `${(dns / Math.max(tls, 1)).toFixed(2)} : 1` : '—';

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-3">
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">DNS / TLS Ratio</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900">{ratio}</div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Top Domains Tracked</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900">{formatNumber(topDomains.length)}</div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Active Hours</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900">{formatNumber(activeHour.length)}</div>
        </section>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <SectionCard title="Top 10 Domains" description="Most observed domains in the current capture window.">
          {topDomains.length ? (
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topDomains} layout="vertical" margin={{ left: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" horizontal={false} />
                  <XAxis type="number" allowDecimals={false} tick={{ fill: '#64748b', fontSize: 12 }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="domain" width={120} tick={{ fill: '#64748b', fontSize: 12 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ borderRadius: '16px', border: '1px solid #e2e8f0' }} />
                  <Bar dataKey="count" fill="#2563eb" radius={[0, 8, 8, 0]} isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState title="No domain data yet" description="Generate traffic to populate the chart." />
          )}
        </SectionCard>

        <SectionCard title="Event Distribution" description="DNS versus TLS event mix.">
          {distribution.some((item) => item.value > 0) ? (
            <div className="grid gap-6 lg:grid-cols-[1fr_0.9fr]">
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={distribution} dataKey="value" nameKey="name" innerRadius={70} outerRadius={100} paddingAngle={2} isAnimationActive={false}>
                      {distribution.map((entry, index) => (
                        <Cell key={entry.name} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ borderRadius: '16px', border: '1px solid #e2e8f0' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="space-y-3">
                {distribution.map((entry) => (
                  <div key={entry.name} className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                    <div className="flex items-center justify-between text-sm">
                      <span className="font-medium text-slate-900">{entry.name}</span>
                      <span className="text-slate-500">{formatNumber(entry.value)}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <EmptyState title="No distribution data yet" description="The mix chart will appear after DNS and TLS events are captured." />
          )}
        </SectionCard>
      </div>

      <SectionCard title="Most Active Hour" description="Hourly event count over the observed window.">
        {activeHour.length ? (
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={activeHour}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                <XAxis dataKey="label" tick={{ fill: '#64748b', fontSize: 12 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#64748b', fontSize: 12 }} axisLine={false} tickLine={false} allowDecimals={false} width={32} />
                <Tooltip contentStyle={{ borderRadius: '16px', border: '1px solid #e2e8f0' }} />
                <Bar dataKey="count" fill="#2563eb" radius={[8, 8, 0, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <EmptyState title="No activity yet" description="Open some websites to see the busiest hour chart." />
        )}
      </SectionCard>
    </div>
  );
}
