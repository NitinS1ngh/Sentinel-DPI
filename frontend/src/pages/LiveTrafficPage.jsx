
import SectionCard from '../components/SectionCard';
import FeedList from '../components/FeedList';
import EmptyState from '../components/EmptyState';
import { formatNumber } from '../lib/format';

export default function LiveTrafficPage({ events, summary, loading }) {

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-3">
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">DNS Events</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900">{formatNumber(summary.totalDns)}</div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">TLS Events</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900">{formatNumber(summary.totalTls)}</div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Live Feed</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-slate-900">{loading ? 'Refreshing' : 'Active'}</div>
        </section>
      </div>

      <SectionCard
        title="Recent Traffic"
        description="A concise, readable stream of the latest DNS and TLS events."
      >
        {events.length ? (
          <div className="max-h-[450px] overflow-y-auto pr-2">
            <FeedList events={events.slice(0, 50)} rawMode={false} />
          </div>
        ) : (
          <EmptyState title="No events yet" description="Traffic will appear here once DNS or TLS packets are observed." />
        )}
      </SectionCard>
    </div>
  );
}
