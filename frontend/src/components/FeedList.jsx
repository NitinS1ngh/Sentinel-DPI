import StatusPill from './StatusPill';
import { formatTime } from '../lib/format';
import { simplifyDomain } from '../lib/domain-parser';

export default function FeedList({ events, rawMode = false }) {
  if (!events.length) {
    return <div className="text-sm text-slate-500">No events yet.</div>;
  }

  const filteredEvents = rawMode
    ? events
    : events.filter((event) => !simplifyDomain(event.domain || '').isBackground);

  if (!filteredEvents.length) {
    return <div className="text-sm text-slate-500">No primary events found. Turn on Raw Feed to see all background noise.</div>;
  }

  return (
    <div className="space-y-2">
      {filteredEvents.map((event) => {
        const domain = event.domain || 'Unknown domain';
        const simplified = rawMode ? { isSimplified: false, name: domain } : simplifyDomain(domain);
        return (
          <div key={event.id || `${event.timestamp}-${event.domain}`} className="flex items-start justify-between gap-4 rounded-xl border border-slate-200 bg-white px-4 py-3 shadow-sm transition-colors hover:bg-slate-50">
            <div>
              <div className="text-sm font-medium text-slate-900">{formatTime(event.timestamp)}</div>
              <div className="mt-1 flex flex-wrap items-center gap-2 text-sm text-slate-600">
                <StatusPill tone={event.eventType === 'TLS' ? 'info' : 'neutral'}>{event.eventType}</StatusPill>
                {simplified.isSimplified ? (
                  <div className="flex flex-col" title={domain}>
                    <span className="font-medium text-slate-900">{simplified.name}</span>
                    <span className="text-[10px] text-slate-400 font-mono truncate max-w-[250px]">{domain}</span>
                  </div>
                ) : (
                  <span className="font-medium text-slate-900">{domain}</span>
                )}
              </div>
            </div>
            <div className="text-right text-xs text-slate-500">
              <div>{event.sourceIp || '—'}</div>
              <div>{event.destinationIp || '—'}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
