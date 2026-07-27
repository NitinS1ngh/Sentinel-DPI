import { useState, useMemo } from 'react';
import SectionCard from '../components/SectionCard';
import DataTable, { NumericValue, TimestampValue } from '../components/DataTable';
import EmptyState from '../components/EmptyState';
import StatusPill from '../components/StatusPill';
import { refreshThreatFeeds, blockDomain } from '../services/api';
import { formatNumber } from '../lib/format';

function extractCanonicalDomain(input) {
  if (!input) return '';
  let str = input.trim().toLowerCase();
  str = str.replace(/^(https?:\/\/)?(ftps?:\/\/)?/, '');
  str = str.split('/')[0].split('?')[0].split('#')[0].split(':')[0];
  if (str.startsWith('www.')) {
    str = str.slice(4);
  }
  if (str.startsWith('*.')) {
    str = str.slice(2);
  }
  return str;
}

function isDomainMatch(itemDomain, searchDomain) {
  if (!itemDomain || !searchDomain) return false;
  const itemClean = extractCanonicalDomain(itemDomain);
  const searchClean = extractCanonicalDomain(searchDomain);
  if (!itemClean || !searchClean) return false;

  if (itemClean === searchClean) return true;
  if (itemClean.endsWith('.' + searchClean)) return true;
  if (searchClean.endsWith('.' + itemClean)) return true;

  return false;
}

export default function ThreatFeedsPage({
  threatFeeds = null,
  threatFeed = [],
  feedUpdates = [],
  latestFeedUpdate = null,
  search = '',
  onRefresh = null,
}) {
  const [refreshing, setRefreshing] = useState(false);
  const [addingDomain, setAddingDomain] = useState(false);
  const [addSuccessMsg, setAddSuccessMsg] = useState('');
  const [error, setError] = useState('');

  const cleanSearch = extractCanonicalDomain(search);
  const isSearching = Boolean(search.trim());

  const feeds = useMemo(() => {
    return (threatFeeds?.feeds || []).filter((feed) => {
      if (!search.trim()) return true;
      const nameMatch = feed.name.toLowerCase().includes(search.toLowerCase());
      const locMatch = feed.location.toLowerCase().includes(search.toLowerCase());
      return nameMatch || locMatch;
    });
  }, [threatFeeds, search]);

  const matchingIndicators = useMemo(() => {
    if (!cleanSearch) return [];
    return (threatFeed || []).filter((item) => isDomainMatch(item.domain, cleanSearch));
  }, [threatFeed, cleanSearch]);

  async function handleRefresh() {
    setRefreshing(true);
    setError('');
    setAddSuccessMsg('');
    try {
      await refreshThreatFeeds();
      if (onRefresh) {
        await onRefresh();
      }
    } catch (err) {
      setError(err.message || 'Unable to refresh feeds');
    } finally {
      setRefreshing(false);
    }
  }

  async function handleAddDomain(domainToAdd) {
    if (!domainToAdd) return;
    setAddingDomain(true);
    setAddSuccessMsg('');
    setError('');
    try {
      await blockDomain(domainToAdd);
      setAddSuccessMsg(`Successfully added "${domainToAdd}" to local threat feed & blocklist!`);
      if (onRefresh) {
        await onRefresh();
      }
    } catch (err) {
      setError(err.message || 'Failed to add domain to feed');
    } finally {
      setAddingDomain(false);
    }
  }

  const feedColumns = [
    { key: 'name', label: 'Feed Name', sortable: true },
    { key: 'type', label: 'Type', sortable: true },
    { key: 'status', label: 'Status', sortable: true, render: (row) => <StatusPill tone={row.status === 'REFRESHED' ? 'success' : row.status === 'FAILED' ? 'danger' : 'neutral'}>{row.status || 'Pending'}</StatusPill> },
    { key: 'last_update', label: 'Last Update', sortable: true, render: (row) => row.last_update ? <TimestampValue value={row.last_update} /> : '—' },
    { key: 'threat_count', label: 'Threats', sortable: true, render: (row) => <NumericValue value={row.threat_count || 0} /> },
    { key: 'version', label: 'Version', sortable: true },
    { key: 'health', label: 'Health', sortable: true, render: (row) => <StatusPill tone={row.health === 'Healthy' ? 'success' : row.health === 'Disabled' ? 'neutral' : 'danger'}>{row.health || 'Unknown'}</StatusPill> },
    { key: 'location', label: 'Location', sortable: true },
    { key: 'error', label: 'Error', sortable: true, render: (row) => row.error || '—' },
  ];

  const indicatorColumns = [
    { key: 'domain', label: 'Domain', sortable: true, render: (row) => <span className="font-medium text-slate-900">{row.domain}</span> },
    { key: 'category', label: 'Category', sortable: true, render: (row) => <span className="text-slate-600">{row.category}</span> },
    { key: 'severity', label: 'Severity', sortable: true, render: (row) => <StatusPill tone={row.severity === 'CRITICAL' || row.severity === 'HIGH' ? 'danger' : 'info'}>{row.severity}</StatusPill> },
    { key: 'description', label: 'Description', sortable: true, render: (row) => <span className="text-slate-600">{row.description}</span> },
  ];

  const updateColumns = [
    { key: 'timestamp', label: 'Time', sortable: true, render: (row) => <TimestampValue value={row.timestamp} /> },
    { key: 'status', label: 'Status', sortable: true, render: (row) => <StatusPill tone={row.status === 'REFRESHED' ? 'success' : 'danger'}>{row.status}</StatusPill> },
    { key: 'sourcesChecked', label: 'Sources', sortable: true, render: (row) => <NumericValue value={row.sourcesChecked} /> },
    { key: 'indicatorsLoaded', label: 'Threats', sortable: true, render: (row) => <NumericValue value={row.indicatorsLoaded} /> },
    { key: 'message', label: 'Log', sortable: true },
  ];

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-3">
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Auto Refresh</div>
          <div className="mt-2"><StatusPill tone={threatFeeds?.auto_refresh_enabled ? 'success' : 'neutral'}>{threatFeeds?.auto_refresh_enabled ? 'Enabled' : 'Disabled'}</StatusPill></div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Threat Entries</div>
          <div className="mt-2 text-2xl font-semibold tracking-tight text-slate-900">{formatNumber(threatFeeds?.threat_count || 0)}</div>
        </section>
        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft">
          <div className="text-sm text-slate-500">Feed Health</div>
          <div className="mt-2"><StatusPill tone={threatFeeds?.health === 'Healthy' ? 'success' : 'danger'}>{threatFeeds?.health || 'Unknown'}</StatusPill></div>
        </section>
      </div>

      {addSuccessMsg ? (
        <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700">
          {addSuccessMsg}
        </div>
      ) : null}

      {error ? (
        <div className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          {error}
        </div>
      ) : null}

      {isSearching && matchingIndicators.length > 0 ? (
        <SectionCard
          title={`Matching Threat Indicators (${matchingIndicators.length})`}
          description={`Found threat entries matching "${cleanSearch}".`}
        >
          <DataTable
            columns={indicatorColumns}
            rows={matchingIndicators}
            initialSortKey="severity"
            emptyState={<EmptyState title="No matching indicators" description="Try another domain search." />}
          />
        </SectionCard>
      ) : null}

      <SectionCard
        title="Threat Feeds"
        description="Deterministic feeds merged into the in-memory threat cache."
        action={
          <button
            type="button"
            onClick={handleRefresh}
            disabled={refreshing}
            className="rounded-full bg-slate-900 px-4 py-2 text-sm font-medium text-white transition-colors disabled:opacity-50 hover:bg-slate-800"
          >
            {refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        }
      >
        <DataTable
          columns={feedColumns}
          rows={feeds}
          initialSortKey="name"
          emptyState={
            isSearching && cleanSearch ? (
              matchingIndicators.length > 0 ? (
                <div className="py-6 text-center text-sm text-slate-500">
                  <div className="text-base font-semibold text-emerald-700">
                    ✓ Domain is already active in Threat Intelligence
                  </div>
                  <div className="mt-1">
                    Matching indicator details are displayed in the table above.
                  </div>
                </div>
              ) : (
                <div className="py-6 text-center">
                  <div className="text-base font-semibold text-slate-900">
                    "{cleanSearch}" is not in any active threat feed
                  </div>
                  <div className="mt-1 text-sm text-slate-500">
                    The domain is currently clean or unlisted. Would you like to add it to your local threat feed & blocklist?
                  </div>
                  <div className="mt-4 flex justify-center">
                    <button
                      type="button"
                      onClick={() => handleAddDomain(cleanSearch)}
                      disabled={addingDomain}
                      className="rounded-full bg-rose-600 px-5 py-2 text-sm font-medium text-white shadow-sm transition-colors hover:bg-rose-700 disabled:opacity-50"
                    >
                      {addingDomain ? 'Adding…' : `+ Add "${cleanSearch}" to Local Threat Feed`}
                    </button>
                  </div>
                </div>
              )
            ) : (
              <EmptyState title="No feeds configured" description="Add feed sources to threat_feeds.json." />
            )
          }
        />
      </SectionCard>

      <SectionCard
        title="Feed Logs"
        description="Recent automatic and manual feed refresh attempts."
        action={<StatusPill tone={latestFeedUpdate ? 'success' : 'neutral'}>{latestFeedUpdate ? latestFeedUpdate.status : 'Idle'}</StatusPill>}
      >
        <DataTable
          columns={updateColumns}
          rows={feedUpdates.slice(0, 10)}
          initialSortKey="timestamp"
          emptyState={<EmptyState title="No feed updates yet" description="The updater logs each successful refresh here." />}
        />
      </SectionCard>
    </div>
  );
}
