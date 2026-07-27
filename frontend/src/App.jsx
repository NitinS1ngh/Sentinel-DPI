import { Suspense, lazy, useEffect, useMemo, useState } from 'react';
import Layout from './components/Layout';
import EmptyState from './components/EmptyState';
import { APP_VERSION } from './config';
import useDashboardData from './hooks/useDashboardData';
import {
  buildDomainRows,
  buildEventDistribution,
  buildMinuteSeries,
  buildMostActiveHour,
  buildTopDomains,
  calculateTrend,
  countEventsLastHour,
  countUniqueDomains,
  filterEventsBySearch,
  getRecentEvents,
  summarizeEvents,
} from './lib/metrics';
import { formatDateTime, formatNumber, formatPercent } from './lib/format';
const OverviewPage = lazy(() => import('./pages/OverviewPage'));
const LiveTrafficPage = lazy(() => import('./pages/LiveTrafficPage'));
const StatisticsPage = lazy(() => import('./pages/StatisticsPage'));
const PoliciesPage = lazy(() => import('./pages/PoliciesPage'));
const ThreatIntelligencePage = lazy(() => import('./pages/ThreatIntelligencePage'));
const SecurityOverviewPage = lazy(() => import('./pages/SecurityOverviewPage'));
const ThreatFeedsPage = lazy(() => import('./pages/ThreatFeedsPage'));
const BlockedEventsPage = lazy(() => import('./pages/BlockedEventsPage'));
const FirewallPage = lazy(() => import('./pages/FirewallPage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));

const PAGES = ['Overview', 'Live Traffic', 'Statistics', 'Policies', 'Raw Feed Section', 'Threat Intelligence', 'Threat Feeds', 'Blocked Events', 'Firewall', 'Settings'];

function getSystemStatus(error, loading) {
  if (error) return 'Degraded';
  if (loading) return 'Loading';
  return 'Healthy';
}

export default function App() {
  const [activePage, setActivePage] = useState(() => {
    return localStorage.getItem('sentinel_active_page') || 'Overview';
  });
  
  useEffect(() => {
    localStorage.setItem('sentinel_active_page', activePage);
  }, [activePage]);

  const [search, setSearch] = useState('');
  const dashboard = useDashboardData();

  const visibleEvents = useMemo(() => filterEventsBySearch(dashboard.events, search), [dashboard.events, search]);
  const sortedEvents = useMemo(() => getRecentEvents(visibleEvents, 50), [visibleEvents]);
  const overviewEvents = useMemo(() => getRecentEvents(visibleEvents, 100), [visibleEvents]);
  const minuteSeries = useMemo(() => buildMinuteSeries(overviewEvents, 60), [overviewEvents]);
  const domainRows = useMemo(() => buildDomainRows(overviewEvents), [overviewEvents]);
  const topDomains = useMemo(() => buildTopDomains(overviewEvents, 10), [overviewEvents]);
  const eventDistribution = useMemo(() => buildEventDistribution(overviewEvents), [overviewEvents]);
  const activeHour = useMemo(() => buildMostActiveHour(overviewEvents), [overviewEvents]);
  const summary = useMemo(() => summarizeEvents(overviewEvents), [overviewEvents]);
  const uniqueDomains = countUniqueDomains(overviewEvents);
  const eventsLastHour = countEventsLastHour(overviewEvents);
  const systemStatus = getSystemStatus(dashboard.error, dashboard.loading);

  const topDomainsWithTrend = useMemo(() => {
    const lastThirty = minuteSeries.slice(-30).reduce((sum, bucket) => sum + bucket.total, 0);
    const previousThirty = minuteSeries.slice(0, 30).reduce((sum, bucket) => sum + bucket.total, 0);
    const trend = calculateTrend(lastThirty, previousThirty);
    return { lastThirty, previousThirty, trend };
  }, [minuteSeries]);

  const sharedProps = {
    events: overviewEvents,
    rawEvents: dashboard.events,
    summary,
    minuteSeries,
    topDomains,
    domainRows,
    eventDistribution,
    activeHour,
    loading: dashboard.loading,
    error: dashboard.error,
    lastUpdated: dashboard.lastUpdated,
    search,
    onSearchChange: setSearch,
    uniqueDomains,
    eventsLastHour,
    apiDomains: dashboard.domains,
    policyEvents: dashboard.policyEvents,
    threatFeed: dashboard.threatFeed,
    threatEvents: dashboard.threatEvents,
    threatStats: dashboard.threatStats,
    securityOverview: dashboard.securityOverview,
    securityIncidents: dashboard.securityIncidents,
    threatFeeds: dashboard.threatFeeds,
    feedUpdates: dashboard.feedUpdates,
    blockedEvents: dashboard.blockedEvents,
    blockStats: dashboard.blockStats,
    blockedDomains: dashboard.blockedDomains,
    firewallStatus: dashboard.firewallStatus,
    firewallRules: dashboard.firewallRules,
    firewallActions: dashboard.firewallActions,
    latestFirewallAction: dashboard.latestFirewallAction,
    latestBlockedEvent: dashboard.latestBlockedEvent,
    latestThreatEvent: dashboard.latestThreatEvent,
    latestSecurityIncident: dashboard.latestSecurityIncident,
    latestFeedUpdate: dashboard.latestFeedUpdate,
    systemStatus,
    liveStatus: dashboard.liveStatus,
    onRefresh: dashboard.refetch,
  };

  function renderPage() {
    const fallback = (
      <section className="rounded-2xl border border-slate-200 bg-white px-6 py-10 text-sm text-slate-500 shadow-soft">
        Loading section…
      </section>
    );

    switch (activePage) {
      case 'Overview':
        return <Suspense fallback={fallback}><OverviewPage {...sharedProps} trendInfo={topDomainsWithTrend} /></Suspense>;
      case 'Live Traffic':
        return <Suspense fallback={fallback}><LiveTrafficPage {...sharedProps} /></Suspense>;
      case 'Statistics':
        return <Suspense fallback={fallback}><StatisticsPage {...sharedProps} /></Suspense>;
      case 'Policies':
        return <Suspense fallback={fallback}><PoliciesPage {...sharedProps} /></Suspense>;
      case 'Threat Intelligence':
        return <Suspense fallback={fallback}><ThreatIntelligencePage {...sharedProps} /></Suspense>;
      case 'Raw Feed':
        return <Suspense fallback={fallback}><SecurityOverviewPage {...sharedProps} /></Suspense>;
      case 'Threat Feeds':
        return <Suspense fallback={fallback}><ThreatFeedsPage {...sharedProps} /></Suspense>;
      case 'Blocked Events':
        return <Suspense fallback={fallback}><BlockedEventsPage {...sharedProps} /></Suspense>;
      case 'Firewall':
        return <Suspense fallback={fallback}><FirewallPage {...sharedProps} /></Suspense>;
      case 'Settings':
        return <Suspense fallback={fallback}><SettingsPage {...sharedProps} /></Suspense>;
      default:
        return <Suspense fallback={fallback}><OverviewPage {...sharedProps} trendInfo={topDomainsWithTrend} /></Suspense>;
    }
  }

  if (dashboard.error && !dashboard.events.length) {
    return (
      <Layout activePage={activePage} onNavigate={setActivePage} search={search} onSearchChange={setSearch} systemStatus={systemStatus} liveStatus={dashboard.liveStatus}>
        <div className="mx-auto max-w-2xl py-20">
          <EmptyState
            title="Unable to load Sentinel DPI"
            description={dashboard.error}
            action={<button onClick={() => window.location.reload()} className="rounded-full bg-slate-900 px-4 py-2 text-sm font-medium text-white">Retry</button>}
          />
        </div>
      </Layout>
    );
  }

  return (
    <Layout activePage={activePage} onNavigate={setActivePage} search={search} onSearchChange={setSearch} systemStatus={systemStatus} liveStatus={dashboard.liveStatus}>
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <div className="flex flex-wrap gap-2 md:hidden">
          {PAGES.map((page) => (
            <button
              key={page}
              onClick={() => setActivePage(page)}
              className={`rounded-full border px-3 py-1.5 text-sm font-medium transition-colors ${
                activePage === page ? 'border-slate-900 bg-slate-900 text-white' : 'border-slate-200 bg-white text-slate-600'
              }`}
            >
              {page}
            </button>
          ))}
        </div>

        <section className="rounded-2xl border border-slate-200 bg-white px-5 py-4 shadow-soft md:hidden">
          <div className="text-sm text-slate-500">Interface</div>
          <div className="mt-1 font-medium text-slate-900">en0</div>
        </section>

        {renderPage()}
        <footer className="pb-4 pt-1 text-center text-xs text-slate-400">
          Sentinel DPI v{APP_VERSION} · Last update {dashboard.lastUpdated ? formatDateTime(dashboard.lastUpdated) : '—'}
        </footer>
      </div>
    </Layout>
  );
}
