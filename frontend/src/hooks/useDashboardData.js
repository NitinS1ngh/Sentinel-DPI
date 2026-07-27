import { useEffect, useMemo, useRef, useState } from 'react';
import { fetchDashboardData } from '../services/api';
import { createLiveDashboardStream } from '../services/liveStream';
import { normalizeBlockedEvent, normalizeEvent, normalizeFeedUpdate, normalizeFirewallAction, normalizePolicyEvent, normalizeSecurityIncident, normalizeThreatEvent } from '../lib/metrics';

const MAX_EVENTS = 1000;
const MAX_POLICY_EVENTS = 500;
const MAX_BLOCKED_EVENTS = 500;
const MAX_FIREWALL_ACTIONS = 200;
const MAX_THREAT_EVENTS = 1000;
const MAX_SECURITY_INCIDENTS = 1000;
const MAX_FEED_UPDATES = 200;

function makeTrafficEventId(event) {
  return `live-${event.type}-${event.timestamp}-${event.domain}-${event.source_ip}-${event.destination_ip}`;
}

function makePolicyEventId(event) {
  return `policy-${event.policy_type}-${event.timestamp}-${event.domain}-${event.source_ip}`;
}

function makeBlockedEventId(event) {
  return `blocked-${event.timestamp}-${event.domain}-${event.protocol}-${event.source_ip}-${event.destination_ip}`;
}

function makeFirewallActionId(event) {
  return `firewall-${event.timestamp}-${event.domain}-${event.action}-${event.backend}`;
}

function makeThreatEventId(event) {
  return `threat-${event.timestamp}-${event.domain}-${event.category}-${event.severity}`;
}

function makeSecurityIncidentId(event) {
  return `security-${event.timestamp}-${event.domain}-${event.score}-${event.category}`;
}

function makeFeedUpdateId(event) {
  return `feed-${event.timestamp}-${event.message}-${event.indicators_written || event.indicators_loaded || 0}`;
}

function getEventKey(row) {
  return row.id || `${row.timestamp}-${row.domain}-${row.sourceIp || row.source_ip || ''}-${row.destinationIp || row.destination_ip || ''}`;
}

function prependUnique(rows, nextRow, maxRows) {
  const nextKey = getEventKey(nextRow);
  const filtered = rows.filter((row) => getEventKey(row) !== nextKey);
  return [nextRow, ...filtered].slice(0, maxRows);
}

function prependManyUnique(rows, nextRows, maxRows) {
  if (!nextRows.length) {
    return rows;
  }

  const nextKeys = new Set();
  const dedupedNextRows = [];

  for (const row of nextRows) {
    const key = getEventKey(row);
    if (nextKeys.has(key)) {
      continue;
    }
    nextKeys.add(key);
    dedupedNextRows.push(row);
  }

  const filteredRows = rows.filter((row) => !nextKeys.has(getEventKey(row)));
  return [...dedupedNextRows.reverse(), ...filteredRows].slice(0, maxRows);
}

export default function useDashboardData() {
  const [state, setState] = useState({
    events: [],
    policyEvents: [],
    blockedEvents: [],
    firewallActions: [],
    threatFeed: [],
    threatEvents: [],
    securityOverview: null,
    securityIncidents: [],
    threatFeeds: null,
    feedUpdates: [],
    stats: null,
    blockStats: null,
    threatStats: null,
    domains: [],
    blockedDomains: [],
    firewallStatus: null,
    firewallRules: [],
    loading: true,
    error: null,
    lastUpdated: null,
    liveStatus: 'disconnected',
    latestBlockedEvent: null,
    latestFirewallAction: null,
    latestThreatEvent: null,
    latestSecurityIncident: null,
    latestFeedUpdate: null,
  });

  const trafficQueueRef = useRef([]);
  const policyQueueRef = useRef([]);
  const flushHandleRef = useRef(null);

  function flushQueuedUpdates() {
    flushHandleRef.current = null;

    const queuedTraffic = trafficQueueRef.current;
    const queuedPolicies = policyQueueRef.current;
    trafficQueueRef.current = [];
    policyQueueRef.current = [];

    if (!queuedTraffic.length && !queuedPolicies.length) {
      return;
    }

    setState((current) => ({
      ...current,
      events: prependManyUnique(current.events, queuedTraffic, MAX_EVENTS),
      policyEvents: prependManyUnique(current.policyEvents, queuedPolicies, MAX_POLICY_EVENTS),
      lastUpdated: new Date().toISOString(),
    }));
  }

  function scheduleFlush() {
    if (flushHandleRef.current !== null) {
      return;
    }

    if (typeof window !== 'undefined' && typeof window.requestAnimationFrame === 'function') {
      flushHandleRef.current = window.requestAnimationFrame(flushQueuedUpdates);
      return;
    }

    flushHandleRef.current = window.setTimeout(flushQueuedUpdates, 0);
  }

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    async function load() {
      try {
        const data = await fetchDashboardData(controller.signal);
        if (!active) return;
        setState((current) => ({
          ...current,
          events: (data.events || []).map(normalizeEvent),
          policyEvents: (data.policyEvents || []).map(normalizePolicyEvent),
          blockedEvents: (data.blockedEvents || []).map(normalizeBlockedEvent),
          firewallActions: (data.firewallActions || []).map(normalizeFirewallAction),
          threatFeed: (data.threats || []).map((item) => ({ ...item })),
          threatEvents: (data.threatEvents || []).map(normalizeThreatEvent),
          securityOverview: data.securityOverview || null,
          securityIncidents: (data.securityIncidents || []).map(normalizeSecurityIncident),
          threatFeeds: data.threatFeeds || null,
          feedUpdates: (data.threatFeeds?.updates || []).map(normalizeFeedUpdate),
          stats: data.stats,
          blockStats: data.blockStats,
          threatStats: data.threatStats,
          domains: data.domains || [],
          blockedDomains: data.blockedDomains || [],
          firewallStatus: data.firewallStatus || null,
          firewallRules: data.firewallRules || [],
          loading: false,
          error: null,
          lastUpdated: new Date().toISOString(),
          latestBlockedEvent: (data.blockedEvents || []).length ? normalizeBlockedEvent(data.blockedEvents[0]) : current.latestBlockedEvent,
          latestFirewallAction: (data.firewallActions || []).length ? normalizeFirewallAction(data.firewallActions[0]) : current.latestFirewallAction,
          latestThreatEvent: (data.threatEvents || []).length ? normalizeThreatEvent(data.threatEvents[0]) : current.latestThreatEvent,
          latestSecurityIncident: (data.securityIncidents || []).length ? normalizeSecurityIncident(data.securityIncidents[0]) : current.latestSecurityIncident,
          latestFeedUpdate: (data.threatFeeds?.updates || []).length ? normalizeFeedUpdate(data.threatFeeds.updates[0]) : current.latestFeedUpdate,
        }));
      } catch (error) {
        if (!active || error.name === 'AbortError') return;
        setState((current) => ({
          ...current,
          loading: false,
          error: error.message || 'Unable to load dashboard data',
        }));
      }
    }

    load();
    const closeLiveStream = createLiveDashboardStream({
      onTrafficEvent: (event) => {
        const normalized = normalizeEvent({
          id: makeTrafficEventId(event),
          timestamp: event.timestamp,
          event_type: event.type,
          domain: event.domain,
          source_ip: event.source_ip,
          destination_ip: event.destination_ip,
          protocol: event.protocol || '',
        });
        trafficQueueRef.current.push(normalized);
        scheduleFlush();
      },
      onPolicyEvent: (event) => {
        const normalized = normalizePolicyEvent({
          id: makePolicyEventId(event),
          timestamp: event.timestamp,
          domain: event.domain,
          policy_type: event.policy_type,
          source_ip: event.source_ip,
        });
        policyQueueRef.current.push(normalized);
        scheduleFlush();
      },
      onBlockedEvent: (event) => {
        const normalized = normalizeBlockedEvent({
          id: makeBlockedEventId(event),
          timestamp: event.timestamp,
          domain: event.domain,
          protocol: event.protocol || '',
          source_ip: event.source_ip,
          destination_ip: event.destination_ip,
          reason: event.reason || '',
        });
        setState((current) => ({
          ...current,
          blockedEvents: prependUnique(current.blockedEvents, normalized, MAX_BLOCKED_EVENTS),
          latestBlockedEvent: normalized,
          lastUpdated: new Date().toISOString(),
        }));
      },
      onFirewallAction: (event) => {
        const normalized = normalizeFirewallAction({
          id: makeFirewallActionId(event),
          timestamp: event.timestamp,
          domain: event.domain,
          action: event.action,
          backend: event.backend,
          status: event.status,
          reason: event.reason,
        });

        setState((current) => {
          const nextRules = [...current.firewallRules];
          const normalizedDomain = normalized.domain;
          if (normalized.action === 'BLOCK') {
            if (!nextRules.includes(normalizedDomain)) {
              nextRules.unshift(normalizedDomain);
            }
          } else if (normalized.action === 'UNBLOCK') {
            const index = nextRules.indexOf(normalizedDomain);
            if (index >= 0) {
              nextRules.splice(index, 1);
            }
          }

          return {
            ...current,
            firewallActions: prependUnique(current.firewallActions, normalized, MAX_FIREWALL_ACTIONS),
            firewallRules: nextRules,
            firewallStatus: {
              ...(current.firewallStatus || {}),
              backend: normalized.backend || current.firewallStatus?.backend || 'Mock',
              health: normalized.status === 'FAILED' ? 'Degraded' : 'Healthy',
              active_rules: nextRules.length,
              last_action: normalized.action,
              last_domain: normalized.domain,
              last_status: normalized.status,
            },
            latestFirewallAction: normalized,
            lastUpdated: new Date().toISOString(),
          };
        });
      },
      onThreatEvent: (event) => {
        const normalized = normalizeThreatEvent({
          id: makeThreatEventId(event),
          timestamp: event.timestamp,
          domain: event.domain,
          category: event.category,
          severity: event.severity,
          description: event.description,
          protocol: event.protocol || '',
          source_ip: event.source_ip,
          destination_ip: event.destination_ip,
        });

        setState((current) => ({
          ...current,
          threatEvents: prependUnique(current.threatEvents, normalized, MAX_THREAT_EVENTS),
          latestThreatEvent: normalized,
          lastUpdated: new Date().toISOString(),
        }));
      },
      onSecurityAnalysis: (event) => {
        const normalized = normalizeSecurityIncident({
          id: makeSecurityIncidentId(event),
          timestamp: event.timestamp,
          domain: event.domain,
          source_ip: event.source_ip,
          destination_ip: event.destination_ip,
          protocol: event.protocol || '',
          event_type: event.event_type,
          category: event.category,
          severity: event.severity,
          confidence: event.confidence,
          score: event.score,
          explanation: event.explanation,
          recommendation: event.recommendation,
        });

        setState((current) => ({
          ...current,
          securityIncidents: prependUnique(current.securityIncidents, normalized, MAX_SECURITY_INCIDENTS),
          securityOverview: current.securityOverview ? {
            ...current.securityOverview,
            latest_score: normalized.score,
            total_incidents_today: (current.securityOverview.total_incidents_today || 0) + 1,
            critical_incidents: normalized.severity === 'CRITICAL' ? (current.securityOverview.critical_incidents || 0) + 1 : current.securityOverview.critical_incidents,
            high_incidents: normalized.severity === 'HIGH' ? (current.securityOverview.high_incidents || 0) + 1 : current.securityOverview.high_incidents,
          } : current.securityOverview,
          latestSecurityIncident: normalized,
          lastUpdated: new Date().toISOString(),
        }));
      },
      onFeedUpdate: (event) => {
        const normalized = normalizeFeedUpdate({
          id: makeFeedUpdateId(event),
          timestamp: event.timestamp,
          source: 'registry',
          status: 'REFRESHED',
          sources_checked: event.sources_checked,
          indicators_loaded: event.indicators_written,
          message: event.message,
        });

        setState((current) => ({
          ...current,
          feedUpdates: prependUnique(current.feedUpdates, normalized, MAX_FEED_UPDATES),
          threatFeeds: current.threatFeeds ? {
            ...current.threatFeeds,
            last_update: normalized.timestamp,
            status: normalized.status,
            health: normalized.status === 'REFRESHED' ? 'Healthy' : 'Degraded',
          } : current.threatFeeds,
          latestFeedUpdate: normalized,
          lastUpdated: new Date().toISOString(),
        }));
      },
      onStatusChange: (liveStatus) => {
        setState((current) => ({ ...current, liveStatus }));
      },
    });

    return () => {
      active = false;
      controller.abort();
      if (flushHandleRef.current !== null && typeof window !== 'undefined') {
        if (typeof window.cancelAnimationFrame === 'function') {
          window.cancelAnimationFrame(flushHandleRef.current);
        } else {
          clearTimeout(flushHandleRef.current);
        }
      }
      closeLiveStream();
    };
  }, []);

  const refetch = async () => {
    try {
      const data = await fetchDashboardData();
      setState((current) => ({
        ...current,
        events: (data.events || []).map(normalizeEvent),
        policyEvents: (data.policyEvents || []).map(normalizePolicyEvent),
        blockedEvents: (data.blockedEvents || []).map(normalizeBlockedEvent),
        firewallActions: (data.firewallActions || []).map(normalizeFirewallAction),
        threatFeed: (data.threats || []).map((item) => ({ ...item })),
        threatEvents: (data.threatEvents || []).map(normalizeThreatEvent),
        securityOverview: data.securityOverview || null,
        securityIncidents: (data.securityIncidents || []).map(normalizeSecurityIncident),
        threatFeeds: data.threatFeeds || null,
        feedUpdates: (data.threatFeeds?.updates || []).map(normalizeFeedUpdate),
        stats: data.stats,
        blockStats: data.blockStats,
        threatStats: data.threatStats,
        domains: data.domains || [],
        blockedDomains: data.blockedDomains || [],
        firewallStatus: data.firewallStatus || null,
        firewallRules: data.firewallRules || [],
        loading: false,
        error: null,
        lastUpdated: new Date().toISOString(),
        latestBlockedEvent: (data.blockedEvents || []).length ? normalizeBlockedEvent(data.blockedEvents[0]) : current.latestBlockedEvent,
        latestFirewallAction: (data.firewallActions || []).length ? normalizeFirewallAction(data.firewallActions[0]) : current.latestFirewallAction,
        latestThreatEvent: (data.threatEvents || []).length ? normalizeThreatEvent(data.threatEvents[0]) : current.latestThreatEvent,
        latestSecurityIncident: (data.securityIncidents || []).length ? normalizeSecurityIncident(data.securityIncidents[0]) : current.latestSecurityIncident,
        latestFeedUpdate: (data.threatFeeds?.updates || []).length ? normalizeFeedUpdate(data.threatFeeds.updates[0]) : current.latestFeedUpdate,
      }));
    } catch {
      // ignore
    }
  };

  return useMemo(() => ({ ...state, refetch }), [state, refetch]);
}
