import { API_BASE } from '../config';

async function requestJSON(path, signal) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      Accept: 'application/json',
    },
    signal,
  });

  if (!response.ok) {
    const error = new Error(`Request failed with status ${response.status}`);
    error.status = response.status;
    throw error;
  }

  return response.json();
}

async function postJSON(path) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const error = new Error(`Request failed with status ${response.status}`);
    error.status = response.status;
    throw error;
  }

  return response.json();
}

export async function fetchDashboardData(signal) {
  const [events, stats, domains, policyEvents, blockedEvents, blockStats, blockedDomains, firewallStatus, firewallRules, firewallActions, threats, threatEvents, threatStats, securityOverview, securityIncidents, threatFeeds] = await Promise.all([
    requestJSON('/events', signal),
    requestJSON('/stats', signal),
    requestJSON('/domains', signal),
    requestJSON('/policy-events', signal),
    requestJSON('/blocked-events', signal),
    requestJSON('/block-stats', signal),
    requestJSON('/blocked-domains', signal),
    requestJSON('/firewall/status', signal),
    requestJSON('/firewall/rules', signal),
    requestJSON('/firewall/actions', signal),
    requestJSON('/threats', signal),
    requestJSON('/threat-events', signal),
    requestJSON('/threat-stats', signal),
    requestJSON('/security/overview', signal),
    requestJSON('/security/incidents', signal),
    requestJSON('/threat-feeds', signal),
  ]);

  return {
    events,
    stats,
    domains,
    policyEvents,
    blockedEvents,
    blockStats,
    blockedDomains,
    firewallStatus,
    firewallRules,
    firewallActions,
    threats,
    threatEvents,
    threatStats,
    securityOverview,
    securityIncidents,
    threatFeeds,
  };
}

export function refreshThreatFeeds() {
  return postJSON('/threat-feeds/refresh');
}

export async function blockDomain(domain) {
  const response = await fetch(`${API_BASE}/firewall/block`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ domain }),
  });
  if (!response.ok) {
    throw new Error(`Failed to block domain (status ${response.status})`);
  }
  return response.json();
}
