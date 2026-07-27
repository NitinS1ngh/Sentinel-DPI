import { parseTimestamp, formatDomain } from './format';

function sortByTimeDesc(a, b) {
  return parseTimestamp(b.timestamp).getTime() - parseTimestamp(a.timestamp).getTime();
}

export function normalizeEvent(event) {
  return {
    id: event.id,
    timestamp: event.timestamp,
    eventType: String(event.eventType || event.event_type || '').toUpperCase(),
    domain: formatDomain(event.domain || ''),
    sourceIp: event.sourceIp || event.source_ip || '',
    destinationIp: event.destinationIp || event.destination_ip || '',
    protocol: event.protocol || '',
  };
}

export function normalizePolicyEvent(event) {
  return {
    id: event.id,
    timestamp: event.timestamp,
    domain: formatDomain(event.domain || ''),
    policyType: String(event.policyType || event.policy_type || '').toUpperCase(),
    sourceIp: event.sourceIp || event.source_ip || '',
  };
}

export function normalizeBlockedEvent(event) {
  return {
    id: event.id,
    timestamp: event.timestamp,
    domain: formatDomain(event.domain || ''),
    protocol: event.protocol || '',
    sourceIp: event.sourceIp || event.source_ip || '',
    destinationIp: event.destinationIp || event.destination_ip || '',
    reason: event.reason || '',
  };
}

export function normalizeFirewallAction(event) {
  return {
    id: event.id,
    timestamp: event.timestamp,
    domain: formatDomain(event.domain || ''),
    action: String(event.action || '').toUpperCase(),
    backend: event.backend || '',
    status: String(event.status || '').toUpperCase(),
    reason: event.reason || '',
  };
}

export function normalizeThreatEvent(event) {
  return {
    id: event.id,
    timestamp: event.timestamp,
    domain: formatDomain(event.domain || ''),
    category: event.category || '',
    severity: String(event.severity || '').toUpperCase(),
    description: event.description || '',
    protocol: event.protocol || '',
    sourceIp: event.sourceIp || event.source_ip || '',
    destinationIp: event.destinationIp || event.destination_ip || '',
  };
}

export function normalizeSecurityIncident(event) {
  return {
    id: event.id,
    timestamp: event.timestamp,
    domain: formatDomain(event.domain || ''),
    sourceIp: event.sourceIp || event.source_ip || '',
    destinationIp: event.destinationIp || event.destination_ip || '',
    protocol: event.protocol || '',
    eventType: String(event.eventType || event.event_type || '').toUpperCase(),
    category: event.category || '',
    severity: String(event.severity || '').toUpperCase(),
    confidence: event.confidence || '',
    score: Number(event.score || 0),
    explanation: event.explanation || '',
    recommendation: event.recommendation || '',
  };
}

export function normalizeFeedUpdate(event) {
  return {
    id: event.id,
    timestamp: event.timestamp,
    source: event.source || '',
    status: event.status || '',
    sourcesChecked: Number(event.sources_checked || event.sourcesChecked || 0),
    indicatorsLoaded: Number(event.indicators_loaded || event.indicatorsLoaded || event.indicators_written || 0),
    message: event.message || '',
  };
}

export function buildSecurityTimeline(incidents, limit = 50) {
  return sortRecentEvents(incidents.map(normalizeSecurityIncident)).slice(0, limit);
}

export function buildSuspiciousDomains(incidents, limit = 10) {
  const map = new Map();
  incidents.map(normalizeSecurityIncident).forEach((incident) => {
    if (!incident.domain) return;
    const current = map.get(incident.domain) || {
      domain: incident.domain,
      maxScore: 0,
      count: 0,
      severity: incident.severity,
      category: incident.category,
      lastSeen: incident.timestamp,
    };
    current.count += 1;
    if (incident.score >= current.maxScore) {
      current.maxScore = incident.score;
      current.severity = incident.severity;
      current.category = incident.category;
      current.lastSeen = incident.timestamp;
    }
    map.set(incident.domain, current);
  });
  return Array.from(map.values()).sort((a, b) => b.maxScore - a.maxScore || b.count - a.count).slice(0, limit);
}

export function sortRecentEvents(events) {
  return [...events].sort(sortByTimeDesc);
}

export function filterEventsBySearch(events, search) {
  const query = search.trim().toLowerCase();
  if (!query) return events;
  return events.filter((event) => {
    const normalized = normalizeEvent(event);
    const haystack = `${normalized.domain} ${normalized.sourceIp} ${normalized.destinationIp} ${normalized.protocol} ${normalized.eventType}`.toLowerCase();
    return haystack.includes(query);
  });
}

export function countUniqueDomains(events) {
  return new Set(events.map((event) => event.domain).filter(Boolean)).size;
}

export function countEventsLastHour(events) {
  const cutoff = Date.now() - 60 * 60 * 1000;
  return events.filter((event) => parseTimestamp(event.timestamp).getTime() >= cutoff).length;
}

export function summarizeEvents(events) {
  const normalized = events.map(normalizeEvent);
  const dnsEvents = normalized.filter((event) => event.eventType === 'DNS');
  const tlsEvents = normalized.filter((event) => event.eventType === 'TLS');

  return {
    totalDns: dnsEvents.length,
    totalTls: tlsEvents.length,
    uniqueDomains: countUniqueDomains(normalized),
    lastHour: countEventsLastHour(normalized),
  };
}

export function countBlockedToday(events) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return events.filter((event) => parseTimestamp(event.timestamp).getTime() >= today.getTime()).length;
}

export function buildBlockedDomainRows(events) {
  const normalized = events.map(normalizeBlockedEvent);
  const map = new Map();

  normalized.forEach((event) => {
    if (!event.domain) return;
    if (!map.has(event.domain)) {
      map.set(event.domain, {
        domain: event.domain,
        count: 0,
        dnsCount: 0,
        tlsCount: 0,
        lastSeen: event.timestamp,
      });
    }

    const row = map.get(event.domain);
    row.count += 1;
    if (event.protocol === 'UDP') row.dnsCount += 1;
    if (event.protocol === 'TCP') row.tlsCount += 1;
    if (parseTimestamp(event.timestamp).getTime() > parseTimestamp(row.lastSeen).getTime()) {
      row.lastSeen = event.timestamp;
    }
  });

  return Array.from(map.values()).sort((a, b) => b.count - a.count || a.domain.localeCompare(b.domain));
}

export function summarizeBlockedEvents(events) {
  const normalized = events.map(normalizeBlockedEvent);
  const blockedRows = buildBlockedDomainRows(normalized);

  return {
    blockedToday: countBlockedToday(normalized),
    blockedDns: normalized.filter((event) => event.protocol === 'UDP').length,
    blockedTls: normalized.filter((event) => event.protocol === 'TCP').length,
    mostBlockedDomains: blockedRows,
  };
}

function countByLabel(items, getLabel) {
  const map = new Map();
  items.forEach((item) => {
    const label = getLabel(item);
    if (!label) return;
    map.set(label, (map.get(label) || 0) + 1);
  });
  return Array.from(map.entries()).map(([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

export function buildThreatCategoryRows(events) {
  const normalized = events.map(normalizeThreatEvent);
  return countByLabel(normalized, (event) => event.category);
}

export function buildThreatSeverityDistribution(events) {
  const normalized = events.map(normalizeThreatEvent);
  return countByLabel(normalized, (event) => event.severity);
}

export function buildTopThreatDomains(events, limit = 10) {
  const normalized = events.map(normalizeThreatEvent);
  const map = new Map();

  normalized.forEach((event) => {
    if (!event.domain) return;
    if (!map.has(event.domain)) {
      map.set(event.domain, {
        domain: event.domain,
        count: 0,
        category: event.category,
        severity: event.severity,
        lastSeen: event.timestamp,
      });
    }

    const row = map.get(event.domain);
    row.count += 1;
    if (parseTimestamp(event.timestamp).getTime() > parseTimestamp(row.lastSeen).getTime()) {
      row.lastSeen = event.timestamp;
      row.category = event.category || row.category;
      row.severity = event.severity || row.severity;
    }
  });

  return Array.from(map.values()).sort((a, b) => b.count - a.count || a.domain.localeCompare(b.domain)).slice(0, limit);
}

export function summarizeThreatEvents(events) {
  const normalized = events.map(normalizeThreatEvent);
  const severityDistribution = buildThreatSeverityDistribution(normalized);
  const categories = buildThreatCategoryRows(normalized);

  return {
    totalThreats: normalized.length,
    critical: normalized.filter((event) => event.severity === 'CRITICAL').length,
    high: normalized.filter((event) => event.severity === 'HIGH').length,
    medium: normalized.filter((event) => event.severity === 'MEDIUM').length,
    low: normalized.filter((event) => event.severity === 'LOW').length,
    severityDistribution,
    categories,
    topDomains: buildTopThreatDomains(normalized, 10),
  };
}

export function getRecentThreatEvents(events, limit = 50) {
  return sortRecentEvents(events.map(normalizeThreatEvent)).slice(0, limit);
}

export function buildMinuteSeries(events, minutes = 60) {
  const normalized = events.map(normalizeEvent);
  const now = Date.now();
  const buckets = new Map();

  for (let index = minutes - 1; index >= 0; index -= 1) {
    const bucketTime = new Date(now - index * 60 * 1000);
    bucketTime.setSeconds(0, 0);
    const key = bucketTime.getTime();
    buckets.set(key, {
      label: bucketTime.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' }),
      total: 0,
      dns: 0,
      tls: 0,
      minute: key,
    });
  }

  normalized.forEach((event) => {
    const time = parseTimestamp(event.timestamp).getTime();
    const minuteKey = Math.floor(time / 60000) * 60000;
    if (!buckets.has(minuteKey)) return;
    const bucket = buckets.get(minuteKey);
    bucket.total += 1;
    if (event.eventType === 'DNS') bucket.dns += 1;
    if (event.eventType === 'TLS') bucket.tls += 1;
  });

  return Array.from(buckets.values());
}

export function buildDomainRows(events) {
  const normalized = events.map(normalizeEvent);
  const map = new Map();

  normalized.forEach((event) => {
    if (!event.domain) return;
    if (!map.has(event.domain)) {
      map.set(event.domain, {
        domain: event.domain,
        count: 0,
        dnsCount: 0,
        tlsCount: 0,
        firstSeen: event.timestamp,
        lastSeen: event.timestamp,
      });
    }

    const row = map.get(event.domain);
    row.count += 1;
    if (event.eventType === 'DNS') row.dnsCount += 1;
    if (event.eventType === 'TLS') row.tlsCount += 1;

    if (parseTimestamp(event.timestamp).getTime() < parseTimestamp(row.firstSeen).getTime()) {
      row.firstSeen = event.timestamp;
    }
    if (parseTimestamp(event.timestamp).getTime() > parseTimestamp(row.lastSeen).getTime()) {
      row.lastSeen = event.timestamp;
    }
  });

  return Array.from(map.values()).sort((a, b) => b.count - a.count || a.domain.localeCompare(b.domain));
}

export function buildTopDomains(events, limit = 10) {
  return buildDomainRows(events).slice(0, limit);
}

export function buildMostActiveHour(events) {
  const normalized = events.map(normalizeEvent);
  const buckets = Array.from({ length: 24 }, (_, hour) => ({
    hour,
    label: `${hour % 12 === 0 ? 12 : hour % 12}${hour < 12 ? ' AM' : ' PM'}`,
    count: 0,
  }));

  normalized.forEach((event) => {
    const hour = parseTimestamp(event.timestamp).getHours();
    buckets[hour].count += 1;
  });

  return buckets;
}

export function buildEventDistribution(events) {
  const normalized = events.map(normalizeEvent);
  return [
    { name: 'DNS', value: normalized.filter((event) => event.eventType === 'DNS').length },
    { name: 'TLS', value: normalized.filter((event) => event.eventType === 'TLS').length },
  ];
}

export function calculateTrend(currentValue, previousValue) {
  if (!previousValue) return null;
  return ((currentValue - previousValue) / previousValue) * 100;
}

export function getRecentEvents(events, limit = 50) {
  return sortRecentEvents(events).slice(0, limit).map(normalizeEvent);
}
