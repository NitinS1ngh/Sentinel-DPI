export function parseTimestamp(value) {
  if (!value) return new Date(0);
  const normalized = String(value).replace(' ', 'T');
  const withZone = normalized.endsWith('Z') ? normalized : `${normalized}Z`;
  const date = new Date(withZone);
  return Number.isNaN(date.getTime()) ? new Date(0) : date;
}

export function formatTime(value) {
  return new Intl.DateTimeFormat('en-US', {
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
  }).format(parseTimestamp(value));
}

export function formatDateTime(value) {
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(parseTimestamp(value));
}

export function formatNumber(value) {
  return new Intl.NumberFormat('en-US').format(value || 0);
}

export function formatPercent(value) {
  if (!Number.isFinite(value)) return '—';
  const sign = value > 0 ? '+' : '';
  return `${sign}${value.toFixed(1)}%`;
}

export function formatDurationSince(value) {
  const diff = Date.now() - parseTimestamp(value).getTime();
  if (diff < 0) return 'just now';
  const minutes = Math.max(1, Math.round(diff / 60000));
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  return `${hours}h ago`;
}

export function formatDomain(domain) {
  if (!domain) return '';
  
  // 1. Check if the domain is a JSON-formatted mDNS service name
  if (domain.startsWith('{') && domain.includes('}')) {
    try {
      const jsonEnd = domain.indexOf('}') + 1;
      const jsonPart = domain.substring(0, jsonEnd);
      const rest = domain.substring(jsonEnd);
      const parsed = JSON.parse(jsonPart);
      
      let friendlyName = parsed.nm || parsed.name || '';
      let serviceType = rest;
      
      if (serviceType.startsWith('.')) serviceType = serviceType.substring(1);
      
      const cleanService = formatDomain(serviceType);
      if (friendlyName) {
        return `${friendlyName} (${cleanService})`;
      }
    } catch (e) {
      // Fall through if JSON parsing fails
    }
  }

  // 2. Map of common local/mDNS service types to human-readable strings
  const mdnsMap = {
    '_companion-link._tcp.local': 'Apple Continuity / Handoff',
    '_companion-link._udp.local': 'Apple Continuity / Handoff',
    '_airplay._tcp.local': 'Apple AirPlay',
    '_googlecast._tcp.local': 'Google Chromecast',
    '_spotify-connect._tcp.local': 'Spotify Connect',
    '_mi-connect._udp.local': 'Xiaomi Mi-Connect',
    '_sleep-proxy._udp.local': 'Apple Sleep Proxy',
    '_homekit._tcp.local': 'Apple HomeKit',
    '_homekit._udp.local': 'Apple HomeKit',
    '_smb._tcp.local': 'Local SMB File Share',
    '_afpovertcp._tcp.local': 'Apple File Share (AFP)',
    '_ssh._tcp.local': 'SSH Remote Access',
    '_sftp-ssh._tcp.local': 'SFTP File Transfer',
    '_http._tcp.local': 'Local Web Server (HTTP)',
    '_https._tcp.local': 'Local Web Server (HTTPS)',
    '_raop._tcp.local': 'Apple AirTunes Audio',
    '_printer._tcp.local': 'Network Printer',
    '_ipp._tcp.local': 'Network Printing (IPP)',
    '_ipps._tcp.local': 'Secure Network Printing',
    '_rdp._tcp.local': 'Remote Desktop',
    '_ftp._tcp.local': 'FTP Server',
    '_coap._udp.local': 'IoT CoAP Service',
    '_adb-tls-connect._tcp.local': 'Android Debug Bridge (ADB)',
  };

  // Check direct matches
  if (mdnsMap[domain]) {
    return mdnsMap[domain];
  }

  // Check suffix matches (e.g. devicename._companion-link._tcp.local)
  for (const [key, value] of Object.entries(mdnsMap)) {
    if (domain.endsWith(key)) {
      const prefix = domain.slice(0, -key.length - 1);
      const cleanPrefix = prefix.replace(/\\/g, '').replace(/^\.+|\.+$/g, '');
      return cleanPrefix ? `${cleanPrefix} (${value})` : value;
    }
  }

  // Fallback for general local/mDNS queries
  if (domain.endsWith('.local')) {
    let clean = domain.replace(/\\/g, '');
    if (clean.startsWith('_')) {
      clean = clean.replace(/^_+/, '').replace(/\._[a-zA-Z0-9_-]+/g, '');
    }
    return clean;
  }

  return domain;
}

