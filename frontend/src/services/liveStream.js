import { API_BASE } from '../config';

export function createLiveDashboardStream({ onTrafficEvent, onPolicyEvent, onBlockedEvent, onFirewallAction, onThreatEvent, onSecurityAnalysis, onFeedUpdate, onStatusChange }) {
  const source = new EventSource(`${API_BASE}/stream`);

  source.onopen = () => {
    onStatusChange?.('connected');
  };

  source.onerror = () => {
    onStatusChange?.('disconnected');
  };

  source.addEventListener('sentinel', (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload.type === 'POLICY') {
        onPolicyEvent?.(payload);
        return;
      }
      if (payload.type === 'BLOCKED') {
        onBlockedEvent?.(payload);
        return;
      }
      if (payload.type === 'FIREWALL') {
        onFirewallAction?.(payload);
        return;
      }
      if (payload.type === 'THREAT') {
        onThreatEvent?.(payload);
        return;
      }
      if (payload.type === 'SECURITY_ANALYSIS') {
        onSecurityAnalysis?.(payload);
        return;
      }
      if (payload.type === 'SECURITY_FEEDS') {
        onFeedUpdate?.(payload);
        return;
      }
      if (payload.type === 'DNS' || payload.type === 'TLS') {
        onTrafficEvent?.(payload);
      }
    } catch {
      // Ignore malformed stream messages and keep the connection alive.
    }
  });

  return () => {
    source.close();
    onStatusChange?.('disconnected');
  };
}
