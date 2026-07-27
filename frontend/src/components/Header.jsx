import { DEFAULT_INTERFACE } from '../config';
import StatusPill from './StatusPill';

export default function Header({ activePage, search, onSearchChange, systemStatus = 'Healthy', liveStatus = 'disconnected' }) {
  const streamConnected = liveStatus === 'connected';
  return (
    <header className="flex flex-col gap-4 border-b border-slate-200 bg-white px-5 py-4 md:flex-row md:items-center md:justify-between">
      <div>
        <div className="text-lg font-semibold tracking-tight text-slate-900">Sentinel DPI</div>
        <div className="mt-1 flex flex-wrap items-center gap-2 text-sm text-slate-500">
          <span>Current Interface: {DEFAULT_INTERFACE}</span>
          <span className="text-slate-300">•</span>
          <span>System Status:</span>
          <StatusPill tone={systemStatus === 'Healthy' ? 'success' : 'danger'}>{systemStatus}</StatusPill>
          <span className="text-slate-300">•</span>
          <span>Live Stream:</span>
          <StatusPill tone={streamConnected ? 'success' : 'danger'}>{streamConnected ? 'Connected' : 'Disconnected'}</StatusPill>
        </div>
      </div>

    </header>
  );
}
