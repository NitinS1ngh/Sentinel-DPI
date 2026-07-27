import SectionCard from '../components/SectionCard';
import StatusPill from '../components/StatusPill';
import { APP_VERSION, DEFAULT_INTERFACE } from '../config';

export default function SettingsPage({ systemStatus, loading }) {
  const apiTone = systemStatus === 'Healthy' ? 'success' : systemStatus === 'Loading' ? 'neutral' : 'danger';

  return (
    <div className="grid gap-6 xl:grid-cols-2">
      <SectionCard title="System" description="Current runtime and connection information.">
        <div className="space-y-4">
          <SettingRow label="Capture Interface" value={DEFAULT_INTERFACE} />
          <SettingRow label="Database Status" value="Connected" tone="success" />
          <SettingRow label="API Status" value={loading ? 'Connecting' : 'Online'} tone={apiTone} />
          <SettingRow label="Version" value={APP_VERSION} />
        </div>
      </SectionCard>

      <SectionCard title="Capture Notes" description="Operational details for the local monitoring setup.">
        <div className="space-y-3 text-sm leading-6 text-slate-600">
          <p>Sentinel DPI is optimized for local traffic visibility on macOS.</p>
          <p>The dashboard uses the REST API backend and refreshes automatically.</p>
          <p>When running outside of sudo, packet capture and database writes may be restricted by macOS permissions.</p>
        </div>
      </SectionCard>
    </div>
  );
}

function SettingRow({ label, value, tone = 'neutral' }) {
  return (
    <div className="flex items-center justify-between rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
      <div>
        <div className="text-sm font-medium text-slate-900">{label}</div>
      </div>
      <div className="flex items-center gap-2">
        <StatusPill tone={tone}>{value}</StatusPill>
      </div>
    </div>
  );
}
