import { APP_NAME } from '../config';

const ITEMS = [
  'Overview',
  'Live Traffic',
  'Raw Feed',
  'Statistics',
  'Policies',
  'Threat Intelligence',
  'Threat Feeds',
  'Blocked Events',
  'Firewall',
  'Settings',
];

export default function Sidebar({ activePage, onNavigate }) {
  return (
    <aside className="hidden min-h-screen w-64 shrink-0 border-r border-slate-200 bg-white/90 px-4 py-5 md:flex md:flex-col">
      <div className="flex items-center gap-3 px-2">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-slate-200 bg-slate-50 text-sm font-semibold text-slate-900">
          SD
        </div>
        <div>
          <div className="text-sm font-semibold tracking-tight text-slate-900">{APP_NAME}</div>
          <div className="text-xs text-slate-500">Local network monitoring</div>
        </div>
      </div>

      <nav className="mt-8 space-y-1">
        {ITEMS.map((item) => {
          const active = activePage === item;
          return (
            <button
              key={item}
              onClick={() => onNavigate(item)}
              className={`flex w-full items-center rounded-xl px-3 py-2.5 text-left text-sm font-medium transition-colors ${
                active ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
              }`}
            >
              {item}
            </button>
          );
        })}
      </nav>

      <div className="mt-8 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-600">
        <p className="font-medium text-slate-900">Sentinel DPI</p>
        <p className="mt-1 leading-6">Minimal local traffic visibility for DNS, TLS, and policy workflows.</p>
      </div>
    </aside>
  );
}
