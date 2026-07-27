const ICONS = {
  dns: (
    <path d="M4 12a8 8 0 1 1 16 0A8 8 0 0 1 4 12Zm8-5v10M7 12h10" strokeLinecap="round" strokeLinejoin="round" />
  ),
  tls: (
    <path d="M8 11V8a4 4 0 1 1 8 0v3m-9 0h10a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1v-5a1 1 0 0 1 1-1Z" strokeLinecap="round" strokeLinejoin="round" />
  ),
  domain: (
    <path d="M12 3a9 9 0 1 0 9 9" strokeLinecap="round" strokeLinejoin="round" />
  ),
  hour: (
    <path d="M12 8v5l3 2m5-3a8 8 0 1 1-16 0 8 8 0 0 1 16 0Z" strokeLinecap="round" strokeLinejoin="round" />
  ),
};

export default function StatCard({ label, value, trend, icon = 'domain', tone = 'neutral' }) {
  const accentClass = tone === 'accent' ? 'text-brand-700' : 'text-slate-600';
  const trendClass = trend?.startsWith('-') ? 'text-rose-600' : 'text-emerald-600';

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-soft">
      <div className="flex items-center justify-between gap-3">
        <div className={`inline-flex h-9 w-9 items-center justify-center rounded-xl bg-slate-100 ${accentClass}`}>
          <svg viewBox="0 0 24 24" className="h-4 w-4 fill-none stroke-current stroke-[1.75]">
            {ICONS[icon]}
          </svg>
        </div>
        {trend ? <span className={`text-xs font-medium ${trendClass}`}>{trend}</span> : null}
      </div>
      <div className="mt-4">
        <p className="text-sm text-slate-500">{label}</p>
        <p className="mt-1 text-2xl font-semibold tracking-tight text-slate-900">{value}</p>
      </div>
    </div>
  );
}
