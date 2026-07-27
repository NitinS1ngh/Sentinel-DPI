export default function SectionCard({ title, description, action, children, className = '' }) {
  return (
    <section className={`rounded-2xl border border-slate-200 bg-white shadow-soft ${className}`}>
      {(title || description || action) && (
        <div className="flex items-start justify-between gap-4 border-b border-slate-100 px-5 py-4">
          <div>
            {title ? <h2 className="text-sm font-semibold tracking-tight text-slate-900">{title}</h2> : null}
            {description ? <p className="mt-1 text-sm leading-6 text-slate-500">{description}</p> : null}
          </div>
          {action ? <div>{action}</div> : null}
        </div>
      )}
      <div className="px-5 py-5">{children}</div>
    </section>
  );
}
