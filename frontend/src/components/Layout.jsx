import Sidebar from './Sidebar';
import Header from './Header';

export default function Layout({ activePage, onNavigate, search, onSearchChange, systemStatus, liveStatus, children }) {
  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900">
      <Sidebar activePage={activePage} onNavigate={onNavigate} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Header activePage={activePage} search={search} onSearchChange={onSearchChange} systemStatus={systemStatus} liveStatus={liveStatus} />
        <main className="min-w-0 flex-1 px-4 py-6 md:px-6 lg:px-8">{children}</main>
      </div>
    </div>
  );
}
