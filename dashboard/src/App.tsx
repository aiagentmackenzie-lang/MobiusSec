import { Routes, Route, NavLink, Outlet } from 'react-router-dom';
import DashboardPage from './pages/DashboardPage';
import ScanPage from './pages/ScanPage';
import FindingsPage from './pages/FindingsPage';
import MASVSPage from './pages/MASVSPage';
import PrivacyPage from './pages/PrivacyPage';
import SBOMPage from './pages/SBOMPage';
import DiffPage from './pages/DiffPage';
import BridgePage from './pages/BridgePage';

const navItems = [
  { to: '/', label: 'Dashboard', icon: '📊' },
  { to: '/scan', label: 'Scan', icon: '🔍' },
  { to: '/findings', label: 'Findings', icon: '⚠️' },
  { to: '/masvs', label: 'MASVS', icon: '🛡️' },
  { to: '/privacy', label: 'Privacy', icon: '🔒' },
  { to: '/sbom', label: 'SBOM', icon: '📦' },
  { to: '/diff', label: 'Diff', icon: '🔄' },
  { to: '/bridge', label: 'Bridge', icon: '🌉' },
];

export default function App() {
  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 bg-slate-900 border-r border-slate-700 flex flex-col">
        <div className="p-4 border-b border-slate-700">
          <h1 className="text-lg font-bold text-sky-400">🦞 MobiusSec</h1>
          <p className="text-xs text-slate-500">Mobile Security Platform</p>
        </div>
        <nav className="flex-1 p-2 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors ${
                  isActive
                    ? 'bg-sky-500/20 text-sky-400 font-medium'
                    : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                }`
              }
            >
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="p-3 border-t border-slate-700 text-xs text-slate-500">
          v0.1.0 · Both platforms · No escape
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto bg-slate-950">
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/scan" element={<ScanPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/masvs" element={<MASVSPage />} />
          <Route path="/privacy" element={<PrivacyPage />} />
          <Route path="/sbom" element={<SBOMPage />} />
          <Route path="/diff" element={<DiffPage />} />
          <Route path="/bridge" element={<BridgePage />} />
        </Routes>
      </main>
    </div>
  );
}