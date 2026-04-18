import { useState } from 'react';

interface SBOMEntry {
  name: string;
  version: string;
  type: 'direct' | 'transitive';
  license: string;
  language: string;
  cves: CVEEntry[];
  health: 'healthy' | 'outdated' | 'vulnerable';
}

interface CVEEntry {
  id: string;
  cvss: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  patchedIn?: string;
}

const DEMO_SBOM: SBOMEntry[] = [
  { name: 'okhttp3', version: '4.9.3', type: 'direct', license: 'Apache-2.0', language: 'Kotlin', cves: [{ id: 'CVE-2023-3635', cvss: 7.5, severity: 'high', description: 'HTTP request smuggling via malformed headers', patchedIn: '4.11.0' }], health: 'vulnerable' },
  { name: 'retrofit', version: '2.9.0', type: 'direct', license: 'Apache-2.0', language: 'Kotlin', cves: [], health: 'healthy' },
  { name: 'glide', version: '4.12.0', type: 'direct', license: 'BSD-3', language: 'Kotlin', cves: [{ id: 'CVE-2023-2305', cvss: 5.4, severity: 'medium', description: 'Path traversal in image loading', patchedIn: '4.14.2' }], health: 'outdated' },
  { name: 'room-runtime', version: '2.5.2', type: 'direct', license: 'Apache-2.0', language: 'Kotlin', cves: [], health: 'healthy' },
  { name: 'firebase-analytics', version: '21.3.0', type: 'direct', license: 'Proprietary', language: 'Kotlin', cves: [], health: 'healthy' },
  { name: 'facebook-sdk', version: '14.1.0', type: 'direct', license: 'Proprietary', language: 'Kotlin', cves: [{ id: 'CVE-2023-3781', cvss: 9.1, severity: 'critical', description: 'Data exfiltration via SDK event logging', patchedIn: '16.1.0' }], health: 'vulnerable' },
  { name: 'kotlinx-coroutines', version: '1.7.1', type: 'direct', license: 'Apache-2.0', language: 'Kotlin', cves: [], health: 'healthy' },
  { name: 'gson', version: '2.10.1', type: 'direct', license: 'Apache-2.0', language: 'Java', cves: [], health: 'healthy' },
  { name: 'okio', version: '3.3.0', type: 'transitive', license: 'Apache-2.0', language: 'Kotlin', cves: [], health: 'healthy' },
  { name: 'androidx-core', version: '1.10.1', type: 'direct', license: 'Apache-2.0', language: 'Kotlin', cves: [], health: 'outdated' },
  { name: 'material-components', version: '1.9.0', type: 'direct', license: 'Apache-2.0', language: 'Kotlin', cves: [], health: 'healthy' },
  { name: 'leakcanary', version: '2.12', type: 'direct', license: 'Apache-2.0', language: 'Kotlin', cves: [], health: 'healthy' },
];

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
};

const HEALTH_STYLES: Record<string, string> = {
  healthy: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  outdated: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  vulnerable: 'bg-red-500/20 text-red-400 border-red-500/30',
};

const HEALTH_ICONS: Record<string, string> = { healthy: '✅', outdated: '⚠️', vulnerable: '🚨' };

export default function SBOMPage() {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<'all' | 'direct' | 'transitive'>('all');
  const [healthFilter, setHealthFilter] = useState<string>('all');

  const allCVEs = DEMO_SBOM.flatMap((e) => e.cves.map((c) => ({ ...c, component: e.name })));
  const totalComponents = DEMO_SBOM.length;
  const vulnerableComponents = DEMO_SBOM.filter((e) => e.health === 'vulnerable').length;
  const outdatedComponents = DEMO_SBOM.filter((e) => e.health === 'outdated').length;
  const directCount = DEMO_SBOM.filter((e) => e.type === 'direct').length;
  const transitiveCount = DEMO_SBOM.filter((e) => e.type === 'transitive').length;

  const filtered = DEMO_SBOM.filter((e) => {
    if (typeFilter !== 'all' && e.type !== typeFilter) return false;
    if (healthFilter !== 'all' && e.health !== healthFilter) return false;
    if (search && !e.name.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">📦 Software Bill of Materials</h1>
        <p className="text-slate-400 text-sm mt-1">Component inventory, vulnerabilities, and license compliance</p>
      </div>

      {/* Health Summary */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 text-center">
          <p className="text-2xl font-bold text-white">{totalComponents}</p>
          <p className="text-xs text-slate-400">Components</p>
        </div>
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 text-center">
          <p className="text-2xl font-bold text-sky-400">{directCount}</p>
          <p className="text-xs text-slate-400">Direct</p>
        </div>
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 text-center">
          <p className="text-2xl font-bold text-slate-400">{transitiveCount}</p>
          <p className="text-xs text-slate-400">Transitive</p>
        </div>
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-center">
          <p className="text-2xl font-bold text-red-400">{vulnerableComponents}</p>
          <p className="text-xs text-red-400">Vulnerable</p>
        </div>
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 text-center">
          <p className="text-2xl font-bold text-yellow-400">{outdatedComponents}</p>
          <p className="text-xs text-yellow-400">Outdated</p>
        </div>
      </div>

      {/* CVE Alerts */}
      {allCVEs.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold text-white mb-3">🚨 CVE Alerts</h2>
          <div className="space-y-2">
            {allCVEs.map((cve) => (
              <div key={cve.id} className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-sm text-sky-400">{cve.id}</span>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium border ${SEVERITY_STYLES[cve.severity]}`}>{cve.severity}</span>
                    <span className="text-xs text-slate-500">CVSS {cve.cvss}</span>
                  </div>
                  <p className="text-sm text-slate-300">{cve.description}</p>
                  <p className="text-xs text-slate-500 mt-1">Component: <span className="text-slate-400">{cve.component}</span>{cve.patchedIn && <> · Patch: <span className="text-emerald-400">{cve.patchedIn}</span></>}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Library Inventory */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold text-white">📚 Library Inventory</h2>
          <div className="flex gap-2">
            <input type="text" placeholder="Search libraries..." value={search} onChange={(e) => setSearch(e.target.value)} className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-300 placeholder-slate-500 w-48" />
            <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value as 'all' | 'direct' | 'transitive')} className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-300">
              <option value="all">All types</option>
              <option value="direct">Direct</option>
              <option value="transitive">Transitive</option>
            </select>
            <select value={healthFilter} onChange={(e) => setHealthFilter(e.target.value)} className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-300">
              <option value="all">All health</option>
              <option value="healthy">Healthy</option>
              <option value="outdated">Outdated</option>
              <option value="vulnerable">Vulnerable</option>
            </select>
          </div>
        </div>
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700 text-slate-400 text-xs uppercase">
                <th className="px-4 py-3 text-left">Component</th>
                <th className="px-4 py-3 text-left">Version</th>
                <th className="px-4 py-3 text-left">Type</th>
                <th className="px-4 py-3 text-left">Language</th>
                <th className="px-4 py-3 text-left">License</th>
                <th className="px-4 py-3 text-center">CVEs</th>
                <th className="px-4 py-3 text-left">Health</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((e) => (
                <tr key={e.name} className="border-b border-slate-700/50 hover:bg-slate-700/20">
                  <td className="px-4 py-3 text-slate-200 font-medium">{e.name}</td>
                  <td className="px-4 py-3 text-slate-400 font-mono text-xs">{e.version}</td>
                  <td className="px-4 py-3"><span className={`text-xs px-2 py-0.5 rounded ${e.type === 'direct' ? 'bg-sky-500/20 text-sky-400' : 'bg-slate-600/50 text-slate-400'}`}>{e.type}</span></td>
                  <td className="px-4 py-3 text-slate-400 text-xs">{e.language}</td>
                  <td className="px-4 py-3 text-slate-400 text-xs">{e.license}</td>
                  <td className="px-4 py-3 text-center">{e.cves.length > 0 ? <span className="text-red-400 font-medium">{e.cves.length}</span> : <span className="text-slate-500">0</span>}</td>
                  <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs font-medium border ${HEALTH_STYLES[e.health]}`}>{HEALTH_ICONS[e.health]} {e.health}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}