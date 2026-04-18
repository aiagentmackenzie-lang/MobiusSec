import { useState } from 'react';
import type { DiffResult, Finding, Severity } from '../types';

const DEMO_DIFF: DiffResult = {
  added: [
    { id: 'AND-NET-003', title: 'Insecure HTTP redirect', description: 'HTTP→HTTPS redirect not enforced', severity: 'high' as Severity, masvs_category: 'NETWORK', platform: 'android' },
    { id: 'CRYPTO-002', title: 'Weak key size in RSA', description: 'RSA key size is 1024 bits', severity: 'medium' as Severity, masvs_category: 'CRYPTO', platform: 'android' },
    { id: 'PRIV-002', title: 'New tracking SDK added', description: 'AdColony SDK collects device data', severity: 'medium' as Severity, masvs_category: 'PRIVACY', platform: 'android' },
  ],
  removed: [
    { id: 'AND-BACKUP-001', title: 'Backup enabled', description: 'allowBackup=true', severity: 'medium' as Severity, masvs_category: 'STORAGE', platform: 'android' },
    { id: 'CODE-002', title: 'Stack trace exposure', description: 'Stack traces printed to console', severity: 'low' as Severity, masvs_category: 'CODE', platform: 'android' },
  ],
  severity_changes: [
    { id: 'SEC-001', title: 'Hardcoded API key', old_severity: 'critical' as Severity, new_severity: 'high' as Severity, direction: 'improved' as const },
    { id: 'AND-001', title: 'App is debuggable', old_severity: 'high' as Severity, new_severity: 'critical' as Severity, direction: 'worse' as const },
    { id: 'NET-002', title: 'No certificate pinning', old_severity: 'low' as Severity, new_severity: 'medium' as Severity, direction: 'worse' as const },
  ],
  verdict: 'REGRESSED — 3 new findings, 1 severity escalation to critical. Immediate action required.',
  summary: {
    v1: { total_findings: 10, critical: 2, high: 3, medium: 3 },
    v2: { total_findings: 11, critical: 3, high: 4, medium: 4 },
    delta: { total: 1, critical: 1, high: 1 },
  },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-500',
  high: 'text-orange-500',
  medium: 'text-yellow-500',
  low: 'text-blue-500',
  info: 'text-gray-400',
};

const SCANS = [
  { id: 'scan-001', label: 'v2.4.1 — Apr 15, 2026' },
  { id: 'scan-002', label: 'v2.3.0 — Mar 28, 2026' },
  { id: 'scan-003', label: 'v2.2.0 — Feb 14, 2026' },
  { id: 'scan-004', label: 'v2.1.0 — Jan 10, 2026' },
];

export default function DiffPage() {
  const [scan1, setScan1] = useState(SCANS[0].id);
  const [scan2, setScan2] = useState(SCANS[1].id);
  const diff = DEMO_DIFF;
  const verdictIsBad = diff.verdict.toLowerCase().includes('regress');

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">🔄 Version Comparison</h1>
        <p className="text-slate-400 text-sm mt-1">Compare findings between two scan versions</p>
      </div>

      {/* Scan Selector */}
      <div className="flex items-center gap-4">
        <div className="flex-1">
          <label className="block text-xs text-slate-400 mb-1">Newer Scan</label>
          <select value={scan1} onChange={(e) => setScan1(e.target.value)} className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-300">
            {SCANS.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
        </div>
        <span className="text-slate-500 mt-5">vs</span>
        <div className="flex-1">
          <label className="block text-xs text-slate-400 mb-1">Older Scan</label>
          <select value={scan2} onChange={(e) => setScan2(e.target.value)} className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-300">
            {SCANS.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
        </div>
      </div>

      {/* Verdict Card */}
      <div className={`border rounded-lg p-5 ${verdictIsBad ? 'bg-red-500/10 border-red-500/30' : 'bg-emerald-500/10 border-emerald-500/30'}`}>
        <div className="flex items-center gap-2 mb-2">
          <span className="text-xl">{verdictIsBad ? '🚨' : '✅'}</span>
          <span className={`text-lg font-bold ${verdictIsBad ? 'text-red-400' : 'text-emerald-400'}`}>{verdictIsBad ? 'Regressed' : 'Improved'}</span>
        </div>
        <p className="text-sm text-slate-300">{diff.verdict}</p>
      </div>

      {/* Side-by-side Summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-5">
          <h3 className="text-sm font-medium text-slate-400 mb-3">📊 Newer Version (v2)</h3>
          <div className="space-y-2">
            <div className="flex justify-between"><span className="text-slate-400">Total</span><span className="text-white font-bold">{diff.summary.v2.total_findings}</span></div>
            <div className="flex justify-between"><span className="text-red-400">Critical</span><span className="text-red-400 font-bold">{diff.summary.v2.critical}</span></div>
            <div className="flex justify-between"><span className="text-orange-400">High</span><span className="text-orange-400 font-bold">{diff.summary.v2.high}</span></div>
            <div className="flex justify-between"><span className="text-yellow-400">Medium</span><span className="text-yellow-400 font-bold">{diff.summary.v2.medium}</span></div>
          </div>
        </div>
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-5">
          <h3 className="text-sm font-medium text-slate-400 mb-3">📊 Older Version (v1)</h3>
          <div className="space-y-2">
            <div className="flex justify-between"><span className="text-slate-400">Total</span><span className="text-white font-bold">{diff.summary.v1.total_findings}</span></div>
            <div className="flex justify-between"><span className="text-red-400">Critical</span><span className="text-red-400 font-bold">{diff.summary.v1.critical}</span></div>
            <div className="flex justify-between"><span className="text-orange-400">High</span><span className="text-orange-400 font-bold">{diff.summary.v1.high}</span></div>
            <div className="flex justify-between"><span className="text-yellow-400">Medium</span><span className="text-yellow-400 font-bold">{diff.summary.v1.medium}</span></div>
          </div>
        </div>
      </div>

      {/* Delta */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-5">
        <h3 className="text-sm font-medium text-white mb-3">📈 Changes Summary</h3>
        <div className="flex gap-6">
          <div className="text-center">
            <p className={`text-2xl font-bold ${diff.summary.delta.total > 0 ? 'text-red-400' : 'text-emerald-400'}`}>{diff.summary.delta.total > 0 ? `+${diff.summary.delta.total}` : diff.summary.delta.total}</p>
            <p className="text-xs text-slate-400">Total</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-red-400">+{diff.summary.delta.critical}</p>
            <p className="text-xs text-slate-400">Critical</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-orange-400">+{diff.summary.delta.high}</p>
            <p className="text-xs text-slate-400">High</p>
          </div>
        </div>
      </div>

      {/* Severity Changes */}
      {diff.severity_changes.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold text-white mb-3">⚡ Severity Changes</h2>
          <div className="space-y-2">
            {diff.severity_changes.map((c) => (
              <div key={c.id} className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 flex items-center justify-between">
                <div>
                  <span className="font-mono text-xs text-sky-400">{c.id}</span>
                  <p className="text-sm text-slate-300">{c.title}</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-sm font-medium ${SEVERITY_COLORS[c.old_severity]}`}>{c.old_severity}</span>
                  <span className="text-slate-500">→</span>
                  <span className={`text-sm font-medium ${SEVERITY_COLORS[c.new_severity]}`}>{c.new_severity}</span>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium border ${c.direction === 'improved' ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' : 'bg-red-500/20 text-red-400 border-red-500/30'}`}>
                    {c.direction === 'improved' ? '↓ improved' : '↑ worse'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Added Findings */}
      {diff.added.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold text-white mb-3">➕ New Findings ({diff.added.length})</h2>
          <div className="space-y-2">
            {diff.added.map((f) => (
              <div key={f.id} className="bg-red-500/5 border border-red-500/20 rounded-lg p-4 flex items-center justify-between">
                <div>
                  <span className="font-mono text-xs text-sky-400">{f.id}</span>
                  <p className="text-sm text-slate-300">{f.title}</p>
                  <p className="text-xs text-slate-500">{f.description}</p>
                </div>
                <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_COLORS[f.severity]}`}>{f.severity}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Removed Findings */}
      {diff.removed.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold text-white mb-3">➖ Resolved Findings ({diff.removed.length})</h2>
          <div className="space-y-2">
            {diff.removed.map((f) => (
              <div key={f.id} className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-4 flex items-center justify-between">
                <div>
                  <span className="font-mono text-xs text-sky-400">{f.id}</span>
                  <p className="text-sm text-slate-300 line-through decoration-emerald-500">{f.title}</p>
                </div>
                <span className="px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">resolved</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}