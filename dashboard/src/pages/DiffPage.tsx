import { useState } from 'react';
import type { DiffResult } from '../types';

const DEMO_DIFF: DiffResult = {
  added: [
    { id: 'V2-NET-003', title: 'Insecure WebSocket connection', description: 'ws:// used instead of wss://', severity: 'high', masvs_category: 'NETWORK', platform: 'android', file: 'SocketService.java' },
    { id: 'V2-CRYPTO-004', title: 'MD5 used for hashing', description: 'MD5 digest found in CryptoUtils', severity: 'medium', masvs_category: 'CRYPTO', platform: 'android', file: 'CryptoUtils.java' },
  ],
  removed: [
    { id: 'V1-DEBUG-001', title: 'App is debuggable', description: 'android:debuggable=true', severity: 'high', masvs_category: 'RESILIENCE', platform: 'android', file: 'AndroidManifest.xml' },
  ],
  severity_changes: [
    { id: 'V1-NET-001', title: 'Cleartext traffic allowed', old_severity: 'critical', new_severity: 'medium', direction: 'improved' },
    { id: 'V1-STORAGE-002', title: 'SharedPreferences plaintext', old_severity: 'medium', new_severity: 'high', direction: 'worse' },
  ],
  verdict: '🟡 MIXED — Some changes, review recommended',
  summary: {
    v1: { total_findings: 8, critical: 2, high: 3, medium: 2 },
    v2: { total_findings: 9, critical: 1, high: 3, medium: 4 },
    delta: { total: 1, critical: -1, high: 0 },
  },
};

export default function DiffPage() {
  const [diff] = useState<DiffResult>(DEMO_DIFF);
  const { verdict, summary, added, removed, severity_changes } = diff;

  const deltaClass = (val: number) => (val > 0 ? 'text-red-400' : val < 0 ? 'text-green-400' : 'text-slate-400');
  const deltaArrow = (val: number) => (val > 0 ? '↑' : val < 0 ? '↓' : '—');

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      <h1 className="text-2xl font-bold text-white">🔄 Diff Analysis</h1>
      <p className="text-sm text-slate-400">Compare two app versions for security changes.</p>

      {/* Version selector (demo) */}
      <div className="bg-slate-900 rounded-xl border border-slate-700 p-5">
        <div className="flex items-end gap-4">
          <div className="flex-1">
            <label className="block text-sm text-slate-400 mb-1">Version 1 (older)</label>
            <div className="bg-slate-800 border border-slate-600 rounded-lg px-4 py-2.5 text-white text-sm">
              📦 SecureApp v2.3.0
            </div>
          </div>
          <div className="text-slate-500 text-lg pb-2">→</div>
          <div className="flex-1">
            <label className="block text-sm text-slate-400 mb-1">Version 2 (newer)</label>
            <div className="bg-slate-800 border border-slate-600 rounded-lg px-4 py-2.5 text-white text-sm">
              📦 SecureApp v2.4.0
            </div>
          </div>
        </div>
      </div>

      {/* Verdict */}
      <div className={`rounded-xl border p-5 text-center ${verdict.includes('REGRESSION') ? 'bg-red-500/10 border-red-500/30' : verdict.includes('IMPROVED') ? 'bg-green-500/10 border-green-500/30' : verdict.includes('WARNING') ? 'bg-orange-500/10 border-orange-500/30' : 'bg-yellow-500/10 border-yellow-500/30'}`}>
        <div className="text-xl font-bold text-white">{verdict}</div>
      </div>

      {/* Comparison table */}
      <div className="bg-slate-900 rounded-xl border border-slate-700 p-5">
        <h2 className="text-lg font-semibold text-white mb-4">📊 Version Comparison</h2>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-slate-400 border-b border-slate-700">
              <th className="text-left py-2 px-3">Metric</th>
              <th className="text-right py-2 px-3">v2.3.0</th>
              <th className="text-right py-2 px-3">v2.4.0</th>
              <th className="text-right py-2 px-3">Delta</th>
            </tr>
          </thead>
          <tbody>
            <tr className="border-b border-slate-800">
              <td className="py-2 px-3 text-white">Total Findings</td>
              <td className="py-2 px-3 text-right text-white">{summary.v1.total_findings}</td>
              <td className="py-2 px-3 text-right text-white">{summary.v2.total_findings}</td>
              <td className={`py-2 px-3 text-right font-bold ${deltaClass(summary.delta.total)}`}>
                {deltaArrow(summary.delta.total)} {summary.delta.total > 0 ? '+' : ''}{summary.delta.total}
              </td>
            </tr>
            <tr className="border-b border-slate-800">
              <td className="py-2 px-3 text-white">Critical</td>
              <td className="py-2 px-3 text-right text-red-400">{summary.v1.critical}</td>
              <td className="py-2 px-3 text-right text-red-400">{summary.v2.critical}</td>
              <td className={`py-2 px-3 text-right font-bold ${deltaClass(summary.delta.critical)}`}>
                {deltaArrow(summary.delta.critical)} {summary.delta.critical > 0 ? '+' : ''}{summary.delta.critical}
              </td>
            </tr>
            <tr className="border-b border-slate-800">
              <td className="py-2 px-3 text-white">High</td>
              <td className="py-2 px-3 text-right text-orange-400">{summary.v1.high}</td>
              <td className="py-2 px-3 text-right text-orange-400">{summary.v2.high}</td>
              <td className={`py-2 px-3 text-right font-bold ${deltaClass(summary.delta.high)}`}>
                {deltaArrow(summary.delta.high)} {summary.delta.high > 0 ? '+' : ''}{summary.delta.high}
              </td>
            </tr>
            <tr>
              <td className="py-2 px-3 text-white">Medium</td>
              <td className="py-2 px-3 text-right text-yellow-400">{summary.v1.medium}</td>
              <td className="py-2 px-3 text-right text-yellow-400">{summary.v2.medium}</td>
              <td className="py-2 px-3 text-right text-slate-400">—</td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* New findings */}
      {added.length > 0 && (
        <div className="bg-slate-900 rounded-xl border border-red-500/30 p-5">
          <h2 className="text-lg font-semibold text-red-400 mb-3">🆕 New Findings ({added.length})</h2>
          <div className="space-y-2">
            {added.map((f) => (
              <div key={f.id} className="flex items-center gap-3 p-3 bg-red-500/5 rounded-lg">
                <span className="text-xs font-bold text-red-400">{f.severity.toUpperCase()}</span>
                <span className="text-white text-sm">{f.title}</span>
                <span className="text-slate-500 text-xs ml-auto">{f.masvs_category}</span>
                {f.file && <span className="text-slate-600 text-xs font-mono">{f.file}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Fixed findings */}
      {removed.length > 0 && (
        <div className="bg-slate-900 rounded-xl border border-green-500/30 p-5">
          <h2 className="text-lg font-semibold text-green-400 mb-3">✅ Fixed ({removed.length})</h2>
          <div className="space-y-2">
            {removed.map((f) => (
              <div key={f.id} className="flex items-center gap-3 p-3 bg-green-500/5 rounded-lg">
                <span className="text-xs font-bold text-green-400">RESOLVED</span>
                <span className="text-white text-sm">{f.title}</span>
                <span className="text-slate-500 text-xs ml-auto">{f.masvs_category}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Severity changes */}
      {severity_changes.length > 0 && (
        <div className="bg-slate-900 rounded-xl border border-slate-700 p-5">
          <h2 className="text-lg font-semibold text-white mb-3">🔄 Severity Changes ({severity_changes.length})</h2>
          <div className="space-y-2">
            {severity_changes.map((c) => (
              <div key={c.id} className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-lg">
                <span className="text-slate-400 text-sm">{c.id}</span>
                <span className="text-white text-sm">{c.title}</span>
                <div className="ml-auto flex items-center gap-2">
                  <span className={`text-xs font-bold ${c.old_severity === 'critical' ? 'text-red-400' : c.old_severity === 'high' ? 'text-orange-400' : 'text-yellow-400'}`}>
                    {c.old_severity.toUpperCase()}
                  </span>
                  <span className="text-slate-500">→</span>
                  <span className={`text-xs font-bold ${c.new_severity === 'critical' ? 'text-red-400' : c.new_severity === 'high' ? 'text-orange-400' : 'text-yellow-400'}`}>
                    {c.new_severity.toUpperCase()}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-xs ${c.direction === 'worse' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
                    {c.direction === 'worse' ? '⬆️ worsened' : '⬇️ improved'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}