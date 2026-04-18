import { useState, useEffect } from 'react';
import { api } from '../api/client';
import type { ScanResult, ScanStatus } from '../types';

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-500',
  high: 'text-orange-500',
  medium: 'text-yellow-500',
  low: 'text-blue-500',
  info: 'text-gray-400',
};

const SEVERITY_BG: Record<string, string> = {
  critical: 'bg-red-500/20 border-red-500/30',
  high: 'bg-orange-500/20 border-orange-500/30',
  medium: 'bg-yellow-500/20 border-yellow-500/30',
  low: 'bg-blue-500/20 border-blue-500/30',
  info: 'bg-gray-500/20 border-gray-500/30',
};

export default function DashboardPage() {
  const [latestScan, setLatestScan] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [status, setStatus] = useState<ScanStatus | null>(null);

  // Demo data for when no scan is running
  const demoResult: ScanResult = {
    app_path: '/demo/app.apk',
    platform: 'android',
    package_name: 'com.example.secureapp',
    app_name: 'SecureApp Demo',
    version: '2.4.1',
    findings: [
      { id: 'AND-001', title: 'App is debuggable', description: 'android:debuggable=true', severity: 'high', masvs_category: 'RESILIENCE', platform: 'android', file: 'AndroidManifest.xml', remediation: 'Set android:debuggable=false' },
      { id: 'AND-NET-001', title: 'Cleartext traffic allowed', description: 'usesCleartextTraffic=true', severity: 'critical', masvs_category: 'NETWORK', platform: 'android', file: 'AndroidManifest.xml', remediation: 'Disable cleartext traffic' },
      { id: 'AND-BACKUP-001', title: 'Backup enabled', description: 'allowBackup=true', severity: 'medium', masvs_category: 'STORAGE', platform: 'android', file: 'AndroidManifest.xml' },
      { id: 'SEC-001', title: 'Hardcoded API key', description: 'AWS key found in Config.java', severity: 'critical', masvs_category: 'CRYPTO', platform: 'android', file: 'Config.java', line: 42 },
      { id: 'AND-EXPORT-001', title: 'Exported activity without permission', description: 'com.example.DetailActivity', severity: 'high', masvs_category: 'PLATFORM', platform: 'android', file: 'AndroidManifest.xml' },
      { id: 'CODE-001', title: 'SQL injection risk', description: 'Raw query with string concatenation', severity: 'high', masvs_category: 'CODE', platform: 'android', file: 'DatabaseHelper.java', line: 87 },
      { id: 'PRIV-001', title: 'Excessive permissions', description: 'READ_CONTACTS, WRITE_CONTACTS, CAMERA', severity: 'medium', masvs_category: 'PRIVACY', platform: 'android', file: 'AndroidManifest.xml' },
      { id: 'NET-002', title: 'No certificate pinning', description: 'Network calls lack SSL pinning', severity: 'low', masvs_category: 'NETWORK', platform: 'android' },
      { id: 'INFO-001', title: 'Debug logging active', description: 'Log.d() calls in release build', severity: 'info', masvs_category: 'CODE', platform: 'android', file: 'MainActivity.java' },
      { id: 'STORAGE-002', title: 'SharedPreferences in plain text', description: 'Sensitive data in default SharedPreferences', severity: 'medium', masvs_category: 'STORAGE', platform: 'android', file: 'LoginActivity.java' },
    ],
    total_findings: 10,
    critical_count: 2,
    high_count: 3,
    medium_count: 3,
    low_count: 1,
    info_count: 1,
    scan_time_seconds: 4.2,
  };

  const result = latestScan || demoResult;

  const severityData = [
    { label: 'Critical', count: result.critical_count, color: 'bg-red-500', text: 'text-red-400' },
    { label: 'High', count: result.high_count, color: 'bg-orange-500', text: 'text-orange-400' },
    { label: 'Medium', count: result.medium_count, color: 'bg-yellow-500', text: 'text-yellow-400' },
    { label: 'Low', count: result.low_count, color: 'bg-blue-500', text: 'text-blue-400' },
    { label: 'Info', count: result.info_count, color: 'bg-gray-500', text: 'text-gray-400' },
  ];

  const platformIcon = result.platform === 'android' ? '🤖' : '🍎';

  // Category breakdown
  const categoryMap: Record<string, number> = {};
  result.findings.forEach((f) => {
    categoryMap[f.masvs_category] = (categoryMap[f.masvs_category] || 0) + 1;
  });
  const categories = Object.entries(categoryMap).sort((a, b) => b[1] - a[1]);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">{platformIcon} {result.app_name}</h1>
          <p className="text-sm text-slate-400 mt-1">
            {result.package_name} · v{result.version} · {result.platform.toUpperCase()} · Scanned in {result.scan_time_seconds.toFixed(1)}s
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="px-3 py-1 bg-sky-500/20 text-sky-400 rounded-full text-sm font-medium">
            {result.total_findings} findings
          </span>
        </div>
      </div>

      {/* Severity Stats */}
      <div className="grid grid-cols-5 gap-4">
        {severityData.map((s) => (
          <div key={s.label} className={`rounded-xl border p-4 ${SEVERITY_BG[s.label.toLowerCase()] || 'bg-slate-800 border-slate-700'}`}>
            <div className={`text-3xl font-bold ${s.text}`}>{s.count}</div>
            <div className="text-sm text-slate-400 mt-1">{s.label}</div>
            {s.count > 0 && (
              <div className="mt-2 h-1.5 rounded-full bg-slate-700 overflow-hidden">
                <div className={`h-full ${s.color} rounded-full`} style={{ width: `${(s.count / result.total_findings) * 100}%` }} />
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Two columns: MASVS + Category breakdown */}
      <div className="grid grid-cols-2 gap-6">
        {/* MASVS Compliance */}
        <div className="bg-slate-900 rounded-xl border border-slate-700 p-5">
          <h2 className="text-lg font-semibold text-white mb-4">🛡️ MASVS 2.0 Compliance</h2>
          <div className="space-y-3">
            {['STORAGE', 'CRYPTO', 'AUTH', 'NETWORK', 'PLATFORM', 'CODE', 'RESILIENCE', 'PRIVACY'].map((cat) => {
              const catCount = categoryMap[cat] || 0;
              const total = result.total_findings || 1;
              const pct = Math.max(0, 100 - (catCount / total) * 100);
              const color = pct >= 80 ? 'text-green-400' : pct >= 50 ? 'text-yellow-400' : 'text-red-400';
              const barColor = pct >= 80 ? 'bg-green-500' : pct >= 50 ? 'bg-yellow-500' : 'bg-red-500';
              return (
                <div key={cat}>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="text-slate-300">{cat}</span>
                    <span className={color}>{pct.toFixed(0)}%</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-slate-700 overflow-hidden">
                    <div className={`h-full ${barColor} rounded-full transition-all`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Category Breakdown */}
        <div className="bg-slate-900 rounded-xl border border-slate-700 p-5">
          <h2 className="text-lg font-semibold text-white mb-4">📊 Finding Categories</h2>
          <div className="space-y-2">
            {categories.map(([cat, count]) => (
              <div key={cat} className="flex items-center justify-between py-2 px-3 rounded-lg bg-slate-800/50">
                <span className="text-sm text-slate-300">{cat}</span>
                <div className="flex items-center gap-2">
                  <div className="h-1.5 rounded-full bg-sky-500" style={{ width: `${Math.max(8, (count / result.total_findings) * 80)}px` }} />
                  <span className="text-sm font-mono text-slate-400">{count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top Findings */}
      <div className="bg-slate-900 rounded-xl border border-slate-700 p-5">
        <h2 className="text-lg font-semibold text-white mb-4">🔴 Top Findings</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-slate-400 border-b border-slate-700">
                <th className="text-left py-2 px-3">Severity</th>
                <th className="text-left py-2 px-3">ID</th>
                <th className="text-left py-2 px-3">Finding</th>
                <th className="text-left py-2 px-3">Category</th>
                <th className="text-left py-2 px-3">File</th>
                <th className="text-left py-2 px-3">Fix</th>
              </tr>
            </thead>
            <tbody>
              {result.findings
                .sort((a, b) => (['critical','high','medium','low','info'].indexOf(a.severity)) - (['critical','high','medium','low','info'].indexOf(b.severity)))
                .slice(0, 10)
                .map((f) => (
                  <tr key={f.id} className="border-b border-slate-800 hover:bg-slate-800/50">
                    <td className={`py-2 px-3 font-medium ${SEVERITY_COLORS[f.severity]}`}>
                      {f.severity.toUpperCase()}
                    </td>
                    <td className="py-2 px-3 text-slate-400 font-mono text-xs">{f.id}</td>
                    <td className="py-2 px-3 text-white">{f.title}</td>
                    <td className="py-2 px-3 text-slate-400">{f.masvs_category}</td>
                    <td className="py-2 px-3 text-slate-500 font-mono text-xs">{f.file || '—'}</td>
                    <td className="py-2 px-3 text-slate-400 text-xs max-w-xs truncate">{f.remediation || '—'}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}