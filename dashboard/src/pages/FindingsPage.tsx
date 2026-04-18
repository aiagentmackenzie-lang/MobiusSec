import { useState } from 'react';
import type { Finding, Severity } from '../types';

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-500 bg-red-500/10 border-red-500/30',
  high: 'text-orange-500 bg-orange-500/10 border-orange-500/30',
  medium: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30',
  low: 'text-blue-500 bg-blue-500/10 border-blue-500/30',
  info: 'text-gray-400 bg-gray-500/10 border-gray-500/30',
};

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  info: 'bg-gray-400',
};

const CATEGORIES = ['STORAGE', 'CRYPTO', 'AUTH', 'NETWORK', 'PLATFORM', 'CODE', 'RESILIENCE', 'PRIVACY'];
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

// Demo findings
const DEMO_FINDINGS: Finding[] = [
  { id: 'AND-NET-001', title: 'Cleartext traffic allowed', description: 'android:usesCleartextTraffic="true" enables HTTP connections, vulnerable to MITM attacks.', severity: 'critical', masvs_category: 'NETWORK', platform: 'android', file: 'AndroidManifest.xml', remediation: 'Set android:usesCleartextTraffic="false" or remove the attribute.' },
  { id: 'SEC-001', title: 'Hardcoded AWS secret key', description: 'AKIAIOSFODNN7EXAMPLE found in Config.java at line 42. Secret key is stored in plaintext.', severity: 'critical', masvs_category: 'CRYPTO', platform: 'android', file: 'Config.java', line: 42, remediation: 'Move secrets to environment variables or Android Keystore.' },
  { id: 'AND-001', title: 'App is debuggable', description: 'android:debuggable="true" in release build allows debugging and data extraction.', severity: 'high', masvs_category: 'RESILIENCE', platform: 'android', file: 'AndroidManifest.xml', remediation: 'Remove android:debuggable attribute or set to false.' },
  { id: 'AND-EXPORT-001', title: 'Exported activity without permission', description: 'com.example.DetailActivity is exported but has no custom permission, allowing any app to invoke it.', severity: 'high', masvs_category: 'PLATFORM', platform: 'android', file: 'AndroidManifest.xml', remediation: 'Add android:exported="false" or add a custom permission.' },
  { id: 'CODE-001', title: 'SQL injection risk', description: 'Raw SQL query with string concatenation in DatabaseHelper.query() at line 87.', severity: 'high', masvs_category: 'CODE', platform: 'android', file: 'DatabaseHelper.java', line: 87, remediation: 'Use parameterized queries or Room DAO.' },
  { id: 'AND-BACKUP-001', title: 'Backup enabled for sensitive app', description: 'android:allowBackup="true" allows data extraction via adb backup.', severity: 'medium', masvs_category: 'STORAGE', platform: 'android', file: 'AndroidManifest.xml', remediation: 'Set android:allowBackup="false" for apps with sensitive data.' },
  { id: 'PRIV-001', title: 'Excessive permissions', description: 'READ_CONTACTS, WRITE_CONTACTS, CAMERA declared but not used in code.', severity: 'medium', masvs_category: 'PRIVACY', platform: 'android', file: 'AndroidManifest.xml', remediation: 'Remove unused permissions.' },
  { id: 'STORAGE-002', title: 'SharedPreferences in plaintext', description: 'Auth token stored in SharedPreferences without encryption.', severity: 'medium', masvs_category: 'STORAGE', platform: 'android', file: 'LoginActivity.java', remediation: 'Use EncryptedSharedPreferences or Android Keystore.' },
  { id: 'NET-002', title: 'No certificate pinning', description: 'Network calls to API endpoints lack SSL certificate pinning.', severity: 'low', masvs_category: 'NETWORK', platform: 'android', remediation: 'Implement certificate pinning using Network Security Config or OkHttp.' },
  { id: 'INFO-001', title: 'Debug logging active', description: 'Log.d() and Log.v() calls found in release build.', severity: 'info', masvs_category: 'CODE', platform: 'android', file: 'MainActivity.java', remediation: 'Strip debug logs in release builds using ProGuard/R8.' },
  { id: 'AUTH-001', title: 'No biometric fallback', description: 'Biometric auth is required but no fallback mechanism is provided.', severity: 'medium', masvs_category: 'AUTH', platform: 'android', file: 'BiometricHelper.java', remediation: 'Provide a fallback authentication method.' },
];

export default function FindingsPage() {
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [search, setSearch] = useState('');

  const filtered = DEMO_FINDINGS.filter((f) => {
    if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
    if (categoryFilter !== 'all' && f.masvs_category !== categoryFilter) return false;
    if (search && !f.title.toLowerCase().includes(search.toLowerCase()) && !f.id.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  }).sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));

  const counts = {
    critical: DEMO_FINDINGS.filter((f) => f.severity === 'critical').length,
    high: DEMO_FINDINGS.filter((f) => f.severity === 'high').length,
    medium: DEMO_FINDINGS.filter((f) => f.severity === 'medium').length,
    low: DEMO_FINDINGS.filter((f) => f.severity === 'low').length,
    info: DEMO_FINDINGS.filter((f) => f.severity === 'info').length,
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">⚠️ Findings</h1>
        <span className="text-sm text-slate-400">{filtered.length} of {DEMO_FINDINGS.length} findings</span>
      </div>

      {/* Filters */}
      <div className="bg-slate-900 rounded-xl border border-slate-700 p-4">
        <div className="flex flex-wrap gap-4">
          {/* Search */}
          <div className="flex-1 min-w-[200px]">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search findings..."
              className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-sky-500"
            />
          </div>

          {/* Severity filter */}
          <div className="flex gap-1.5">
            <button
              onClick={() => setSeverityFilter('all')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${severityFilter === 'all' ? 'bg-sky-500/20 text-sky-400' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'}`}
            >
              All ({DEMO_FINDINGS.length})
            </button>
            {SEVERITIES.map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter(s)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${severityFilter === s ? SEVERITY_COLORS[s] + ' border' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'}`}
              >
                {s.charAt(0).toUpperCase() + s.slice(1)} ({counts[s]})
              </button>
            ))}
          </div>

          {/* Category filter */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-slate-800 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-sky-500"
          >
            <option value="all">All Categories</option>
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Findings list */}
      <div className="space-y-3">
        {filtered.map((f) => (
          <div key={f.id} className="bg-slate-900 rounded-xl border border-slate-700 p-5 hover:border-slate-600 transition-colors">
            <div className="flex items-start gap-3">
              <div className={`w-2.5 h-2.5 rounded-full mt-1.5 flex-shrink-0 ${SEVERITY_DOT[f.severity]}`} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-xs font-bold ${SEVERITY_COLORS[f.severity]?.split(' ')[0]}`}>
                    {f.severity.toUpperCase()}
                  </span>
                  <span className="text-xs font-mono text-slate-500">{f.id}</span>
                  <span className="text-xs px-2 py-0.5 bg-slate-800 text-slate-400 rounded">{f.masvs_category}</span>
                  {f.file && <span className="text-xs font-mono text-slate-600">{f.file}{f.line ? `:${f.line}` : ''}</span>}
                </div>
                <h3 className="text-white font-medium">{f.title}</h3>
                <p className="text-sm text-slate-400 mt-1">{f.description}</p>
                {f.remediation && (
                  <div className="mt-3 p-3 bg-green-500/5 border border-green-500/20 rounded-lg">
                    <span className="text-xs font-medium text-green-400">💡 Fix: </span>
                    <span className="text-sm text-green-300">{f.remediation}</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}

        {filtered.length === 0 && (
          <div className="text-center py-12 text-slate-500">
            No findings match the current filters.
          </div>
        )}
      </div>
    </div>
  );
}