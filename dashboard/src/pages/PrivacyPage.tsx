import { useState } from 'react';

const COMPLIANCE_SCORES = [
  { framework: 'GDPR', score: 72, emoji: '🇪🇺', color: 'text-blue-400' },
  { framework: 'LGPD', score: 68, emoji: '🇧🇷', color: 'text-green-400' },
  { framework: 'CCPA', score: 80, emoji: '🇺🇸', color: 'text-purple-400' },
];

const DATA_COLLECTION = [
  { type: 'Device Identifiers', collected: true, purpose: 'Analytics', risk: 'high', details: 'IMEI, Android ID, GAID transmitted to 3rd parties' },
  { type: 'Location Data', collected: true, purpose: 'App functionality', risk: 'high', details: 'GPS coordinates sent to analytics SDK' },
  { type: 'Contact List', collected: true, purpose: 'Invite feature', risk: 'critical', details: 'Full contact list uploaded on first launch' },
  { type: 'Camera Access', collected: true, purpose: 'Profile photo', risk: 'medium', details: 'Camera accessible without explicit consent prompt' },
  { type: 'Clipboard Data', collected: false, purpose: 'N/A', risk: 'low', details: 'No clipboard access detected' },
  { type: 'SMS Data', collected: false, purpose: 'N/A', risk: 'low', details: 'No SMS permissions requested' },
  { type: 'Installation Tracking', collected: true, purpose: 'Attribution', risk: 'medium', details: 'Install referrer collected by Facebook SDK' },
  { type: 'App Usage Analytics', collected: true, purpose: 'Product improvement', risk: 'low', details: 'Session duration, screen views tracked via Firebase' },
];

const SDK_TRACKING = [
  { name: 'Firebase Analytics', data: ['App usage', 'Device info', 'Location (coarse)'], risk: 'medium', category: 'Analytics' },
  { name: 'Facebook SDK', data: ['Device ID', 'Install referrer', 'App events'], risk: 'high', category: 'Advertising' },
  { name: 'Google Ads', data: ['Device ID', 'Location', 'App activity'], risk: 'high', category: 'Advertising' },
  { name: 'Crashlytics', data: ['Crash logs', 'Device info'], risk: 'low', category: 'Monitoring' },
  { name: 'OneSignal', data: ['Push token', 'Device info'], risk: 'medium', category: 'Notifications' },
];

const PERMISSIONS = [
  { declared: 'INTERNET', used: true, risk: 'low' },
  { declared: 'ACCESS_FINE_LOCATION', used: true, risk: 'high' },
  { declared: 'READ_CONTACTS', used: false, risk: 'critical' },
  { declared: 'WRITE_CONTACTS', used: false, risk: 'critical' },
  { declared: 'CAMERA', used: true, risk: 'medium' },
  { declared: 'READ_PHONE_STATE', used: false, risk: 'critical' },
  { declared: 'VIBRATE', used: true, risk: 'low' },
  { declared: 'WAKE_LOCK', used: true, risk: 'low' },
  { declared: 'RECEIVE_BOOT_COMPLETED', used: true, risk: 'low' },
  { declared: 'BLUETOOTH_ADMIN', used: false, risk: 'medium' },
];

const DATA_FLOWS = [
  { source: 'App', destination: 'Firebase', data: 'Usage analytics', encrypted: true },
  { source: 'App', destination: 'Facebook', data: 'Device ID, events', encrypted: false },
  { source: 'App', destination: 'Google Ads', data: 'Location, device info', encrypted: false },
  { source: 'App', destination: 'Backend API', data: 'Auth tokens', encrypted: true },
  { source: 'App', destination: 'Crashlytics', data: 'Crash data', encrypted: true },
];

const RISK_STYLES: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
};

export default function PrivacyPage() {
  const [permFilter, setPermFilter] = useState<'all' | 'unused' | 'used'>('all');

  const filteredPerms = PERMISSIONS.filter((p) => {
    if (permFilter === 'unused') return !p.used;
    if (permFilter === 'used') return p.used;
    return true;
  });

  const unusedCount = PERMISSIONS.filter((p) => !p.used).length;

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">🕵️ Privacy & Compliance</h1>
        <p className="text-slate-400 text-sm mt-1">Data collection, SDK tracking, and regulatory compliance analysis</p>
      </div>

      {/* Compliance Score Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {COMPLIANCE_SCORES.map((c) => (
          <div key={c.framework} className="bg-slate-800/50 border border-slate-700 rounded-lg p-5">
            <div className="flex items-center justify-between mb-3">
              <span className="text-lg font-medium text-white">{c.emoji} {c.framework}</span>
              <span className={`text-2xl font-bold ${c.score >= 75 ? 'text-emerald-400' : c.score >= 50 ? 'text-yellow-400' : 'text-red-400'}`}>{c.score}%</span>
            </div>
            <div className="w-full bg-slate-700 rounded-full h-2.5">
              <div className={`${c.score >= 75 ? 'bg-emerald-500' : c.score >= 50 ? 'bg-yellow-500' : 'bg-red-500'} h-2.5 rounded-full`} style={{ width: `${c.score}%` }} />
            </div>
            <p className="text-xs text-slate-500 mt-2">{c.score >= 75 ? 'Good compliance posture' : c.score >= 50 ? 'Several gaps identified' : 'Significant non-compliance'}</p>
          </div>
        ))}
      </div>

      {/* Data Collection Map */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-3">📊 Data Collection Map</h2>
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700 text-slate-400 text-xs uppercase">
                <th className="px-4 py-3 text-left">Data Type</th>
                <th className="px-4 py-3 text-center">Collected</th>
                <th className="px-4 py-3 text-left">Purpose</th>
                <th className="px-4 py-3 text-center">Risk</th>
                <th className="px-4 py-3 text-left">Details</th>
              </tr>
            </thead>
            <tbody>
              {DATA_COLLECTION.map((d) => (
                <tr key={d.type} className="border-b border-slate-700/50 hover:bg-slate-700/20">
                  <td className="px-4 py-3 text-slate-200 font-medium">{d.type}</td>
                  <td className="px-4 py-3 text-center">{d.collected ? <span className="text-red-400">●</span> : <span className="text-emerald-400">○</span>}</td>
                  <td className="px-4 py-3 text-slate-400">{d.purpose}</td>
                  <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs font-medium border ${RISK_STYLES[d.risk]}`}>{d.risk}</span></td>
                  <td className="px-4 py-3 text-slate-400 text-xs">{d.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* SDK Tracking Table */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-3">🔗 SDK Tracking</h2>
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700 text-slate-400 text-xs uppercase">
                <th className="px-4 py-3 text-left">SDK</th>
                <th className="px-4 py-3 text-left">Category</th>
                <th className="px-4 py-3 text-left">Data Accessed</th>
                <th className="px-4 py-3 text-center">Risk</th>
              </tr>
            </thead>
            <tbody>
              {SDK_TRACKING.map((s) => (
                <tr key={s.name} className="border-b border-slate-700/50 hover:bg-slate-700/20">
                  <td className="px-4 py-3 text-slate-200 font-medium">{s.name}</td>
                  <td className="px-4 py-3 text-slate-400">{s.category}</td>
                  <td className="px-4 py-3 text-slate-400">{s.data.join(', ')}</td>
                  <td className="px-4 py-3 text-center"><span className={`px-2 py-0.5 rounded text-xs font-medium border ${RISK_STYLES[s.risk]}`}>{s.risk}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Permission Analysis */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold text-white">🔐 Permission Analysis</h2>
          <div className="flex items-center gap-2">
            <span className="text-xs text-red-400">{unusedCount} unused</span>
            <select value={permFilter} onChange={(e) => setPermFilter(e.target.value as 'all' | 'unused' | 'used')} className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-300">
              <option value="all">All</option>
              <option value="unused">Unused only</option>
              <option value="used">Used only</option>
            </select>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {filteredPerms.map((p) => (
            <div key={p.declared} className={`flex items-center justify-between px-4 py-2.5 rounded-lg border ${p.used ? 'bg-slate-800/50 border-slate-700' : 'bg-red-500/10 border-red-500/30'}`}>
              <span className="font-mono text-sm text-slate-300">{p.declared}</span>
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded text-xs font-medium border ${RISK_STYLES[p.risk]}`}>{p.risk}</span>
                <span className={`text-xs ${p.used ? 'text-emerald-400' : 'text-red-400'}`}>{p.used ? '✓ used' : '✗ unused'}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Data Flow Visualization */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-3">🔀 Data Flow</h2>
        <div className="space-y-3">
          {DATA_FLOWS.map((f, i) => (
            <div key={i} className="flex items-center gap-3 bg-slate-800/50 border border-slate-700 rounded-lg px-4 py-3">
              <span className="text-sm font-medium text-sky-400 min-w-[60px]">{f.source}</span>
              <span className="text-slate-500">→</span>
              <span className="text-sm font-medium text-orange-400 min-w-[80px]">{f.destination}</span>
              <span className="text-xs text-slate-400 flex-1">{f.data}</span>
              <span className={`px-2 py-0.5 rounded text-xs font-medium ${f.encrypted ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'}`}>
                {f.encrypted ? '🔒 Encrypted' : '⚠️ Unencrypted'}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}