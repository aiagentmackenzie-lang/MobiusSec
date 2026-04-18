import { useState } from 'react';
import type { ScanResult } from '../types';

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-500',
  high: 'text-orange-500',
  medium: 'text-yellow-500',
  low: 'text-blue-500',
  info: 'text-gray-400',
};

export default function ScanPage() {
  const [appPath, setAppPath] = useState('');
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanStep, setScanStep] = useState('');

  const steps = [
    'Extracting app package...',
    'Analyzing manifest/config...',
    'Scanning for secrets...',
    'Running YARA rules...',
    'Privacy analysis...',
    'Generating SBOM...',
    'Mapping MASVS compliance...',
    'Complete!',
  ];

  const handleScan = async () => {
    if (!appPath.trim()) return;
    setScanning(true);
    setProgress(0);
    setError(null);
    setResult(null);

    // Simulate scan progress
    for (let i = 0; i < steps.length; i++) {
      setScanStep(steps[i]);
      setProgress(Math.round(((i + 1) / steps.length) * 100));
      await new Promise((r) => setTimeout(r, 400));
    }

    // Demo result
    setResult({
      app_path: appPath,
      platform: appPath.endsWith('.ipa') ? 'ios' : 'android',
      package_name: 'com.example.app',
      app_name: appPath.split('/').pop()?.replace(/\.(apk|ipa)$/, '') || 'App',
      version: '1.0.0',
      findings: [
        { id: 'AND-001', title: 'App is debuggable', description: 'android:debuggable=true in manifest', severity: 'high', masvs_category: 'RESILIENCE', platform: 'android', file: 'AndroidManifest.xml', remediation: 'Set android:debuggable=false' },
        { id: 'AND-NET-001', title: 'Cleartext traffic allowed', description: 'usesCleartextTraffic=true', severity: 'critical', masvs_category: 'NETWORK', platform: 'android', file: 'AndroidManifest.xml', remediation: 'Disable cleartext traffic' },
        { id: 'SEC-002', title: 'Hardcoded API key', description: 'Google API key found in source', severity: 'high', masvs_category: 'CRYPTO', platform: 'android', file: 'ApiService.java', line: 23 },
        { id: 'PRIV-001', title: 'Excessive permissions', description: 'READ_CONTACTS, CAMERA not needed', severity: 'medium', masvs_category: 'PRIVACY', platform: 'android', file: 'AndroidManifest.xml' },
      ],
      total_findings: 4,
      critical_count: 1,
      high_count: 2,
      medium_count: 1,
      low_count: 0,
      info_count: 0,
      scan_time_seconds: 3.8,
    });
    setScanning(false);
  };

  return (
    <div className="p-6 space-y-6 max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold text-white">🔍 New Scan</h1>

      {/* Input */}
      <div className="bg-slate-900 rounded-xl border border-slate-700 p-6">
        <label className="block text-sm font-medium text-slate-300 mb-2">
          APK or IPA file path
        </label>
        <div className="flex gap-3">
          <input
            type="text"
            value={appPath}
            onChange={(e) => setAppPath(e.target.value)}
            placeholder="/path/to/app.apk or /path/to/app.ipa"
            className="flex-1 bg-slate-800 border border-slate-600 rounded-lg px-4 py-2.5 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-transparent"
            disabled={scanning}
          />
          <button
            onClick={handleScan}
            disabled={scanning || !appPath.trim()}
            className="px-6 py-2.5 bg-sky-500 hover:bg-sky-600 disabled:bg-slate-700 disabled:text-slate-500 text-white font-medium rounded-lg transition-colors"
          >
            {scanning ? 'Scanning...' : 'Scan'}
          </button>
        </div>
        <p className="text-xs text-slate-500 mt-2">
          Supports Android APK and iOS IPA files. The app will be extracted and analyzed for security vulnerabilities.
        </p>
      </div>

      {/* Progress */}
      {scanning && (
        <div className="bg-slate-900 rounded-xl border border-slate-700 p-6">
          <h3 className="text-sm font-medium text-slate-300 mb-3">Scan Progress</h3>
          <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
            <div
              className="h-full bg-sky-500 rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
          <p className="text-sm text-sky-400 mt-2">{scanStep}</p>
          <p className="text-xs text-slate-500">{progress}%</p>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-red-400">
          ❌ {error}
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4">
          <div className="bg-slate-900 rounded-xl border border-sky-500/30 p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">
                {result.platform === 'android' ? '🤖' : '🍎'} {result.app_name}
              </h2>
              <span className="px-3 py-1 bg-sky-500/20 text-sky-400 rounded-full text-sm">
                {result.total_findings} findings
              </span>
            </div>
            <div className="grid grid-cols-5 gap-3">
              {([
                { label: 'Critical', count: result.critical_count, color: 'text-red-400 bg-red-500/10' },
                { label: 'High', count: result.high_count, color: 'text-orange-400 bg-orange-500/10' },
                { label: 'Medium', count: result.medium_count, color: 'text-yellow-400 bg-yellow-500/10' },
                { label: 'Low', count: result.low_count, color: 'text-blue-400 bg-blue-500/10' },
                { label: 'Info', count: result.info_count, color: 'text-gray-400 bg-gray-500/10' },
              ] as const).map((s) => (
                <div key={s.label} className={`rounded-lg p-3 text-center ${s.color}`}>
                  <div className="text-2xl font-bold">{s.count}</div>
                  <div className="text-xs">{s.label}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-slate-900 rounded-xl border border-slate-700 p-5">
            <h3 className="text-sm font-medium text-slate-300 mb-3">Findings</h3>
            <div className="space-y-2">
              {result.findings
                .sort((a, b) => (['critical', 'high', 'medium', 'low', 'info'].indexOf(a.severity)) - (['critical', 'high', 'medium', 'low', 'info'].indexOf(b.severity)))
                .map((f) => (
                  <div key={f.id} className="flex items-center gap-3 p-2 rounded-lg bg-slate-800/50">
                    <span className={`text-xs font-bold ${SEVERITY_COLORS[f.severity]}`}>
                      {f.severity.toUpperCase()}
                    </span>
                    <span className="text-white text-sm">{f.title}</span>
                    <span className="text-slate-500 text-xs ml-auto">{f.masvs_category}</span>
                    {f.file && <span className="text-slate-600 text-xs font-mono">{f.file}</span>}
                  </div>
                ))}
            </div>
          </div>

          <div className="flex gap-3">
            <button className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm transition-colors">
              📄 Export HTML
            </button>
            <button className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm transition-colors">
              📊 Export SARIF
            </button>
            <button className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm transition-colors">
              📦 Export STIX
            </button>
          </div>
        </div>
      )}
    </div>
  );
}