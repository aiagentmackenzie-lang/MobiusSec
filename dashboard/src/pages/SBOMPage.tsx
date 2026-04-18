const DEMO_COMPONENTS = [
  { type: 'library', name: 'OkHttp3', version: '4.12.0', license: 'Apache-2.0', risk: 'low', purl: 'pkg:maven/com.squareup.okhttp3/okhttp@4.12.0', description: 'HTTP client' },
  { type: 'library', name: 'Retrofit', version: '2.9.0', license: 'Apache-2.0', risk: 'low', purl: 'pkg:maven/com.squareup.retrofit2/retrofit@2.9.0', description: 'REST client' },
  { type: 'library', name: 'Gson', version: '2.10.1', license: 'Apache-2.0', risk: 'low', purl: 'pkg:maven/com.google.code.gson/gson@2.10.1', description: 'JSON serialization' },
  { type: 'library', name: 'Firebase Analytics', version: '21.5.0', license: 'Proprietary', risk: 'medium', purl: 'pkg:maven/com.google.firebase/firebase-analytics@21.5.0', description: 'Analytics SDK — tracks user behavior' },
  { type: 'library', name: 'Facebook SDK', version: '16.1.0', license: 'Proprietary', risk: 'high', purl: 'pkg:maven/com.facebook.android/facebook-android-sdk@16.1.0', description: 'Social SDK — collects device info, advertising ID' },
  { type: 'library', name: 'Glide', version: '4.16.0', license: 'BSD-3', risk: 'low', purl: 'pkg:maven/com.github.bumptech.glide/glide@4.16.0', description: 'Image loading' },
  { type: 'library', name: 'Room', version: '2.6.1', license: 'Apache-2.0', risk: 'low', purl: 'pkg:maven/androidx.room/room-runtime@2.6.1', description: 'SQLite ORM' },
  { type: 'library', name: 'Timber', version: '5.0.1', license: 'Apache-2.0', risk: 'low', purl: 'pkg:maven/com.jakewharton.timber/timber@5.0.1', description: 'Logging' },
  { type: 'library', name: 'SQLCipher', version: '4.5.6', license: 'Apache-2.0', risk: 'low', purl: 'pkg:maven/net.zetetic/android-database-sqlcipher@4.5.6', description: 'Encrypted SQLite' },
  { type: 'framework', name: 'AndroidX Core', version: '1.12.0', license: 'Apache-2.0', risk: 'none', purl: 'pkg:maven/androidx.core/core-ktx@1.12.0', description: 'Core Android extensions' },
  { type: 'framework', name: 'Kotlin Stdlib', version: '1.9.22', license: 'Apache-2.0', risk: 'none', purl: 'pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@1.9.22', description: 'Kotlin standard library' },
  { type: 'library', name: 'AppsFlyer', version: '6.12.2', license: 'Proprietary', risk: 'high', purl: 'pkg:maven/com.appsflyer/af-android-sdk@6.12.2', description: 'Attribution SDK — collects advertising ID, device info' },
];

const RISK_COLORS: Record<string, string> = {
  high: 'text-red-400 bg-red-500/10',
  medium: 'text-yellow-400 bg-yellow-500/10',
  low: 'text-blue-400 bg-blue-500/10',
  none: 'text-green-400 bg-green-500/10',
};

export default function SBOMPage() {
  const libCount = DEMO_COMPONENTS.filter((c) => c.type === 'library').length;
  const frameworkCount = DEMO_COMPONENTS.filter((c) => c.type === 'framework').length;
  const highRisk = DEMO_COMPONENTS.filter((c) => c.risk === 'high').length;
  const proprietaryCount = DEMO_COMPONENTS.filter((c) => c.license === 'Proprietary').length;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">📦 Software Bill of Materials</h1>
        <div className="flex gap-2">
          <button className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm transition-colors">
            📋 Export CycloneDX JSON
          </button>
          <button className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm transition-colors">
            📄 Export CycloneDX XML
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-slate-900 rounded-xl border border-slate-700 p-5 text-center">
          <div className="text-3xl font-bold text-sky-400">{DEMO_COMPONENTS.length}</div>
          <div className="text-sm text-slate-400 mt-1">Total Components</div>
        </div>
        <div className="bg-slate-900 rounded-xl border border-slate-700 p-5 text-center">
          <div className="text-3xl font-bold text-white">{libCount}</div>
          <div className="text-sm text-slate-400 mt-1">Libraries</div>
          <div className="text-xs text-slate-500">{frameworkCount} frameworks</div>
        </div>
        <div className="bg-slate-900 rounded-xl border border-slate-700 p-5 text-center">
          <div className="text-3xl font-bold text-red-400">{highRisk}</div>
          <div className="text-sm text-slate-400 mt-1">High Risk</div>
          <div className="text-xs text-red-400">Tracking SDKs</div>
        </div>
        <div className="bg-slate-900 rounded-xl border border-slate-700 p-5 text-center">
          <div className="text-3xl font-bold text-yellow-400">{proprietaryCount}</div>
          <div className="text-sm text-slate-400 mt-1">Proprietary Licenses</div>
          <div className="text-xs text-slate-500">Requires review</div>
        </div>
      </div>

      {/* License distribution */}
      <div className="bg-slate-900 rounded-xl border border-slate-700 p-5">
        <h2 className="text-lg font-semibold text-white mb-4">📊 License Distribution</h2>
        <div className="flex gap-4">
          {(['Apache-2.0', 'BSD-3', 'Proprietary', 'MIT'] as const).map((license) => {
            const count = DEMO_COMPONENTS.filter((c) => c.license === license).length;
            const pct = Math.round((count / DEMO_COMPONENTS.length) * 100);
            const color = license === 'Proprietary' ? 'bg-yellow-500' : 'bg-sky-500';
            return (
              <div key={license} className="flex-1 bg-slate-800/50 rounded-lg p-3">
                <div className="text-sm text-white font-medium">{license}</div>
                <div className="text-2xl font-bold text-sky-400">{count}</div>
                <div className="h-1.5 bg-slate-700 rounded-full mt-2 overflow-hidden">
                  <div className={`h-full ${color} rounded-full`} style={{ width: `${pct}%` }} />
                </div>
                <div className="text-xs text-slate-500 mt-1">{pct}%</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Component table */}
      <div className="bg-slate-900 rounded-xl border border-slate-700 p-5">
        <h2 className="text-lg font-semibold text-white mb-4">🔍 Component Inventory</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-slate-400 border-b border-slate-700">
                <th className="text-left py-2 px-3">Type</th>
                <th className="text-left py-2 px-3">Name</th>
                <th className="text-left py-2 px-3">Version</th>
                <th className="text-left py-2 px-3">License</th>
                <th className="text-left py-2 px-3">Description</th>
                <th className="text-left py-2 px-3">Risk</th>
              </tr>
            </thead>
            <tbody>
              {DEMO_COMPONENTS.map((c) => (
                <tr key={c.purl} className="border-b border-slate-800 hover:bg-slate-800/50">
                  <td className="py-2 px-3">
                    <span className={`px-2 py-0.5 rounded text-xs ${c.type === 'framework' ? 'bg-purple-500/20 text-purple-400' : 'bg-sky-500/20 text-sky-400'}`}>
                      {c.type}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-white font-mono text-xs">{c.name}</td>
                  <td className="py-2 px-3 text-slate-400 font-mono">{c.version}</td>
                  <td className="py-2 px-3">
                    <span className={`text-xs ${c.license === 'Proprietary' ? 'text-yellow-400' : 'text-slate-400'}`}>
                      {c.license}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-slate-500 text-xs max-w-xs truncate">{c.description}</td>
                  <td className="py-2 px-3">
                    <span className={`px-2 py-0.5 rounded text-xs ${RISK_COLORS[c.risk] || RISK_COLORS.none}`}>
                      {c.risk.toUpperCase()}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* CycloneDX metadata */}
      <div className="bg-slate-900 rounded-xl border border-slate-700 p-5">
        <h2 className="text-lg font-semibold text-white mb-4">📋 CycloneDX Metadata</h2>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-slate-500">Format:</span>
            <span className="text-white ml-2">CycloneDX 1.6</span>
          </div>
          <div>
            <span className="text-slate-500">Spec Version:</span>
            <span className="text-white ml-2">1.6</span>
          </div>
          <div>
            <span className="text-slate-500">Serial Number:</span>
            <span className="text-white ml-2 font-mono">urn:uuid:f6f...</span>
          </div>
          <div>
            <span className="text-slate-500">Generated:</span>
            <span className="text-white ml-2">2026-04-18T16:30:00Z</span>
          </div>
        </div>
      </div>
    </div>
  );
}