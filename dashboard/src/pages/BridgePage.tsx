import { useState } from 'react';

const CI_SNIPPETS = [
  {
    id: 'github',
    label: 'GitHub Actions',
    icon: '🐙',
    lang: 'yaml',
    code: `name: MobiusSec Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run MobiusSec
        uses: mobiussec/action@v1
        with:
          api-key: \${{ secrets.MOBIUS_API_KEY }}
          app-path: app/build/release/app.apk
          quality-gate: true
          fail-on: critical`,
  },
  {
    id: 'gitlab',
    label: 'GitLab CI',
    icon: '🦊',
    lang: 'yaml',
    code: `mobiussec-scan:
  stage: test
  image: mobiussec/cli:latest
  script:
    - mobiussec scan --app app.apk --api-key $MOBIUS_API_KEY --quality-gate --fail-on critical
  artifacts:
    reports:
      security: mobiussec-report.json`,
  },
  {
    id: 'fastlane',
    label: 'Fastlane',
    icon: '🚀',
    lang: 'ruby',
    code: `# Fastfile
lane :security_scan do
  mobiussec(
    app_path: "app.apk",
    api_key: ENV["MOBIUS_API_KEY"],
    quality_gate: true,
    fail_on: "critical"
  )
end`,
  },
  {
    id: 'bitrise',
    label: 'Bitrise',
    icon: '🔺',
    lang: 'yaml',
    code: `---
format_version: '11'
default_step_lib_source: https://github.com/bitrise-io/bitrise-steplib.git
workflows:
  scan:
    steps:
    - script:
        title: MobiusSec Security Scan
        inputs:
        - content: |-
            mobiussec scan \\
              --app app.apk \\
              --api-key $MOBIUS_API_KEY \\
              --quality-gate \\
              --fail-on critical`,
  },
];

const API_CONNECTIONS = [
  { name: 'GitHub', status: 'connected', lastSync: '2 min ago' },
  { name: 'GitLab', status: 'disconnected', lastSync: null },
  { name: 'Slack', status: 'connected', lastSync: '5 min ago' },
  { name: 'Jira', status: 'error', lastSync: '1 hour ago' },
  { name: 'PagerDuty', status: 'disconnected', lastSync: null },
];

const WEBHOOKS = [
  { url: 'https://api.mobiussec.dev/webhook/gh-12345', events: ['scan.complete', 'finding.critical'], active: true },
  { url: 'https://hooks.slack.com/services/T0X/B0X/xxx', events: ['scan.complete'], active: true },
  { url: 'https://jira.example.com/webhook/mobius', events: ['finding.critical', 'finding.high'], active: false },
];

const STATUS_STYLES: Record<string, string> = {
  connected: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  disconnected: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
  error: 'bg-red-500/20 text-red-400 border-red-500/30',
};

const STATUS_ICONS: Record<string, string> = { connected: '🟢', disconnected: '⚪', error: '🔴' };

export default function BridgePage() {
  const [activeSnippet, setActiveSnippet] = useState('github');
  const [copied, setCopied] = useState<string | null>(null);
  const [gateCritical, setGateCritical] = useState(true);
  const [gateHigh, setGateHigh] = useState(false);
  const [gateThreshold, setGateThreshold] = useState('5');

  const currentSnippet = CI_SNIPPETS.find((s) => s.id === activeSnippet)!;

  const handleCopy = (code: string, id: string) => {
    navigator.clipboard.writeText(code).catch(() => {});
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">🔗 CI/CD & Integration Bridge</h1>
        <p className="text-slate-400 text-sm mt-1">Connect MobiusSec to your pipeline and tools</p>
      </div>

      {/* API Connection Status */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-3">📡 API Connections</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {API_CONNECTIONS.map((conn) => (
            <div key={conn.name} className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="text-lg">{STATUS_ICONS[conn.status]}</span>
                <div>
                  <p className="text-sm font-medium text-white">{conn.name}</p>
                  <p className="text-xs text-slate-500">{conn.lastSync ? `Last sync: ${conn.lastSync}` : 'Not configured'}</p>
                </div>
              </div>
              <span className={`px-2 py-0.5 rounded text-xs font-medium border ${STATUS_STYLES[conn.status]}`}>{conn.status}</span>
            </div>
          ))}
        </div>
      </div>

      {/* CI/CD Snippets */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-3">⚙️ CI/CD Integration</h2>
        <div className="flex gap-2 mb-3">
          {CI_SNIPPETS.map((s) => (
            <button key={s.id} onClick={() => setActiveSnippet(s.id)} className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${activeSnippet === s.id ? 'bg-sky-500 text-white' : 'bg-slate-800 border border-slate-700 text-slate-400 hover:text-white'}`}>
              {s.icon} {s.label}
            </button>
          ))}
        </div>
        <div className="relative">
          <pre className="bg-slate-950 border border-slate-700 rounded-lg p-4 text-sm text-slate-300 overflow-x-auto font-mono leading-relaxed">
            {currentSnippet.code}
          </pre>
          <button onClick={() => handleCopy(currentSnippet.code, currentSnippet.id)} className="absolute top-3 right-3 bg-slate-700 hover:bg-slate-600 text-slate-300 px-3 py-1.5 rounded text-xs font-medium transition-colors">
            {copied === currentSnippet.id ? '✓ Copied' : '📋 Copy'}
          </button>
        </div>
      </div>

      {/* Webhook Configuration */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-3">🔔 Webhooks</h2>
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700 text-slate-400 text-xs uppercase">
                <th className="px-4 py-3 text-left">URL</th>
                <th className="px-4 py-3 text-left">Events</th>
                <th className="px-4 py-3 text-center">Status</th>
              </tr>
            </thead>
            <tbody>
              {WEBHOOKS.map((wh, i) => (
                <tr key={i} className="border-b border-slate-700/50 hover:bg-slate-700/20">
                  <td className="px-4 py-3 text-sky-400 font-mono text-xs break-all">{wh.url}</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {wh.events.map((e) => (
                        <span key={e} className="px-2 py-0.5 rounded bg-slate-700 text-slate-300 text-xs">{e}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-center">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${wh.active ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-600/50 text-slate-500'}`}>
                      {wh.active ? 'Active' : 'Paused'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Quality Gate Settings */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-3">🚧 Quality Gate</h2>
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-5 space-y-4">
          <p className="text-sm text-slate-400">Configure when CI/CD pipelines should fail based on scan results.</p>
          <div className="space-y-3">
            <label className="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" checked={gateCritical} onChange={(e) => setGateCritical(e.target.checked)} className="w-4 h-4 rounded border-slate-600 bg-slate-700 text-sky-500 focus:ring-sky-500" />
              <span className="text-sm text-slate-300">Fail on any <span className="text-red-400 font-medium">critical</span> finding</span>
            </label>
            <label className="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" checked={gateHigh} onChange={(e) => setGateHigh(e.target.checked)} className="w-4 h-4 rounded border-slate-600 bg-slate-700 text-sky-500 focus:ring-sky-500" />
              <span className="text-sm text-slate-300">Fail on any <span className="text-orange-400 font-medium">high</span> finding</span>
            </label>
            <div className="flex items-center gap-3">
              <span className="text-sm text-slate-300">Fail when total findings exceed</span>
              <input type="number" value={gateThreshold} onChange={(e) => setGateThreshold(e.target.value)} className="w-16 bg-slate-700 border border-slate-600 rounded px-2 py-1 text-sm text-white text-center" />
            </div>
          </div>
          <div className="pt-2 border-t border-slate-700">
            <p className="text-xs text-slate-500">Quality gate config: <span className="text-slate-400">{gateCritical ? 'critical=1' : ''}{gateCritical && gateHigh ? ', ' : ''}{gateHigh ? 'high=1' : ''}{(gateCritical || gateHigh) ? ', ' : ''}max_total={gateThreshold}</span></p>
          </div>
        </div>
      </div>
    </div>
  );
}