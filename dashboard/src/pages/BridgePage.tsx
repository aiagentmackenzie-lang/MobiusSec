const PORTFOLIO_TOOLS = [
  {
    name: 'GHOSTWIRE',
    icon: '👻',
    description: 'Network forensics engine — C2 beacon detection, JA4+ fingerprinting, PCAP analysis',
    capabilities: ['network_analysis', 'c2_detection', 'ja4_fingerprinting', 'pcap_analysis'],
    matchingCategories: ['NETWORK', 'RESILIENCE'],
    bridgeType: 'pcap_export',
    dataFlow: 'MobiusSec → GHOSTWIRE (export network artifacts)',
    url: 'https://github.com/aiagentmackenzie-lang/GHOSTWIRE',
  },
  {
    name: 'HATCHERY',
    icon: '🥚',
    description: 'Malware sandbox — dynamic analysis, IOC extraction, YARA scanning',
    capabilities: ['malware_analysis', 'dynamic_analysis', 'ioc_extraction', 'yara_scanning'],
    matchingCategories: ['RESILIENCE', 'CODE'],
    bridgeType: 'sample_submission',
    dataFlow: 'MobiusSec → HATCHERY (submit suspicious samples)',
    url: 'https://github.com/aiagentmackenzie-lang/HATCHERY',
  },
  {
    name: 'DEADDROP',
    icon: '🔍',
    description: 'Digital forensics toolkit — disk/memory forensics, timeline analysis',
    capabilities: ['disk_forensics', 'memory_forensics', 'timeline_analysis', 'yara_hunting'],
    matchingCategories: ['STORAGE', 'CODE'],
    bridgeType: 'artifact_export',
    dataFlow: 'MobiusSec → DEADDROP (export artifacts for forensics)',
    url: 'https://github.com/aiagentmackenzie-lang/DEADDROP',
  },
  {
    name: 'HONEYTRAP',
    icon: '🕸️',
    description: 'Deception framework — honeypots, honeytokens, behavioral analysis',
    capabilities: ['deception', 'honeytokens', 'honeypots', 'behavioral_analysis'],
    matchingCategories: ['NETWORK', 'RESILIENCE'],
    bridgeType: 'alert_feed',
    dataFlow: 'HONEYTRAP → MobiusSec (honeypot alerts feed threat model)',
    url: 'https://github.com/aiagentmackenzie-lang/HONEYTRAP',
  },
  {
    name: 'WebBreaker',
    icon: '🕸️',
    description: 'Web app pentest toolkit — SQLi, XSS, CSRF, fuzzing, header analysis',
    capabilities: ['web_pentesting', 'sqli', 'xss', 'csrf', 'fuzzing', 'header_analysis'],
    matchingCategories: ['NETWORK', 'PLATFORM'],
    bridgeType: 'api_url_export',
    dataFlow: 'MobiusSec → WebBreaker (export API URLs for pentesting)',
    url: 'https://github.com/aiagentmackenzie-lang/WebBreaker',
  },
];

const BRIDGE_COLORS: Record<string, string> = {
  pcap_export: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  sample_submission: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  artifact_export: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  alert_feed: 'bg-green-500/20 text-green-400 border-green-500/30',
  api_url_export: 'bg-sky-500/20 text-sky-400 border-sky-500/30',
};

// Demo: categories with findings from current scan
const ACTIVE_CATEGORIES = ['NETWORK', 'CRYPTO', 'RESILIENCE', 'STORAGE', 'CODE', 'PLATFORM'];

export default function BridgePage() {
  const recommendedTools = PORTFOLIO_TOOLS.filter(
    (tool) => tool.matchingCategories.some((c) => ACTIVE_CATEGORIES.includes(c))
  );

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">🌉 Portfolio Bridge</h1>
          <p className="text-sm text-slate-400 mt-1">
            Connect MobiusSec findings to the broader security portfolio for deeper analysis.
          </p>
        </div>
        <div className="text-right">
          <div className="text-sm text-slate-400">Active findings in</div>
          <div className="text-xs text-sky-400">{ACTIVE_CATEGORIES.length} MASVS categories</div>
        </div>
      </div>

      {/* Recommended tools */}
      <div className="bg-slate-900 rounded-xl border border-sky-500/30 p-5">
        <h2 className="text-lg font-semibold text-sky-400 mb-4">⚡ Recommended Tools</h2>
        <p className="text-sm text-slate-400 mb-4">
          Based on your current findings, these portfolio tools can provide deeper analysis:
        </p>
        <div className="space-y-4">
          {recommendedTools.map((tool) => (
            <div key={tool.name} className="bg-slate-800/50 rounded-lg p-4 border border-slate-700 hover:border-slate-600 transition-colors">
              <div className="flex items-start gap-3">
                <span className="text-2xl">{tool.icon}</span>
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="text-white font-bold text-lg">{tool.name}</h3>
                    <span className={`px-2 py-0.5 rounded text-xs border ${BRIDGE_COLORS[tool.bridgeType]}`}>
                      {tool.bridgeType.replace('_', ' ')}
                    </span>
                  </div>
                  <p className="text-sm text-slate-400 mb-2">{tool.description}</p>

                  <div className="flex flex-wrap gap-1.5 mb-2">
                    {tool.matchingCategories.map((cat) => (
                      <span key={cat} className={`px-2 py-0.5 rounded text-xs ${
                        ACTIVE_CATEGORIES.includes(cat)
                          ? 'bg-sky-500/20 text-sky-400'
                          : 'bg-slate-700 text-slate-500'
                      }`}>
                        {cat}
                        {ACTIVE_CATEGORIES.includes(cat) && ' ✓'}
                      </span>
                    ))}
                  </div>

                  <div className="text-xs text-slate-500 mb-3">
                    <span className="text-slate-400">Data flow:</span> {tool.dataFlow}
                  </div>

                  <div className="flex gap-2">
                    <button className="px-3 py-1.5 bg-sky-500/20 hover:bg-sky-500/30 text-sky-400 rounded-lg text-sm transition-colors">
                      🔄 Export Findings
                    </button>
                    <a
                      href={tool.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg text-sm transition-colors"
                    >
                      🔗 GitHub
                    </a>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* All bridge connections */}
      <div className="bg-slate-900 rounded-xl border border-slate-700 p-5">
        <h2 className="text-lg font-semibold text-white mb-4">🔗 All Connections</h2>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-slate-400 border-b border-slate-700">
              <th className="text-left py-2 px-3">Tool</th>
              <th className="text-left py-2 px-3">Bridge Type</th>
              <th className="text-left py-2 px-3">Data Flow</th>
              <th className="text-left py-2 px-3">Categories</th>
              <th className="text-left py-2 px-3">Status</th>
            </tr>
          </thead>
          <tbody>
            {PORTFOLIO_TOOLS.map((tool) => {
              const isMatch = tool.matchingCategories.some((c) => ACTIVE_CATEGORIES.includes(c));
              return (
                <tr key={tool.name} className="border-b border-slate-800">
                  <td className="py-2 px-3">
                    <span className="text-white font-medium">{tool.icon} {tool.name}</span>
                  </td>
                  <td className="py-2 px-3">
                    <span className={`px-2 py-0.5 rounded text-xs border ${BRIDGE_COLORS[tool.bridgeType]}`}>
                      {tool.bridgeType.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-xs text-slate-400 max-w-xs">{tool.dataFlow}</td>
                  <td className="py-2 px-3">
                    <div className="flex gap-1">
                      {tool.matchingCategories.map((c) => (
                        <span key={c} className="px-1.5 py-0.5 bg-slate-700 text-slate-400 rounded text-xs">{c}</span>
                      ))}
                    </div>
                  </td>
                  <td className="py-2 px-3">
                    {isMatch ? (
                      <span className="text-green-400 text-xs">✅ Recommended</span>
                    ) : (
                      <span className="text-slate-500 text-xs">—</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Integration instructions */}
      <div className="bg-slate-900 rounded-xl border border-slate-700 p-5">
        <h2 className="text-lg font-semibold text-white mb-4">📖 Integration Guide</h2>
        <div className="space-y-3">
          <div className="bg-slate-800/50 rounded-lg p-4">
            <h3 className="text-sm font-medium text-white mb-2">Export findings to GHOSTWIRE</h3>
            <code className="text-xs text-sky-400 bg-slate-900 px-3 py-2 rounded block">
              mobius stix app.apk --output ghostwire-import.json<br/>
              ghostwire import --file ghostwire-import.json
            </code>
          </div>
          <div className="bg-slate-800/50 rounded-lg p-4">
            <h3 className="text-sm font-medium text-white mb-2">Submit suspicious samples to HATCHERY</h3>
            <code className="text-xs text-sky-400 bg-slate-900 px-3 py-2 rounded block">
              mobius bridge app.apk  # Shows recommended tools<br/>
              # Export findings for HATCHERY analysis
              mobius report app.apk --format json --output hatchery-input.json
            </code>
          </div>
          <div className="bg-slate-800/50 rounded-lg p-4">
            <h3 className="text-sm font-medium text-white mb-2">Feed HONEYTRAP alerts into mobile threat model</h3>
            <code className="text-xs text-sky-400 bg-slate-900 px-3 py-2 rounded block">
              # HONEYTRAP alerts can inform MobiusSec scanning priorities<br/>
              # Use bridge to correlate honeypot data with mobile findings
            </code>
          </div>
        </div>
      </div>
    </div>
  );
}