import { useState } from 'react';
import type { MASVSStatus } from '../types';

const CATEGORIES = [
  { key: 'STORAGE', label: 'Storage', emoji: '🗄️' },
  { key: 'CRYPTO', label: 'Cryptography', emoji: '🔐' },
  { key: 'AUTH', label: 'Authentication', emoji: '🔑' },
  { key: 'NETWORK', label: 'Network', emoji: '🌐' },
  { key: 'PLATFORM', label: 'Platform', emoji: '📱' },
  { key: 'CODE', label: 'Code Quality', emoji: '🧑‍💻' },
  { key: 'RESILIENCE', label: 'Resilience', emoji: '🛡️' },
  { key: 'PRIVACY', label: 'Privacy', emoji: '🕵️' },
] as const;

const STATUS_STYLES: Record<MASVSStatus, string> = {
  pass: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  fail: 'bg-red-500/20 text-red-400 border-red-500/30',
  warn: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  skip: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
};

const STATUS_LABELS: Record<MASVSStatus, string> = {
  pass: 'PASS',
  fail: 'FAIL',
  warn: 'WARN',
  skip: 'SKIP',
};

interface MASVSTest {
  id: string;
  category: string;
  description: string;
  status: MASVSStatus;
  level: 1 | 2;
}

const DEMO_TESTS: MASVSTest[] = [
  { id: 'MASVS-STORAGE-1', category: 'STORAGE', description: 'Sensitive data not stored in plaintext', status: 'fail', level: 1 },
  { id: 'MASVS-STORAGE-2', category: 'STORAGE', description: 'SharedPreferences encrypted', status: 'fail', level: 2 },
  { id: 'MASVS-STORAGE-3', category: 'STORAGE', description: 'No sensitive data in logs', status: 'warn', level: 1 },
  { id: 'MASVS-CRYPTO-1', category: 'CRYPTO', description: 'No hardcoded secrets', status: 'fail', level: 1 },
  { id: 'MASVS-CRYPTO-2', category: 'CRYPTO', description: 'Uses proven crypto algorithms', status: 'pass', level: 1 },
  { id: 'MASVS-CRYPTO-3', category: 'CRYPTO', description: 'Key management follows best practices', status: 'warn', level: 2 },
  { id: 'MASVS-AUTH-1', category: 'AUTH', description: 'Secure authentication mechanism', status: 'pass', level: 1 },
  { id: 'MASVS-AUTH-2', category: 'AUTH', description: 'Biometric fallback provided', status: 'fail', level: 2 },
  { id: 'MASVS-AUTH-3', category: 'AUTH', description: 'Session management secure', status: 'pass', level: 1 },
  { id: 'MASVS-NETWORK-1', category: 'NETWORK', description: 'No cleartext traffic', status: 'fail', level: 1 },
  { id: 'MASVS-NETWORK-2', category: 'NETWORK', description: 'Certificate pinning implemented', status: 'fail', level: 2 },
  { id: 'MASVS-NETWORK-3', category: 'NETWORK', description: 'TLS configuration secure', status: 'warn', level: 1 },
  { id: 'MASVS-PLATFORM-1', category: 'PLATFORM', description: 'No exported components without permission', status: 'fail', level: 1 },
  { id: 'MASVS-PLATFORM-2', category: 'PLATFORM', description: 'Input validation on all intents', status: 'pass', level: 1 },
  { id: 'MASVS-PLATFORM-3', category: 'PLATFORM', description: 'WebView security configured', status: 'warn', level: 2 },
  { id: 'MASVS-CODE-1', category: 'CODE', description: 'No SQL injection vulnerabilities', status: 'fail', level: 1 },
  { id: 'MASVS-CODE-2', category: 'CODE', description: 'Debug logs stripped in release', status: 'fail', level: 1 },
  { id: 'MASVS-CODE-3', category: 'CODE', description: 'Code obfuscation applied', status: 'skip', level: 2 },
  { id: 'MASVS-RESILIENCE-1', category: 'RESILIENCE', description: 'App not debuggable in release', status: 'fail', level: 1 },
  { id: 'MASVS-RESILIENCE-2', category: 'RESILIENCE', description: 'Tamper detection implemented', status: 'skip', level: 2 },
  { id: 'MASVS-RESILIENCE-3', category: 'RESILIENCE', description: 'Anti-reverse engineering controls', status: 'skip', level: 2 },
  { id: 'MASVS-PRIVACY-1', category: 'PRIVACY', description: 'Minimal permissions declared', status: 'fail', level: 1 },
  { id: 'MASVS-PRIVACY-2', category: 'PRIVACY', description: 'Privacy policy accessible', status: 'pass', level: 1 },
  { id: 'MASVS-PRIVACY-3', category: 'PRIVACY', description: 'Data collection transparency', status: 'warn', level: 2 },
];

const CATEGORY_SCORES: Record<string, { pass: number; fail: number; warn: number; skip: number }> = {
  STORAGE: { pass: 0, fail: 2, warn: 1, skip: 0 },
  CRYPTO: { pass: 1, fail: 1, warn: 1, skip: 0 },
  AUTH: { pass: 2, fail: 1, warn: 0, skip: 0 },
  NETWORK: { pass: 0, fail: 2, warn: 1, skip: 0 },
  PLATFORM: { pass: 1, fail: 1, warn: 1, skip: 0 },
  CODE: { pass: 0, fail: 2, warn: 0, skip: 1 },
  RESILIENCE: { pass: 0, fail: 1, warn: 0, skip: 2 },
  PRIVACY: { pass: 1, fail: 1, warn: 1, skip: 0 },
};

function RadarChart({ scores }: { scores: Record<string, { pass: number; fail: number; warn: number; skip: number }> }) {
  const cats = Object.keys(scores);
  const n = cats.length;
  const cx = 180, cy = 180, r = 140;
  const angleStep = (2 * Math.PI) / n;

  const points = cats.map((cat, i) => {
    const s = scores[cat];
    const total = s.pass + s.fail + s.warn + s.skip;
    const pct = total > 0 ? s.pass / total : 0;
    const dist = pct * r;
    const angle = i * angleStep - Math.PI / 2;
    return { x: cx + dist * Math.cos(angle), y: cy + dist * Math.sin(angle), pct };
  });

  const webLines = cats.map((_, i) => {
    const angle = i * angleStep - Math.PI / 2;
    return { x2: cx + r * Math.cos(angle), y2: cy + r * Math.sin(angle) };
  });

  const rings = [0.25, 0.5, 0.75, 1].map((scale) =>
    cats.map((_, i) => {
      const angle = i * angleStep - Math.PI / 2;
      return { x: cx + r * scale * Math.cos(angle), y: cy + r * scale * Math.sin(angle) };
    })
  );

  return (
    <svg viewBox="0 0 360 360" className="w-full max-w-sm mx-auto">
      {rings.map((ring, ri) => (
        <polygon key={ri} points={ring.map((p) => `${p.x},${p.y}`).join(' ')} fill="none" stroke="#334155" strokeWidth="1" />
      ))}
      {webLines.map((l, i) => (
        <line key={i} x1={cx} y1={cy} x2={l.x2} y2={l.y2} stroke="#334155" strokeWidth="1" />
      ))}
      <polygon
        points={points.map((p) => `${p.x},${p.y}`).join(' ')}
        fill="rgba(14,165,233,0.15)"
        stroke="#0ea5e9"
        strokeWidth="2"
      />
      {points.map((p, i) => (
        <g key={i}>
          <circle cx={p.x} cy={p.y} r="4" fill="#0ea5e9" />
          <text x={cx + (r + 20) * Math.cos(i * angleStep - Math.PI / 2)} y={cy + (r + 20) * Math.sin(i * angleStep - Math.PI / 2)} textAnchor="middle" dominantBaseline="middle" className="fill-slate-400 text-[10px]">{cats[i]}</text>
        </g>
      ))}
    </svg>
  );
}

function CategoryCard({ catKey, label, emoji, scores }: { catKey: string; label: string; emoji: string; scores: { pass: number; fail: number; warn: number; skip: number } }) {
  const total = scores.pass + scores.fail + scores.warn + scores.skip;
  const pct = total > 0 ? Math.round((scores.pass / total) * 100) : 0;
  const barColor = pct >= 80 ? 'bg-emerald-500' : pct >= 50 ? 'bg-yellow-500' : 'bg-red-500';

  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium text-slate-200">{emoji} {label}</span>
        <span className="text-xs text-slate-400">{pct}%</span>
      </div>
      <div className="w-full bg-slate-700 rounded-full h-2 mb-2">
        <div className={`${barColor} h-2 rounded-full`} style={{ width: `${pct}%` }} />
      </div>
      <div className="flex gap-3 text-xs">
        <span className="text-emerald-400">✓{scores.pass}</span>
        <span className="text-red-400">✗{scores.fail}</span>
        <span className="text-yellow-400">⚠{scores.warn}</span>
        <span className="text-slate-500">—{scores.skip}</span>
      </div>
    </div>
  );
}

export default function MASVSPage() {
  const [levelFilter, setLevelFilter] = useState<1 | 2 | 'all'>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');

  const filtered = DEMO_TESTS.filter((t) => {
    if (levelFilter !== 'all' && t.level !== levelFilter) return false;
    if (categoryFilter !== 'all' && t.category !== categoryFilter) return false;
    return true;
  });

  const l1Tests = DEMO_TESTS.filter((t) => t.level === 1);
  const l2Tests = DEMO_TESTS.filter((t) => t.level === 2);
  const l1Pass = l1Tests.every((t) => t.status === 'pass');
  const l2Pass = l2Tests.every((t) => t.status === 'pass');

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">🛡️ MASVS Compliance</h1>
          <p className="text-slate-400 text-sm mt-1">OWASP MASVS 2.0 verification results</p>
        </div>
        <div className="flex gap-3">
          <div className={`flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-medium ${l1Pass ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-red-500/10 border-red-500/30 text-red-400'}`}>
            L1 {l1Pass ? '✅' : '❌'}
          </div>
          <div className={`flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-medium ${l2Pass ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-red-500/10 border-red-500/30 text-red-400'}`}>
            L2 {l2Pass ? '✅' : '❌'}
          </div>
        </div>
      </div>

      {/* Radar Chart */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">📊 Category Radar</h2>
        <RadarChart scores={CATEGORY_SCORES} />
      </div>

      {/* Category Score Cards */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-3">🏷️ Category Scores</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {CATEGORIES.map((cat) => (
            <CategoryCard key={cat.key} catKey={cat.key} label={cat.label} emoji={cat.emoji} scores={CATEGORY_SCORES[cat.key]} />
          ))}
        </div>
      </div>

      {/* Test Results Table */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-3">📋 Test Results</h2>
        <div className="flex gap-2 mb-3">
          <select value={categoryFilter} onChange={(e) => setCategoryFilter(e.target.value)} className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-300">
            <option value="all">All Categories</option>
            {CATEGORIES.map((c) => <option key={c.key} value={c.key}>{c.label}</option>)}
          </select>
          <select value={levelFilter} onChange={(e) => setLevelFilter(e.target.value as 'all' | 1 | 2)} className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-300">
            <option value="all">All Levels</option>
            <option value="1">L1</option>
            <option value="2">L2</option>
          </select>
        </div>
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700 text-slate-400 text-xs uppercase">
                <th className="px-4 py-3 text-left">Test ID</th>
                <th className="px-4 py-3 text-left">Description</th>
                <th className="px-4 py-3 text-left">Category</th>
                <th className="px-4 py-3 text-left">Level</th>
                <th className="px-4 py-3 text-left">Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((t) => (
                <tr key={t.id} className="border-b border-slate-700/50 hover:bg-slate-700/20">
                  <td className="px-4 py-3 text-sky-400 font-mono text-xs">{t.id}</td>
                  <td className="px-4 py-3 text-slate-300">{t.description}</td>
                  <td className="px-4 py-3 text-slate-400">{t.category}</td>
                  <td className="px-4 py-3 text-slate-400">L{t.level}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium border ${STATUS_STYLES[t.status]}`}>{STATUS_LABELS[t.status]}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}