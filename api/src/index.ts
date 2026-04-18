/** MobiusSec API Server — Fastify + WebSocket */

import Fastify from 'fastify';
import cors from '@fastify/cors';
import websocket from '@fastify/websocket';
import { exec } from 'child_process';
import { randomUUID } from 'crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, extname } from 'path';

const app = Fastify({ logger: true });
app.register(cors, { origin: true });
app.register(websocket);

// In-memory scan store (swap for DB in production)
const scans = new Map();

// ─── Helpers ───────────────────────────────────────────────

function detectPlatform(filename: string): 'android' | 'ios' | 'unknown' {
  const ext = extname(filename).toLowerCase();
  if (ext === '.apk') return 'android';
  if (ext === '.ipa') return 'ios';
  return 'unknown';
}

function runScan(appPath: string, scanId: string, ws?: any) {
  const platform = detectPlatform(appPath);
  scans.set(scanId, {
    id: scanId,
    appPath,
    platform,
    status: 'running',
    progress: 0,
    results: null,
    masvs: null,
    privacy: null,
    sbom: null,
    startedAt: new Date().toISOString(),
  });

  const cmd = `cd "${process.cwd()}" && python3 -c "
import json, sys
sys.path.insert(0, 'core')
from mobiussec.scanner import Scanner
from mobiussec.models import ScanConfig, Platform
from pathlib import Path

config = ScanConfig(app_path=Path('${appPath}'))
scanner = Scanner(config)
result = scanner.scan()
output = result.to_dict()
if scanner.privacy_report:
    output['privacy'] = scanner.privacy_report
if scanner.sbom:
    output['sbom'] = scanner.sbom
json.dump(output, sys.stdout, default=str)
"`;

  const child = exec(cmd, { timeout: 300000, maxBuffer: 50 * 1024 * 1024 }, (error, stdout, stderr) => {
    const scan = scans.get(scanId);
    if (!scan) return;

    if (error) {
      scan.status = 'error';
      scan.error = stderr?.toString() || error.message;
    } else {
      try {
        const data = JSON.parse(stdout);
        scan.results = data;
        scan.masvs = data.masvs_result || null;
        scan.privacy = data.privacy || null;
        scan.sbom = data.sbom || null;
        scan.status = 'complete';
      } catch (e: any) {
        scan.status = 'error';
        scan.error = `JSON parse error: ${e.message}`;
      }
    }
    scan.completedAt = new Date().toISOString();

    if (ws && ws.readyState === 1) {
      ws.send(JSON.stringify({ type: 'scan_complete', scanId, status: scan.status }));
    }
  });

  // Progress updates via WebSocket
  if (ws) {
    const steps = ['extracting', 'analyzing', 'scanning_secrets', 'running_yara', 'privacy_analysis', 'generating_sbom', 'mapping_masvs', 'complete'];
    let step = 0;
    const interval = setInterval(() => {
      const scan = scans.get(scanId);
      if (!scan || scan.status !== 'running') {
        clearInterval(interval);
        return;
      }
      step = Math.min(step + 1, steps.length - 1);
      scan.progress = Math.round((step / steps.length) * 100);
      if (ws.readyState === 1) {
        ws.send(JSON.stringify({ type: 'scan_progress', scanId, step: steps[step], progress: scan.progress }));
      }
    }, 2000);
  }
}

// ─── REST Endpoints ────────────────────────────────────────

/** Submit app for scanning */
app.post('/api/v1/scan', async (request, reply) => {
  const { appPath } = request.body as any;
  if (!appPath || !existsSync(appPath)) {
    return reply.code(400).send({ error: 'appPath is required and must exist' });
  }
  const scanId = randomUUID();
  runScan(appPath, scanId);
  return { scanId, status: 'running' };
});

/** Get scan status */
app.get('/api/v1/scan/:id', async (request, reply) => {
  const { id } = request.params as any;
  const scan = scans.get(id);
  if (!scan) return reply.code(404).send({ error: 'Scan not found' });
  return {
    id: scan.id,
    status: scan.status,
    progress: scan.progress,
    platform: scan.platform,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt || null,
    error: scan.error || null,
  };
});

/** Get scan results */
app.get('/api/v1/scan/:id/results', async (request, reply) => {
  const { id } = request.params as any;
  const scan = scans.get(id);
  if (!scan) return reply.code(404).send({ error: 'Scan not found' });
  if (scan.status !== 'complete') return reply.code(202).send({ status: scan.status, progress: scan.progress });
  return scan.results;
});

/** Get MASVS compliance mapping */
app.get('/api/v1/scan/:id/masvs', async (request, reply) => {
  const { id } = request.params as any;
  const scan = scans.get(id);
  if (!scan) return reply.code(404).send({ error: 'Scan not found' });
  if (!scan.masvs) return reply.code(404).send({ error: 'MASVS results not available' });
  return scan.masvs;
});

/** Get privacy analysis */
app.get('/api/v1/scan/:id/privacy', async (request, reply) => {
  const { id } = request.params as any;
  const scan = scans.get(id);
  if (!scan) return reply.code(404).send({ error: 'Scan not found' });
  if (!scan.privacy) return reply.code(404).send({ error: 'Privacy results not available' });
  return scan.privacy;
});

/** Get SBOM (CycloneDX) */
app.get('/api/v1/scan/:id/sbom', async (request, reply) => {
  const { id } = request.params as any;
  const scan = scans.get(id);
  if (!scan) return reply.code(404).send({ error: 'Scan not found' });
  if (!scan.sbom) return reply.code(404).send({ error: 'SBOM not available' });
  return scan.sbom;
});

/** Get report (HTML/SARIF/JSON) */
app.get('/api/v1/scan/:id/report', async (request, reply) => {
  const { id } = request.params as any;
  const format = (request.query as any).format || 'json';
  const scan = scans.get(id);
  if (!scan) return reply.code(404).send({ error: 'Scan not found' });
  if (scan.status !== 'complete') return reply.code(202).send({ status: scan.status });

  if (format === 'sarif') {
    return generateSarif(scan.results);
  }
  return scan.results;
});

/** Compare two scans */
app.post('/api/v1/diff', async (request, reply) => {
  const { scanId1, scanId2 } = request.body as any;
  const scan1 = scans.get(scanId1);
  const scan2 = scans.get(scanId2);
  if (!scan1 || !scan2) return reply.code(404).send({ error: 'One or both scans not found' });
  if (scan1.status !== 'complete' || scan2.status !== 'complete') {
    return reply.code(202).send({ error: 'Both scans must be complete' });
  }
  return diffScans(scan1.results, scan2.results);
});

// ─── WebSocket ─────────────────────────────────────────────

app.register(async function (fastify) {
  fastify.get('/ws/scan/:id', { websocket: true }, (connection, request) => {
    const { id } = request.params as any;
    const scan = scans.get(id);

    connection.socket.on('message', (message: Buffer) => {
      const data = JSON.parse(message.toString());
      if (data.type === 'subscribe' && scan) {
        // Send current status
        connection.socket.send(JSON.stringify({
          type: 'scan_status',
          scanId: id,
          status: scan.status,
          progress: scan.progress,
        }));
      }
    });

    // Send periodic updates
    const interval = setInterval(() => {
      const s = scans.get(id);
      if (!s || s.status !== 'running') {
        clearInterval(interval);
        if (s) {
          connection.socket.send(JSON.stringify({
            type: 'scan_complete',
            scanId: id,
            status: s.status,
          }));
        }
        connection.socket.close();
        return;
      }
      connection.socket.send(JSON.stringify({
        type: 'scan_progress',
        scanId: id,
        progress: s.progress,
        status: s.status,
      }));
    }, 2000);
  });
});

// ─── Report Generators ────────────────────────────────────

function generateSarif(results: any) {
  const rules: any[] = [];
  const resultsList: any[] = [];

  if (results?.findings) {
    for (const f of results.findings) {
      const ruleId = f.id || 'unknown';
      if (!rules.find(r => r.id === ruleId)) {
        rules.push({
          id: ruleId,
          shortDescription: { text: f.title },
          fullDescription: { text: f.description },
          helpUri: `https://mas.owasp.org/`,
          properties: { 'security-severity': f.severity },
        });
      }
      resultsList.push({
        ruleId,
        level: f.severity === 'critical' ? 'error' : f.severity === 'high' ? 'error' : 'warning',
        message: { text: f.description },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.file || 'unknown' },
            region: { startLine: f.line || 1 },
          },
        }],
      });
    }
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'MobiusSec',
          version: '0.1.0',
          informationUri: 'https://github.com/aiagentmackenzie-lang/MobiusSec',
          rules,
        },
      },
      results: resultsList,
    }],
  };
}

function diffScans(r1: any, r2: any) {
  const findings1 = new Map((r1?.findings || []).map((f: any) => [f.id, f]));
  const findings2 = new Map((r2?.findings || []).map((f: any) => [f.id, f]));

  const added: any[] = [];
  const removed: any[] = [];
  const unchanged: any[] = [];

  for (const [id, f] of findings2) {
    if (!findings1.has(id)) added.push(f);
    else unchanged.push(f);
  }
  for (const [id, f] of findings1) {
    if (!findings2.has(id)) removed.push(f);
  }

  return {
    added: added.length,
    removed: removed.length,
    unchanged: unchanged.length,
    addedFindings: added,
    removedFindings: removed,
    summary: {
      v1: { total: findings1.size, critical: [...findings1.values()].filter(f => f.severity === 'critical').length, high: [...findings1.values()].filter(f => f.severity === 'high').length },
      v2: { total: findings2.size, critical: [...findings2.values()].filter(f => f.severity === 'critical').length, high: [...findings2.values()].filter(f => f.severity === 'high').length },
    },
  };
}

// ─── Start ─────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';

app.listen({ port: PORT, host: HOST }, (err) => {
  if (err) {
    app.log.error(err);
    process.exit(1);
  }
  console.log(`🦞 MobiusSec API running on http://${HOST}:${PORT}`);
});

export default app;