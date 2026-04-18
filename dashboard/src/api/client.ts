/** MobiusSec API client */

import type { ScanResult, ScanStatus, DiffResult } from '../types';

const API_BASE = '/api/v1';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export const api = {
  /** Submit a scan */
  submitScan: (appPath: string) =>
    request<{ scanId: string; status: string }>('/scan', {
      method: 'POST',
      body: JSON.stringify({ appPath }),
    }),

  /** Get scan status */
  getScanStatus: (id: string) =>
    request<ScanStatus>(`/scan/${id}`),

  /** Get scan results */
  getScanResults: (id: string) =>
    request<ScanResult>(`/scan/${id}/results`),

  /** Get MASVS compliance */
  getMASVS: (id: string) =>
    request<Record<string, unknown>>(`/scan/${id}/masvs`),

  /** Get privacy analysis */
  getPrivacy: (id: string) =>
    request<Record<string, unknown>>(`/scan/${id}/privacy`),

  /** Get SBOM */
  getSBOM: (id: string) =>
    request<Record<string, unknown>>(`/scan/${id}/sbom`),

  /** Get report */
  getReport: (id: string, format: 'json' | 'sarif' = 'json') =>
    request<ScanResult | Record<string, unknown>>(`/scan/${id}/report?format=${format}`),

  /** Compare two scans */
  diff: (scanId1: string, scanId2: string) =>
    request<DiffResult>('/diff', {
      method: 'POST',
      body: JSON.stringify({ scanId1, scanId2 }),
    }),
};