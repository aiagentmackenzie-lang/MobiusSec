/** API types matching the MobiusSec Python models */

export type Platform = 'android' | 'ios';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type MASVSStatus = 'pass' | 'fail' | 'warn' | 'skip';

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  masvs_category: string;
  masvs_test_id?: string;
  platform: Platform;
  file?: string;
  line?: number;
  remediation?: string;
}

export interface MASVSCategoryScore {
  pass: number;
  fail: number;
  warn: number;
  skip: number;
}

export interface MASVSResult {
  l1_ready: boolean;
  l2_ready: boolean;
  category_scores: Record<string, MASVSCategoryScore>;
  total_tests: number;
  passed: number;
  failed: number;
}

export interface ScanResult {
  app_path: string;
  platform: Platform;
  package_name: string;
  app_name: string;
  version: string;
  findings: Finding[];
  masvs_result?: MASVSResult;
  privacy?: Record<string, unknown>;
  sbom?: Record<string, unknown>;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  scan_time_seconds: number;
}

export interface ScanStatus {
  id: string;
  status: 'running' | 'complete' | 'error';
  progress: number;
  platform?: Platform;
  startedAt: string;
  completedAt?: string;
  error?: string;
}

export interface DiffResult {
  added: Finding[];
  removed: Finding[];
  severity_changes: Array<{
    id: string;
    title: string;
    old_severity: Severity;
    new_severity: Severity;
    direction: 'worse' | 'improved';
  }>;
  verdict: string;
  summary: {
    v1: { total_findings: number; critical: number; high: number; medium: number };
    v2: { total_findings: number; critical: number; high: number; medium: number };
    delta: { total: number; critical: number; high: number };
  };
}