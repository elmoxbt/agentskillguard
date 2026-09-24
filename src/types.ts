export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Finding {
  ruleId: string;
  capability: string;
  severity: Severity;
  description: string;
  file: string;
  line: number;
  snippet: string;
}

export interface ToolMetadata {
  name?: string;
  version?: string;
  description?: string;
  declaredTools?: string[];
  source: string;
}

export interface Violation {
  capability: string;
  severity: Severity;
  message: string;
}

export interface ScanResult {
  target: string;
  scannedAt: string;
  filesScanned: number;
  metadata: ToolMetadata | null;
  findings: Finding[];
  capabilities: string[];
  violations: Violation[];
  verdict: 'ALLOW' | 'WARN' | 'BLOCK';
  verdictReason: string;
}
