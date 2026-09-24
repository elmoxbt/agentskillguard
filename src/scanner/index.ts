import { walk } from '../utils/fileWalker';
import { analyzeFile } from './staticAnalyzer';
import { readMetadata } from './mcpMetadata';
import { evaluatePolicy } from '../policy/enforcer';
import { computeVerdict } from '../report/verdict';
import { Policy } from '../policy/schema';
import { Finding, ScanResult } from '../types';

export function scanTarget(target: string, policy: Policy | null): ScanResult {
  const files = walk(target);
  const metadata = readMetadata(target);

  const findings: Finding[] = [];
  for (const file of files) {
    findings.push(...analyzeFile(file));
  }

  const violations = evaluatePolicy(findings, policy, files);
  const { verdict, reason } = computeVerdict(violations);
  const capabilities = Array.from(new Set(findings.map((f) => f.capability))).sort();

  return {
    target,
    scannedAt: new Date().toISOString(),
    filesScanned: files.length,
    metadata,
    findings,
    capabilities,
    violations,
    verdict,
    verdictReason: reason,
  };
}
