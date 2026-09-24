import chalk from 'chalk';
import { ScanResult, Finding } from '../types';

const SEVERITY_COLOR: Record<string, (s: string) => string> = {
  CRITICAL: chalk.bgRed.white.bold,
  HIGH: chalk.red.bold,
  MEDIUM: chalk.yellow,
  LOW: chalk.gray,
};

function verdictBadge(verdict: string): string {
  const label = ` ${verdict} `;
  if (verdict === 'BLOCK') return chalk.bgRed.white.bold(label);
  if (verdict === 'WARN') return chalk.bgYellow.black.bold(label);
  return chalk.bgGreen.black.bold(label);
}

export function printReport(result: ScanResult): void {
  console.log('');
  console.log(chalk.bold('AGENTSKILLGUARD'));
  console.log(chalk.dim(`target: ${result.target}`));
  if (result.metadata?.name) {
    console.log(chalk.dim(`tool:   ${result.metadata.name}${result.metadata.version ? '@' + result.metadata.version : ''}`));
  }
  console.log(chalk.dim(`files scanned: ${result.filesScanned}`));
  console.log('');

  if (result.findings.length === 0) {
    console.log(chalk.green('No suspicious capabilities detected.'));
  } else {
    console.log(chalk.bold('Capabilities detected:'));
    const byCapability = new Map<string, Finding[]>();
    for (const f of result.findings) {
      if (!byCapability.has(f.capability)) byCapability.set(f.capability, []);
      byCapability.get(f.capability)!.push(f);
    }
    for (const [capability, findings] of byCapability) {
      const sev = findings[0].severity;
      const color = SEVERITY_COLOR[sev] ?? ((s: string) => s);
      console.log(`  [x] ${color(sev.padEnd(8))} ${capability} — ${findings[0].description}`);
      for (const f of findings.slice(0, 3)) {
        console.log(chalk.dim(`        ${f.file}:${f.line}  ${f.snippet}`));
      }
      if (findings.length > 3) {
        console.log(chalk.dim(`        …and ${findings.length - 3} more occurrence(s)`));
      }
    }
  }

  console.log('');
  if (result.violations.length > 0) {
    console.log(chalk.bold('Policy violations:'));
    for (const v of result.violations) {
      const color = SEVERITY_COLOR[v.severity] ?? ((s: string) => s);
      console.log(`  [!] ${color(v.severity.padEnd(8))} ${v.message}`);
    }
    console.log('');
  }

  console.log(`Recommended action: ${verdictBadge(result.verdict)}`);
  console.log(chalk.dim(result.verdictReason));
  console.log('');
}
