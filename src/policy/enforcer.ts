import * as fs from 'fs';
import { Finding, Violation } from '../types';
import { Policy } from './schema';
import { extractDomains, extractLiteralUrls } from '../scanner/staticAnalyzer';

/**
 * Capabilities that are never acceptable for an agent tool, regardless of
 * what a policy manifest grants. A policy can only narrow permissions
 * below this floor — it can never widen past it.
 */
const ALWAYS_BLOCKED_CAPABILITIES = new Set([
  'wallet.private_key_access',
  'system.shell_exec',
  'code.dynamic_load',
  'code.obfuscation',
  'solana.unlimited_approval',
]);

export function evaluatePolicy(findings: Finding[], policy: Policy | null, filesScanned: string[]): Violation[] {
  const violations: Violation[] = [];
  const capabilitiesSeen = new Set(findings.map((f) => f.capability));

  // 1. Hard floor — applies even with no policy supplied at all.
  for (const cap of capabilitiesSeen) {
    if (ALWAYS_BLOCKED_CAPABILITIES.has(cap)) {
      const f = findings.find((x) => x.capability === cap)!;
      violations.push({
        capability: cap,
        severity: 'CRITICAL',
        message: `${cap} is never permitted, regardless of policy (${f.description})`,
      });
    }
  }

  if (!policy) {
    return violations;
  }

  // 2. Wallet signing must be explicitly granted.
  if (capabilitiesSeen.has('wallet.signing') && !policy.permissions.wallet.signing) {
    violations.push({
      capability: 'wallet.signing',
      severity: 'CRITICAL',
      message: 'Tool signs transactions but policy.permissions.wallet.signing is false.',
    });
  }

  // 3. Dynamic URLs can never be verified against an allowlist.
  if (capabilitiesSeen.has('network.dynamic_url')) {
    violations.push({
      capability: 'network.dynamic_url',
      severity: 'HIGH',
      message: 'Tool builds request URLs dynamically — the target domain cannot be statically verified against the allowlist.',
    });
  }

  // 4. Any literal domain contacted must be in the allowlist.
  if (capabilitiesSeen.has('network.http')) {
    const allowlist = new Set(policy.permissions.network.domains);
    const seenDomains = new Set<string>();
    for (const file of filesScanned) {
      const content = fs.readFileSync(file, 'utf-8');
      extractDomains(extractLiteralUrls(content)).forEach((d) => seenDomains.add(d));
    }
    for (const domain of seenDomains) {
      if (!allowlist.has(domain)) {
        violations.push({
          capability: 'network.http',
          severity: 'HIGH',
          message: `Tool contacts domain "${domain}", which is not in the policy's network.domains allowlist.`,
        });
      }
    }
  }

  // 5. Transaction manipulation requires at least one granted Solana program.
  if (capabilitiesSeen.has('solana.tx_modification') && policy.permissions.solana.programs.length === 0) {
    violations.push({
      capability: 'solana.tx_modification',
      severity: 'HIGH',
      message: 'Tool modifies transaction instructions but the policy grants no Solana program permissions.',
    });
  }

  return violations;
}
