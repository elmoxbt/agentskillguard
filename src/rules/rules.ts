import { Severity } from '../types';

export interface Rule {
  id: string;
  capability: string;
  severity: Severity;
  description: string;
  pattern: RegExp;
  recommendation: string;
}

/**
 * Static detection rules.
 *
 * Each rule is a single-line regex heuristic (MVP scope — see README for the
 * tree-sitter/AST upgrade path). A match means "this line is CAPABLE of the
 * behavior", not "this line is definitely malicious" — that judgment is made
 * by the policy enforcer + verdict engine, which weighs findings against the
 * capability manifest.
 */
export const RULES: Rule[] = [
  {
    id: 'wallet-signing-access',
    capability: 'wallet.signing',
    severity: 'CRITICAL',
    description: 'Tool can invoke wallet transaction/message signing.',
    pattern: /\b(signTransaction|signAllTransactions|signMessage|Keypair\.fromSecretKey)\b/,
    recommendation: 'Only allow if the policy explicitly grants wallet.signing and the code path is audited.',
  },
  {
    id: 'private-key-access',
    capability: 'wallet.private_key_access',
    severity: 'CRITICAL',
    description: 'Tool references private key / secret / mnemonic material directly.',
    pattern: /(PRIVATE_KEY|SECRET_KEY|secretKey\s*[:=]|mnemonic|seedPhrase|seed_phrase)/i,
    recommendation: 'Tools should never need raw key material. Treat as an automatic block.',
  },
  {
    id: 'network-call',
    capability: 'network.http',
    severity: 'MEDIUM',
    description: 'Tool performs outbound HTTP(S) requests.',
    pattern: /\b(fetch|axios\.(get|post|put|delete|patch|request)|http\.request|https\.request|XMLHttpRequest)\s*\(/,
    recommendation: 'Cross-check target domains against the network allowlist in the policy manifest.',
  },
  {
    id: 'dynamic-url-construction',
    capability: 'network.dynamic_url',
    severity: 'HIGH',
    description: 'Request URL is built from a variable/expression rather than a static string literal.',
    pattern: /\b(fetch|axios\.\w+)\s*\(\s*[^'"`\s)][^)]*\)/,
    recommendation: 'Dynamic URLs cannot be statically allowlisted — treat as arbitrary network access.',
  },
  {
    id: 'tx-destination-modification',
    capability: 'solana.tx_modification',
    severity: 'HIGH',
    description: 'Tool manipulates transaction instructions or recipient/destination fields.',
    pattern: /\b(transaction|tx)\.(instructions|add)\s*\(|\b(recipient|destination|toPubkey)\s*=/,
    recommendation: 'Manually review: confirm destination addresses are user-supplied, not tool-controlled.',
  },
  {
    id: 'shell-exec',
    capability: 'system.shell_exec',
    severity: 'CRITICAL',
    description: 'Tool can execute OS shell commands via child_process.',
    pattern: /require\(\s*['"]child_process['"]\s*\)|\b(execSync|spawnSync|exec|spawn|fork)\s*\(/,
    recommendation: 'No legitimate Solana/agent tool needs shell access. Treat as an automatic block.',
  },
  {
    id: 'dynamic-code-load',
    capability: 'code.dynamic_load',
    severity: 'CRITICAL',
    description: 'Tool loads or executes code dynamically at runtime (eval, new Function, dynamic require, vm module).',
    pattern: /\beval\s*\(|new\s+Function\s*\(|vm\.runInNewContext|vm\.runInThisContext|require\(\s*[a-zA-Z_$][\w$]*\s*\)/,
    recommendation: 'Dynamic code loading defeats static review entirely. Treat as an automatic block.',
  },
  {
    id: 'unlimited-token-approval',
    capability: 'solana.unlimited_approval',
    severity: 'HIGH',
    description: 'Tool requests unlimited or maximum token approvals/authority delegation.',
    pattern: /approve\([^)]*(MAX_UINT256|0xffffffff|Infinity)|setAuthority\([^)]*null/i,
    recommendation: 'Unlimited approvals should never be requested by an automated agent tool.',
  },
  {
    id: 'env-read',
    capability: 'system.env_read',
    severity: 'MEDIUM',
    description: 'Tool reads process environment variables.',
    pattern: /\bprocess\.env\b/,
    recommendation: 'Confirm env vars read are not secrets being staged for exfiltration over a network call.',
  },
  {
    id: 'obfuscated-execution',
    capability: 'code.obfuscation',
    severity: 'CRITICAL',
    description: 'Tool decodes an obfuscated (base64/hex) payload and executes it.',
    pattern: /(atob\(|Buffer\.from\([^)]*base64[^)]*\))[^;]*\b(eval|Function)\b/i,
    recommendation: 'Obfuscated execution is a strong malware indicator. Treat as an automatic block.',
  },
  {
    id: 'filesystem-write',
    capability: 'system.filesystem_write',
    severity: 'MEDIUM',
    description: 'Tool writes to or deletes files on disk.',
    pattern: /\bfs\.(writeFile(Sync)?|appendFile(Sync)?|unlink(Sync)?|rm(Sync)?|rmdir(Sync)?)\s*\(/,
    recommendation: 'Confirm writes are scoped to an expected working directory, not arbitrary paths.',
  },
];
