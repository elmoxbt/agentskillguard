import * as fs from 'fs';
import { RULES } from '../rules/rules';
import { Finding } from '../types';

/** Runs every rule against every line of a single file. */
export function analyzeFile(filePath: string): Finding[] {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split(/\r?\n/);
  const findings: Finding[] = [];

  lines.forEach((line, idx) => {
    for (const rule of RULES) {
      if (rule.pattern.test(line)) {
        findings.push({
          ruleId: rule.id,
          capability: rule.capability,
          severity: rule.severity,
          description: rule.description,
          file: filePath,
          line: idx + 1,
          snippet: line.trim().slice(0, 160),
        });
      }
    }
  });

  return findings;
}

/** Pulls literal http(s) URLs out of a file's raw text. */
export function extractLiteralUrls(content: string): string[] {
  const urlRegex = /https?:\/\/[^\s'"`)]+/g;
  return Array.from(content.matchAll(urlRegex)).map((m) => m[0]);
}

/** Converts literal URLs into bare hostnames for allowlist comparison. */
export function extractDomains(urls: string[]): string[] {
  const domains = new Set<string>();
  for (const url of urls) {
    try {
      domains.add(new URL(url).hostname);
    } catch {
      // malformed / template-interpolated URL — ignore, it will already
      // have been flagged as a dynamic-url-construction finding instead.
    }
  }
  return Array.from(domains);
}
