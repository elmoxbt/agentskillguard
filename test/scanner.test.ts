/**
 * Minimal assertion-based smoke test — no test framework dependency.
 * Run with: npm test
 */
import * as assert from 'assert';
import * as path from 'path';
import { scanTarget } from '../src/scanner';
import { loadPolicy } from '../src/policy/loader';

function run() {
  const policy = loadPolicy(path.join(__dirname, '../policies/example-swap-agent.yaml'));

  const malicious = scanTarget(path.join(__dirname, '../examples/malicious-tool'), policy);
  assert.strictEqual(malicious.verdict, 'BLOCK', `expected malicious-tool to BLOCK, got ${malicious.verdict}`);
  assert.ok(malicious.findings.some((f) => f.capability === 'wallet.private_key_access'), 'expected private key finding');
  assert.ok(malicious.findings.some((f) => f.capability === 'system.shell_exec'), 'expected shell-exec finding');
  assert.ok(malicious.findings.some((f) => f.capability === 'code.dynamic_load'), 'expected dynamic-code-load finding');
  console.log('\u2713 malicious-tool correctly BLOCKED (%d findings, %d violations)', malicious.findings.length, malicious.violations.length);

  const safe = scanTarget(path.join(__dirname, '../examples/safe-tool'), policy);
  assert.strictEqual(safe.verdict, 'ALLOW', `expected safe-tool to ALLOW, got ${safe.verdict}`);
  console.log('\u2713 safe-tool correctly ALLOWED (%d findings, %d violations)', safe.findings.length, safe.violations.length);

  // No policy supplied at all: hard-floor capabilities must still block.
  const noPolicy = scanTarget(path.join(__dirname, '../examples/malicious-tool'), null);
  assert.strictEqual(noPolicy.verdict, 'BLOCK', 'expected hard-floor capabilities to BLOCK even with no policy');
  console.log('\u2713 hard-floor capabilities BLOCK even without a policy manifest');

  console.log('\nAll tests passed.');
}

run();
