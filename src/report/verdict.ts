import { Violation } from '../types';

/**
 * Verdict is driven entirely by *violations* (findings checked against the
 * policy + hard floor), not raw finding counts. A tool can have plenty of
 * informational MEDIUM findings (e.g. "reads process.env") and still ALLOW,
 * as long as nothing crosses a permission boundary.
 */
export function computeVerdict(violations: Violation[]): { verdict: 'ALLOW' | 'WARN' | 'BLOCK'; reason: string } {
  const critical = violations.filter((v) => v.severity === 'CRITICAL');
  const high = violations.filter((v) => v.severity === 'HIGH');

  if (critical.length > 0) {
    return {
      verdict: 'BLOCK',
      reason: `${critical.length} critical violation(s): ${critical.map((v) => v.capability).join(', ')}.`,
    };
  }

  if (high.length > 0) {
    return {
      verdict: 'WARN',
      reason: `${high.length} high-severity issue(s) require manual review: ${high.map((v) => v.capability).join(', ')}.`,
    };
  }

  if (violations.length > 0) {
    return {
      verdict: 'WARN',
      reason: `${violations.length} lower-severity policy issue(s) found. Review recommended before granting broader access.`,
    };
  }

  return { verdict: 'ALLOW', reason: 'No policy violations detected. Review any informational findings below before deploying.' };
}
