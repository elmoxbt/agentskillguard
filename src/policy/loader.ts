import * as fs from 'fs';
import * as yaml from 'js-yaml';
import { Policy, PolicySchema } from './schema';

export function loadPolicy(policyPath: string): Policy {
  const raw = fs.readFileSync(policyPath, 'utf-8');
  const parsed = yaml.load(raw);
  const result = PolicySchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid policy manifest (${policyPath}): ${issues}`);
  }
  return result.data;
}

export const DEFAULT_POLICY_YAML = `name: default-deny
description: "Starter policy — deny everything until explicitly granted."

permissions:
  solana:
    programs: []
    max_sol: 0
    tokens: []

  network:
    domains: []

  wallet:
    signing: false
    max_transactions_per_hour: 0
`;
