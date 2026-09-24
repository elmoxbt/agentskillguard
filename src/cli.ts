#!/usr/bin/env node
import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import chalk from 'chalk';
import { scanTarget } from './scanner';
import { loadPolicy, DEFAULT_POLICY_YAML } from './policy/loader';
import { printReport } from './report/formatter';
import { saveScan, listScans } from './db/store';

const program = new Command();

program
  .name('skillguard')
  .description('AgentSkillGuard — static security scanner for AI agent tools that touch a Solana wallet.')
  .version('0.1.0');

program
  .command('scan <target>')
  .description('Scan a tool directory or file for dangerous capabilities')
  .option('-p, --policy <file>', 'Path to a YAML capability manifest to enforce')
  .option('--json', 'Print machine-readable JSON instead of the formatted report')
  .option('--no-save', 'Do not persist this scan to the local history database')
  .action((target: string, opts: { policy?: string; json?: boolean; save: boolean }) => {
    const resolvedTarget = path.resolve(target);
    if (!fs.existsSync(resolvedTarget)) {
      console.error(chalk.red(`Target not found: ${resolvedTarget}`));
      process.exitCode = 1;
      return;
    }

    const policy = opts.policy ? loadPolicy(path.resolve(opts.policy)) : null;
    const result = scanTarget(resolvedTarget, policy);

    if (opts.save) {
      try {
        saveScan(result);
      } catch (err) {
        console.error(chalk.yellow(`Warning: could not save scan history (${(err as Error).message})`));
      }
    }

    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      printReport(result);
    }

    if (result.verdict === 'BLOCK') {
      process.exitCode = 2;
    } else if (result.verdict === 'WARN') {
      process.exitCode = 1;
    }
  });

program
  .command('init-policy')
  .description('Write a starter deny-by-default policy manifest')
  .option('-o, --out <file>', 'Output path', 'skillguard.policy.yaml')
  .action((opts: { out: string }) => {
    const outPath = path.resolve(opts.out);
    if (fs.existsSync(outPath)) {
      console.error(chalk.red(`Refusing to overwrite existing file: ${outPath}`));
      process.exitCode = 1;
      return;
    }
    fs.writeFileSync(outPath, DEFAULT_POLICY_YAML, 'utf-8');
    console.log(chalk.green(`Wrote starter policy to ${outPath}`));
  });

program
  .command('history')
  .description('Show recent scans from local history')
  .option('-n, --limit <n>', 'Number of rows to show', '20')
  .action((opts: { limit: string }) => {
    const rows = listScans(parseInt(opts.limit, 10));
    if (rows.length === 0) {
      console.log(chalk.dim('No scans recorded yet. Run `skillguard scan <target>` first.'));
      return;
    }
    for (const r of rows) {
      const label = String(r.verdict).padEnd(6);
      const colored = r.verdict === 'BLOCK' ? chalk.red(label) : r.verdict === 'WARN' ? chalk.yellow(label) : chalk.green(label);
      console.log(
        `#${r.id}  ${r.scanned_at}  ${colored}  ${r.tool_name ?? '(unnamed)'}  ${r.target}  ` +
          chalk.dim(`(${r.findings_count} findings, ${r.violations_count} violations)`)
      );
    }
  });

program.parse(process.argv);
