# AgentSkillGuard

**A static security scanner for AI agent tools before they get anywhere near a Solana wallet.**

Agents increasingly install tools (MCP servers, plugins, "skills") from third parties. Every wallet-security effort so far has assumed the *agent* is the thing to secure. AgentSkillGuard's thesis: **the tool supply chain is the attack surface.** A perfectly secure agent handing a perfectly signed transaction to a malicious swap-tool is still a drained wallet.

Think `npm audit` + ClamAV, scoped to the specific things an agent tool can do to a Solana wallet.

```
skillguard scan ./my-agent-tool --policy policies/example-swap-agent.yaml
```

```
AGENTSKILLGUARD
target: /home/user/my-agent-tool
files scanned: 3

Capabilities detected:
  [x] CRITICAL  wallet.private_key_access — Tool references private key / secret / mnemonic material directly.
        index.js:12  const secretKey = process.env.WALLET_PRIVATE_KEY;
  [x] CRITICAL  system.shell_exec — Tool can execute OS shell commands via child_process.
        index.js:34  exec('curl -s ' + relayHost + '/beacon');
  [x] CRITICAL  code.dynamic_load — Tool loads or executes code dynamically at runtime.
        index.js:30  eval(Buffer.from(patch, 'base64').toString());
  ...

Policy violations:
  [!] CRITICAL  wallet.private_key_access is never permitted, regardless of policy
  [!] CRITICAL  system.shell_exec is never permitted, regardless of policy
  [!] CRITICAL  code.dynamic_load is never permitted, regardless of policy

Recommended action:  BLOCK
3 critical violation(s): wallet.private_key_access, system.shell_exec, code.dynamic_load.
```

---

## How it works

```
              ┌────────────────────┐
  tool code → │  static analyzer    │ → findings (capability + severity + line)
              │  (rule engine)      │
              └─────────┬──────────┘
                         │
              ┌──────────▼──────────┐
   policy.yml → │  policy enforcer   │ → violations (findings checked against
              │  (capability manifest│    the manifest + a hard floor of
              │   + hard floor)      │    never-allowed capabilities)
              └─────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │   verdict engine     │ → ALLOW / WARN / BLOCK
              └──────────────────────┘
```

1. **Static analyzer** (`src/scanner/staticAnalyzer.ts`) walks every `.js`/`.ts` file in the target and runs a rule set (`src/rules/rules.ts`) against it line-by-line, tagging matches with a **capability** (e.g. `wallet.signing`, `system.shell_exec`) and severity.
2. **Policy enforcer** (`src/policy/enforcer.ts`) loads a YAML **capability manifest** and checks detected capabilities against it. A small set of capabilities (private-key access, shell exec, dynamic code loading, obfuscated execution, unlimited approvals) are an **always-blocked floor** — no policy can grant them.
3. **Verdict engine** (`src/report/verdict.ts`) turns violations into a single recommendation: `BLOCK` (critical violation), `WARN` (needs manual review), or `ALLOW`.
4. Every scan is optionally persisted to a local SQLite database (`~/.agentskillguard/scans.db`) so you can build a `skillguard history` audit trail across every tool you've ever vetted.

### Detected capabilities

| Capability | Checks for | Severity |
|---|---|---|
| `wallet.signing` | Can the tool sign transactions/messages? | CRITICAL |
| `wallet.private_key_access` | Does it touch raw private keys / mnemonics? | CRITICAL |
| `network.http` | Does it make outbound HTTP requests? | MEDIUM |
| `network.dynamic_url` | Are request URLs built dynamically (unverifiable)? | HIGH |
| `solana.tx_modification` | Does it mutate transaction instructions/destinations? | HIGH |
| `system.shell_exec` | Can it run OS shell commands? | CRITICAL |
| `code.dynamic_load` | Does it `eval`/`new Function`/dynamic `require`? | CRITICAL |
| `solana.unlimited_approval` | Does it request unlimited token approvals? | HIGH |
| `system.env_read` | Does it read `process.env`? | MEDIUM |
| `code.obfuscation` | Does it decode+execute base64/hex payloads? | CRITICAL |
| `system.filesystem_write` | Does it write/delete files? | MEDIUM |

This maps directly to the "tool permissions" checklist a human reviewer would ask about — the scanner just does it automatically, on every install.

## The capability manifest

```yaml
name: swap-agent
description: "Allows a swap tool to route trades through Jupiter and call its price API."

permissions:
  solana:
    programs:
      - Jupiter
    max_sol: 0.5
    tokens:
      - USDC

  network:
    domains:
      - api.jup.ag
      - quote-api.jup.ag

  wallet:
    signing: true
    max_transactions_per_hour: 10
```

The scanner statically enforces `wallet.signing`, `network.domains`, and `solana.programs`. `max_sol` and `max_transactions_per_hour` describe the intended **runtime** ceiling — static analysis can prove a tool is *capable* of signing, but it can't prove what amount it will sign at runtime. See Roadmap below.

## Install & run

```bash
npm install
npm run build

# scan the bundled "malicious" fixture — should BLOCK
npm run scan:demo:malicious

# scan the bundled "safe" fixture — should ALLOW
npm run scan:demo:safe

# scan any tool on your machine
node dist/cli.js scan ./path/to/tool --policy policies/example-swap-agent.yaml

# scan without a policy — only the hard-blocked floor applies
node dist/cli.js scan ./path/to/tool

# machine-readable output (for CI / pre-install hooks)
node dist/cli.js scan ./path/to/tool --json

# generate a starter deny-by-default policy
node dist/cli.js init-policy -o my-tool.policy.yaml

# see everything you've scanned so far
node dist/cli.js history
```

Exit codes are CI-friendly: `0` = ALLOW, `1` = WARN, `2` = BLOCK — so you can wire `skillguard scan` into a pre-install hook and have it actually stop an install.

Run the smoke tests directly with `npm test` (no test framework, just assertions — see `test/scanner.test.ts`).

## Project structure

```
agentskillguard/
├── src/
│   ├── cli.ts                  # commander-based CLI entry point
│   ├── types.ts                # shared types (Finding, Violation, ScanResult...)
│   ├── rules/rules.ts           # the rule set — add new detection rules here
│   ├── scanner/
│   │   ├── index.ts             # orchestrates a scan end-to-end
│   │   ├── staticAnalyzer.ts    # line-based rule matching + URL extraction
│   │   └── mcpMetadata.ts       # reads package.json / mcp.json for tool identity
│   ├── policy/
│   │   ├── schema.ts            # zod schema for the YAML capability manifest
│   │   ├── loader.ts            # loads + validates a policy file
│   │   └── enforcer.ts          # findings + policy -> violations
│   ├── report/
│   │   ├── verdict.ts           # violations -> ALLOW / WARN / BLOCK
│   │   └── formatter.ts         # colored CLI report
│   ├── db/store.ts              # SQLite scan history (better-sqlite3)
│   └── utils/fileWalker.ts      # recursive source-file discovery
├── policies/example-swap-agent.yaml
├── examples/
│   ├── malicious-tool/          # fixture that trips nearly every rule (inert — do not run)
│   └── safe-tool/                # fixture that scans clean
└── test/scanner.test.ts         # smoke test asserting both fixtures verdict correctly
```

## Scope & honesty about limitations

This is a portfolio-grade MVP, not a production security product. Specifically:

- **Detection is regex/line-based, not a real AST.** It's fast and dependency-light, but it can be evaded by anyone who tries (multi-line obfuscation, string-splitting `"ev" + "al"`, etc). The natural upgrade path is a Tree-sitter-based AST pass (`tree-sitter-javascript`/`tree-sitter-typescript`) doing call-graph and data-flow analysis instead of pattern matching — the rule *interface* (`Rule.pattern` → `Rule.check(ast)`) is designed so that swap is additive, not a rewrite.
- **Static analysis can't enforce runtime limits.** `max_sol` and `max_transactions_per_hour` in the manifest are real intents but need a runtime wrapper (a proxy the agent calls through, which meters actual transaction amounts/frequency against the manifest) to actually enforce — the scanner can only flag that a tool *is capable* of exceeding them if it doesn't hard-code such limits itself.
- **No sandboxed dynamic analysis yet.** A tool that decrypts its payload only at runtime (fetched from a CDN post-install, key derived from an unpredictable seed) won't be caught by source scanning at all. That needs an actual sandboxed execution pass — out of scope for the MVP.

## Roadmap

- [ ] Tree-sitter AST engine (real call-graph analysis instead of regex)
- [ ] Runtime enforcement proxy: wraps `@solana/web3.js` calls so `max_sol` / `max_transactions_per_hour` are enforced live, not just requested
- [ ] MCP-native scanning: intercept tool registration at the protocol level and scan before an agent is ever allowed to call it
- [ ] Signature/hash database of previously-scanned malicious tools (the "ClamAV" half of the pitch)
- [ ] `skillguard watch` — scan on every `npm install` in an agent's tool directory
