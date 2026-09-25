# AgentSkillGuard

A static security scanner for AI agent tools (MCP servers, plugins, skills) before they're granted access to a Solana wallet.

Agents increasingly install third-party tools. AgentSkillGuard's thesis: the tool supply chain is part of the attack surface, not just the wallet itself. It scans a tool's source for dangerous capabilities, checks them against a YAML permission manifest, and returns a clear **ALLOW / WARN / BLOCK** verdict.

```
npx @elmoxbt/agentskillguard scan ./my-agent-tool --policy policies/example-swap-agent.yaml
```

- **Repo:** https://github.com/elmoxbt/agentskillguard
- **npm:** https://www.npmjs.com/package/@elmoxbt/agentskillguard

## How it works

1. **Static analyzer** — walks the target's source files and flags capabilities like wallet signing, private key access, shell execution, dynamic code loading, unlimited token approvals, and arbitrary network calls.
2. **Policy enforcer** — checks detected capabilities against a YAML capability manifest. A fixed set of capabilities (private-key access, shell exec, `eval`/dynamic code, obfuscated execution, unlimited approvals) are never permitted, regardless of policy.
3. **Verdict engine** — combines the results into a single recommendation, with CI-friendly exit codes (`0` ALLOW, `1` WARN, `2` BLOCK).
4. Scans are optionally logged to a local history so you can audit everything you've vetted over time.

## Capability manifest

```yaml
name: swap-agent
permissions:
  solana:
    programs: [Jupiter]
    max_sol: 0.5
    tokens: [USDC]
  network:
    domains: [api.jup.ag]
  wallet:
    signing: true
    max_transactions_per_hour: 10
```

## Install & run

```bash
npm install
npm run build

npm run scan:demo:malicious   # bundled fixture — should BLOCK
npm run scan:demo:safe        # bundled fixture — should ALLOW

node dist/cli.js scan ./path/to/tool --policy policies/example-swap-agent.yaml
node dist/cli.js scan ./path/to/tool --json
node dist/cli.js history
```

Or, once published, use it directly without cloning:

```bash
npx @elmoxbt/agentskillguard scan ./path/to/tool
```

## Scope

This is an MVP: detection is regex/line-based rather than a full AST, so it can be evaded by sufficiently obfuscated code, and runtime limits (`max_sol`, `max_transactions_per_hour`) are captured in the manifest but require a runtime enforcement layer to actually enforce — static analysis can only confirm a tool is *capable* of exceeding them.

**Roadmap:** Tree-sitter-based AST analysis, a runtime enforcement proxy for `web3.js` calls, and a hash database of previously scanned malicious tools.

## License

MIT
