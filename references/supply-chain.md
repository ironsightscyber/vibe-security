# Supply Chain Security

## Slopsquatting — AI Package Hallucination Attacks

AI code assistants invent package names that don't exist. Attackers register those names on npm and PyPI before developers notice. The package installs cleanly and can execute arbitrary code during `npm install` via `postinstall` scripts.

**Scale:** A USENIX Security 2025 study across 576,000 code samples from 16 LLMs found an average hallucination rate of **19.7%** — roughly 1 in 5 AI-suggested package names doesn't exist. 43% of hallucinated names recur identically on repeated runs, making them reliably targetable.

**Confirmed real-world cases (2025–2026):**
- `huggingface-cli` (PyPI) — registered by a security researcher; 30,000+ downloads in 3 months
- `react-codeshift` (npm) — spread to 237 repos via AI agent skill forks before discovery
- `@async-mutex/mutex` — promoted by Google AI Overview
- Socket.dev documented 280 malicious packages published in a single weekend via AI automation

**Audit process:**
1. Before running `npm install` or `pip install` after AI-suggested package additions, verify every new package name on [npmjs.com](https://npmjs.com) or [pypi.org](https://pypi.org)
2. Check: does the package have downloads? Does it have a real GitHub repo? Does the README match what you expect?
3. Cross-reference with `npm audit` and Socket.dev
4. Flag any package that wasn't in your lockfile before the AI session

```bash
# Check what the AI added to package.json vs what was there before
git diff package.json
# For each new package, verify it exists and has real usage
npm info <package-name>
```

## Malicious npm Packages Targeting AI Workflows

Beyond slopsquatting, attackers publish packages that specifically target developers using AI assistants:

**SANDWORM_MODE worm (Socket Research, February 2026):** A self-replicating npm worm with a `McpInject` module that deploys a rogue MCP server. The MCP server contains prompt-injection blocks instructing AI assistants to silently read SSH keys, AWS credentials, and npm tokens. Targets were explicitly AI-workflow environments.

**Bait-and-switch via clean version history:** Attackers run many clean versions to build trust and bypass security scanners, then inject malware in a later release. The Postmark-MCP npm package (September 2025) ran 15 clean versions, then version 1.0.16 BCC'd all outgoing email to attacker infrastructure using pre-authorized corporate API keys.

**OX Security batch RCE (2025–2026):** Unsanitised STDIO in MCP handlers affected Windsurf, GPT Researcher, LiteLLM, Agent Zero, DocsGPT, and Langchain-Chatchat — combined downstream impact over 150 million downloads.

## Dependency Pinning for AI-Generated Code

AI assistants often suggest packages without specifying versions, or use loose version ranges (`^`, `~`). In combination with the malicious-update pattern above, unpinned dependencies are high risk.

**Practices:**
- Commit your `package-lock.json` or `yarn.lock` — never `.gitignore` it
- Use exact versions for MCP server packages in `package.json` (no `^` prefix)
- Run `npm ci` in CI/CD pipelines instead of `npm install` (respects exact lockfile versions)
- Enable Dependabot or Renovate for automated security update PRs
- Use Socket.dev or Snyk to scan for malicious packages, not just vulnerable ones

```json
// BAD: loose version range — will silently upgrade to any future 1.x
{
  "dependencies": {
    "@modelcontextprotocol/server-filesystem": "^1.0.0"
  }
}

// GOOD: pinned version
{
  "dependencies": {
    "@modelcontextprotocol/server-filesystem": "1.2.3"
  }
}
```

## Audit Rules Files and AI Configuration

Before cloning and opening an unfamiliar repository with an AI assistant, audit these files for malicious content:

- `.cursorrules` — Cursor reads this before every session
- `.github/copilot-instructions.md` — GitHub Copilot reads this
- `CLAUDE.md` — Claude Code reads this
- `.claude/settings.json` — Check for `enableAllProjectMcpServers: true` and unexpected `mcpServers` entries

A malicious actor can craft a repo that, when opened in Cursor or Claude Code, immediately exfiltrates your API keys via hidden instructions in these files. This is not theoretical — CVE-2025-59536 documents the exact mechanism for Claude Code.

**Check for hidden Unicode before trusting any rules file:**
```bash
# Hidden zero-width chars and bidi overrides
grep -rP '[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{206F}\x{FEFF}]' .cursorrules CLAUDE.md
```

## Scanning Tools

| Tool | What it catches |
|------|----------------|
| `npm audit` | Known CVEs in dependencies |
| [Socket.dev](https://socket.dev) | Malicious packages, suspicious behaviour, install scripts |
| [Snyk](https://snyk.io) | CVEs + some malicious packages |
| `gitleaks detect` | Secrets committed to git history |
| `detect-secrets scan` | Secrets in current files |
| `safe-regex` | ReDoS-vulnerable regex patterns |
| [vulnerablemcp.info](https://vulnerablemcp.info) | CVEs in MCP server packages |
