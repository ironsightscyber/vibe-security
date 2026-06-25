# IronSights Vibe Check

A Claude Code skill for auditing AI-generated code for the security vulnerabilities that vibe-coded apps consistently ship with.

**Install:** Copy `SKILL.md` and the `references/` directory into your Claude Code skills directory:

```
~/.claude/skills/ironsights-vibe-check/
├── SKILL.md
└── references/
    ├── secrets-and-env.md
    ├── database-security.md
    ├── authentication.md
    ├── rate-limiting.md
    ├── payments.md
    ├── mobile.md
    ├── ai-integration.md
    ├── deployment.md
    ├── data-access.md
    ├── error-handling-logging.md
    ├── data-privacy.md
    ├── mcp-and-agents.md
    └── supply-chain.md
```

Then invoke it with `/ironsights-vibe-check` in Claude Code.

---

## What It Catches

Vibe-coded apps are breached in predictable ways. In January 2026, Moltbook launched after its founder said "I didn't write a single line of code." A single `curl` command exposed 1.5 million AI agent tokens, 35,000 user emails, and 4,060 private messages. CVE-2025-48757 (May 2025) documented the same class of defect across 170 Lovable-generated apps. RedHunt Labs found secrets in 1 in 5 of ~130,000 vibe-coded sites scanned in 2025.

**Step 0 — Repository Exposure Check** runs first. A secret in a public repo is an incident, not a finding. The skill detects whether the repo is public before starting the audit, escalates severity accordingly, and provides commands to scan git history.

**13 audit categories:**

1. **Secrets & Environment Variables** — hardcoded keys, client-side env prefixes, MCP config file exposure
2. **Database Access Control** — Supabase RLS, Firebase Security Rules, Convex auth guards
3. **Authentication & Authorization** — MFA, RBAC, IDOR/BOLA, JWT algorithm confusion, middleware bypass, OAuth misconfigs
4. **Rate Limiting & Abuse Prevention** — auth endpoints, AI API calls, CAPTCHA, tamper-proof counters
5. **Payment Security** — client-side price manipulation, webhook verification, subscription status
6. **Mobile Security** — token storage, API proxy, deep link validation
7. **AI / LLM Integration** — API key exposure, usage caps, prompt injection, unsafe rendering
8. **Deployment & Infrastructure** — security headers, CORS, GraphQL introspection, source maps, IaC security
9. **Data Access & Input Validation** — SQL injection, mass assignment, ReDoS, insecure deserialization, race conditions
10. **Error Handling & Logging** — stack trace leakage, server-side-only logging, monitoring and alerting
11. **Data Privacy & Compliance** — PII minimisation, encryption at rest, GDPR/CCPA/Australian Privacy Principles, right to deletion
12. **MCP & AI Agent Security** — tool poisoning, indirect prompt injection, CVE reference, SSRF via agents
13. **Supply Chain** — slopsquatting, malicious npm packages, dependency pinning

---

## Why This Exists

AI assistants are statistically worse at security than human developers: 2.74× more XSS, 1.91× more IDOR, 2.14× more secrets exposure (Veracode + CSA, 2025). Iterative prompting makes it worse — 5 rounds of refinement produces 37% more critical vulnerabilities than the initial generation.

This skill is maintained by [IronSights](https://ironsights.com.au) — Australian cybersecurity specialists in managed security, penetration testing, and secure architecture for technology-driven businesses.

---

## Reference Files

| File | Category |
|------|----------|
| `references/secrets-and-env.md` | API keys, env variable config, MCP config secrets |
| `references/database-security.md` | Supabase RLS, Firebase Rules, Convex |
| `references/authentication.md` | MFA, RBAC, IDOR/BOLA, JWT, OAuth, Server Actions |
| `references/rate-limiting.md` | Rate limiting, CAPTCHA, abuse prevention |
| `references/payments.md` | Stripe security, webhook verification |
| `references/mobile.md` | React Native / Expo |
| `references/ai-integration.md` | LLM API security, prompt injection |
| `references/deployment.md` | Headers, CORS, GraphQL, IaC security |
| `references/data-access.md` | SQL injection, ReDoS, race conditions |
| `references/error-handling-logging.md` | Stack trace leakage, logging, monitoring |
| `references/data-privacy.md` | PII, encryption at rest, privacy regulations |
| `references/mcp-and-agents.md` | MCP tool poisoning, agent security, CVEs |
| `references/supply-chain.md` | Slopsquatting, malicious npm, pinning |

---

Maintained by [IronSights](https://ironsights.com.au) · [Security Services](https://ironsights.com.au/managed-security)
