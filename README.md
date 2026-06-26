# IronSights Vibe Check

A Claude Code skill for auditing AI-generated code for the security vulnerabilities that vibe-coded apps consistently ship with.

**Install:**
```bash
git clone https://github.com/slow-turtle-dancing/ironsights-vibe-check.git \
  ~/.claude/skills/ironsights-vibe-check
```

Then invoke with `/ironsights-vibe-check` in Claude Code.

---

## The Numbers

- **87%** of AI-generated PRs contain at least one vulnerability
- **62%** of AI code ships with vulnerabilities (OX Security / CSA, 4M scans)
- **100%** of tested AI-generated apps had SSRF — **0%** had security headers (OX Security, 15 apps)
- **2.74×** more XSS, **1.91×** more IDOR, **2.14×** more secrets exposure vs human-written code
- **37%** more critical vulnerabilities after 5 iterative refinement rounds — more prompting = worse security

Real breaches: Moltbook (Jan 2026, 1.5M tokens), CVE-2025-48757 (170 Lovable apps), EnrichLead (zero auth on launch day), RedHunt Labs Wave 15 (secrets in 1 in 5 of ~130,000 sites).

---

## What It Checks

**Step 0 — Repository Exposure Check** runs first. A secret in a public repo is an incident, not a finding.

**18 audit categories with severity tags (`[QUICK]` / `[MEDIUM]` / `[ARCH]`):**

| # | Category | Key patterns |
|---|----------|-------------|
| 1 | Secrets & Environment Variables | Hardcoded keys, NEXT_PUBLIC_ prefixes, MCP config files |
| 2 | Database Access Control | Supabase RLS, Firebase Rules, Convex |
| 3 | Authentication & Authorization | MFA, RBAC, IDOR/BOLA, JWT algorithm confusion, OAuth |
| 4 | Multitenancy & Tenant Isolation | Cross-tenant data leakage, scoped queries, background jobs |
| 5 | Rate Limiting & Abuse Prevention | Auth endpoints, AI API calls, CAPTCHA, wiring gap |
| 6 | Payment Security | Client-side price manipulation, webhook verification |
| 7 | Mobile Security | Token storage, API proxy, deep links |
| 8 | AI / LLM Integration | API key exposure, prompt injection, semantic cache poisoning |
| 9 | Deployment & Infrastructure | Security headers, CORS, GraphQL, Next.js CVEs, IaC |
| 10 | SSRF | Server-side request forgery, webhook SSRF, image optimizer |
| 11 | File Upload Security | Path traversal, SVG XSS, MIME bypass, polyglots |
| 12 | XSS, Injection & DOM Attacks | dangerouslySetInnerHTML, javascript: URIs, prototype pollution |
| 13 | Cryptographic Failures | bcrypt vs SHA-256, AES-GCM, nonce reuse, timing attacks |
| 14 | Data Access & Input Validation | SQLi, Prisma operator injection, ReDoS, race conditions |
| 15 | Error Handling & Logging | Stack trace leakage, structured logging, monitoring |
| 16 | Data Privacy & Compliance | GDPR, CCPA, Australian Privacy Principles |
| 17 | MCP & AI Agent Security | Tool poisoning, indirect prompt injection, 8+ CVEs |
| 18 | Supply Chain | Slopsquatting, malicious npm, dependency pinning |

---

## Reference Files

| File | Category |
|------|----------|
| `references/secrets-and-env.md` | API keys, MCP config secrets, .gitignore |
| `references/database-security.md` | Supabase RLS, Firebase, Convex |
| `references/authentication.md` | MFA, RBAC, IDOR, JWT, OAuth, Next.js middleware |
| `references/multitenancy.md` | Cross-tenant isolation, scoped queries, background jobs |
| `references/rate-limiting.md` | Rate limiting, CAPTCHA, wiring gap |
| `references/payments.md` | Stripe, webhooks, server-side price lookup |
| `references/mobile.md` | React Native / Expo |
| `references/ai-integration.md` | LLM keys, prompt injection, output sanitization |
| `references/deployment.md` | Headers, CORS, GraphQL, Next.js CVEs, IaC |
| `references/ssrf.md` | SSRF patterns, private IP blocking, webhook verification |
| `references/file-uploads.md` | Path traversal, SVG XSS, MIME spoofing, size limits |
| `references/xss-injection.md` | DOMPurify, javascript: URIs, postMessage, CSP |
| `references/cryptography.md` | bcrypt, AES-GCM, nonce uniqueness, timing-safe comparison |
| `references/data-access.md` | SQLi, Prisma operator injection, ReDoS, race conditions |
| `references/error-handling-logging.md` | Stack traces, structured logging, Sentry |
| `references/data-privacy.md` | PII, right to deletion, GDPR, Australian Privacy Act |
| `references/mcp-and-agents.md` | Tool poisoning, agent security, CVE reference list |
| `references/supply-chain.md` | Slopsquatting, malicious packages, pinning |

---

Maintained by [IronSights](https://ironsights.com.au) · Australian cybersecurity specialists · [Security Services](https://ironsights.com.au/managed-security)
