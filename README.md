# IronSights Vibe Security

**A free Claude Code skill that audits AI-generated code for the vulnerabilities it consistently ships with.**

Built and maintained by [IronSights](https://ironsights.com.au) — Australian cybersecurity specialists.

---

## Why this exists

AI coding tools like Claude Code, Cursor, Lovable, and Bolt write code fast. They also introduce the same security mistakes, over and over. This skill gives Claude Code a structured security checklist — the same categories our consultants review in professional audits — so you can catch the obvious problems before they ship.

**The numbers:**
- **87%** of AI-generated PRs contain at least one vulnerability
- **62%** of AI code ships with vulnerabilities (OX Security / CSA, 4M scans)
- **100%** of tested AI-generated apps had SSRF — **0%** had security headers (OX Security, 15 apps)
- **2.74×** more XSS, **1.91×** more IDOR, **2.14×** more secrets exposure vs human-written code
- **37%** more critical vulnerabilities after 5 rounds of AI refinement — more prompting makes it worse

Real breaches: Moltbook (Jan 2026, 1.5M tokens exposed via a single `curl`), CVE-2025-48757 (170 Lovable apps, all data publicly readable), EnrichLead (zero authentication on launch day), RedHunt Labs Wave 15 (secrets found in 1 in 5 of ~130,000 vibe-coded sites).

---

## Installation

### Prerequisites

Before installing, you need:
- **Claude Code** — Anthropic's AI coding assistant ([claude.ai/code](https://claude.ai/code))
- **Git** — version control tool ([git-scm.com](https://git-scm.com/downloads))

### Install (Mac / Linux)

Open a terminal and run:

```bash
git clone https://github.com/ironsightscyber/vibe-security.git \
  ~/.claude/skills/ironsights-vibe-check
```

### Install (Windows)

Open Command Prompt or PowerShell and run:

```powershell
git clone https://github.com/ironsightscyber/vibe-security.git `
  "$env:USERPROFILE\.claude\skills\ironsights-vibe-check"
```

### Use it

Open any project in Claude Code and type:

```
/ironsights-vibe-check
```

Claude will run through 18 security categories and report findings by severity — Critical, High, Medium, Low — with code fixes for each.

---

## What it checks

**Step 0 — Repository Exposure** runs first. A secret in a public repo is already compromised.

**18 audit categories:**

| # | Category | What it catches |
|---|----------|----------------|
| 1 | Secrets & Environment Variables | Hardcoded API keys, exposed `.env` files, MCP config leaks |
| 2 | Database Access Control | Supabase RLS disabled, Firebase open rules, Convex auth gaps |
| 3 | Authentication & Authorization | IDOR/BOLA, MFA gaps, JWT algorithm confusion, OAuth misconfiguration |
| 4 | Multitenancy & Tenant Isolation | Cross-tenant data leakage, unscoped queries |
| 5 | Rate Limiting & Abuse Prevention | Unprotected auth endpoints, missing CAPTCHA, AI API abuse |
| 6 | Payment Security | Client-side price manipulation, unsigned webhooks |
| 7 | Mobile Security | Insecure token storage, exposed API keys in bundles |
| 8 | AI / LLM Integration | API key exposure, prompt injection, cache poisoning |
| 9 | Deployment & Infrastructure | Missing security headers, wildcard CORS, outdated Next.js CVEs |
| 10 | SSRF | Server-side request forgery via webhooks, image optimizer, link previews |
| 11 | File Upload Security | Path traversal, SVG XSS, MIME spoofing, missing size limits |
| 12 | XSS, Injection & DOM Attacks | Unsanitised HTML, `javascript:` URIs, prototype pollution |
| 13 | Cryptographic Failures | SHA-256 used for passwords, AES-CBC, nonce reuse |
| 14 | Data Access & Input Validation | SQL injection, Prisma operator injection, ReDoS |
| 15 | Error Handling & Logging | Stack traces in API responses, secrets in logs |
| 16 | Data Privacy & Compliance | GDPR, CCPA, Australian Privacy Principles |
| 17 | MCP & AI Agent Security | Tool poisoning, indirect prompt injection, 8+ patched CVEs |
| 18 | Supply Chain | Slopsquatted packages, malicious npm, unpinned dependencies |

---

## Need a professional review?

This skill catches common, predictable vulnerabilities. It does not replace a hands-on security assessment.

If you're handling customer data, taking payments, or building for an enterprise client, consider a professional review:

- **[Vibe Security Check](https://ironsights.com.au/vibe-security)** — AI-specific security review for apps built with Claude Code, Cursor, Lovable, or Bolt
- **[Cyber Security Audit](https://ironsights.com.au/cyber-security-audit)** — a structured assessment of your application and infrastructure
- **[Managed Security](https://ironsights.com.au/managed-security)** — ongoing monitoring and incident response for your business
- **[Contact IronSights](https://ironsights.com.au/contact)** — talk to our team about your specific situation

---

## Contributing

Found a new vulnerability pattern? Open a pull request. We update this skill as new research and CVEs emerge.

---

> **Disclaimer:** This skill is a starting point for security review, not a substitute for a professional penetration test or security audit. CVE references and statistics reflect publicly available research at time of writing. IronSights Pty Ltd makes no warranty as to the completeness of findings.
