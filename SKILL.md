# IronSights Vibe Check

Audit code for security vulnerabilities that AI code generation consistently introduces. Vibe-coded apps — built rapidly with Claude Code, Cursor, Lovable, Bolt, v0, or similar tools — are breached in predictable ways.

**The numbers:** 87% of AI-generated PRs contain at least one vulnerability. 62% of AI code ships with vulnerabilities. 100% of tested AI-generated apps had SSRF; 0% had security headers (OX Security, 15 production apps). AI code is 2.74× more likely to contain XSS, 1.91× more likely to have IDOR, and 2.14× more likely to leak secrets than equivalent human-written code (Veracode + CSA, 2025).

**Iterative prompting makes it worse.** 5 rounds of refinement produces 37% more critical vulnerabilities than the initial generation. Asking an AI to "make it more secure" specifically causes the most cryptographic errors (21.1%), because it replaces `bcrypt` with SHA-256 and removes authentication from encryption modes. Audit after every significant iteration, not just at launch.

The pattern is documented: Moltbook (January 2026) — 1.5 million AI agent tokens exposed via a single `curl` command. CVE-2025-48757 (May 2025) — 170 Lovable apps, tables fully readable with the public `anon` key. RedHunt Labs Wave 15 — secrets in 1 in 5 of ~130,000 vibe-coded sites.


## The Core Principles

**Never trust the client.** Every price, user ID, role, subscription status, feature flag, and rate limit counter must be validated or enforced server-side. If it exists only in the browser, mobile bundle, or request body, an attacker controls it.

**AI verifies authentication but skips authorization.** It checks "is the user logged in" but rarely checks "does this user own this specific resource." IDOR (Insecure Direct Object Reference) is the #1 vulnerability class in AI-generated code.

**Middleware defined ≠ middleware wired.** Research found rate limiting, auth guards, and tenant scoping middleware defined in every codebase — and connected to routes in almost none. After each audit category, verify the protection is actually mounted on the routes that need it.


## Step 0: Repository Exposure Check

**Run this before anything else.** The answers change the severity of every finding that follows.

```bash
# 1. Check the remote origin to determine if repo is likely public
git remote get-url origin

# 2. Scan current files AND full git history for secrets
gitleaks detect --source . --verbose

# 3. If no gitleaks installed: manual history scan
git log --all --full-history --oneline
git grep -I "sk_live_\|AKIA\|ghp_\|xoxb-\|service_role" $(git log --all --format='%H') 2>/dev/null | head -20

# 4. Check if .git is accessible on the production domain
curl -s https://yourdomain.com/.git/HEAD
# If it returns "ref: refs/heads/main" — your entire source is downloadable
```

**If the repo is public:**
- Any secret in the current codebase or git history is already stolen — **rotate immediately, before fixing the code**
- Secrets in a public repo are **Critical** regardless of how old the commit is
- Check if the secret has been used: Stripe's dashboard shows API key usage logs; Anthropic's console shows per-key spend

**If the repo is private:**
- Still scan for secrets — treat findings as High
- Private repos become public via visibility change, accidental fork, or CI log exposure

**Report the repository visibility at the top of all findings.**


## Audit Process

For each step, load the relevant reference file only when the codebase uses that technology or pattern. Skip steps that are not applicable.

Each finding is tagged:
- `[QUICK]` — single file, one code change, testable immediately
- `[MEDIUM]` — multi-file change, requires testing and review
- `[ARCH]` — requires design decisions; possibly breaking changes

---

1. **Secrets & Environment Variables** `[QUICK]`
   Hardcoded keys, client-side env prefixes, MCP config file exposure. See `references/secrets-and-env.md`.
   *Verify:* `git ls-files | grep -E '\.env'` returns nothing. MCP config files not tracked.

2. **Database Access Control** `[ARCH]`
   Supabase RLS, Firebase Security Rules, Convex auth guards. The #1 critical vulnerability source.
   See `references/database-security.md`.
   *Verify:* Test endpoints with the public `anon` key: `curl 'https://xxx.supabase.co/rest/v1/users?select=*' -H "apikey: ANON_KEY"` — should return 0 rows or 401.

3. **Authentication & Authorization — IDOR, MFA, RBAC** `[MEDIUM]`
   JWT algorithm confusion, MFA enforcement, RBAC patterns, middleware bypass (CVE-2025-29927), IDOR/BOLA, OAuth misconfigs.
   See `references/authentication.md`.
   *Verify:* `grep -rn "findMany\|findFirst\|findUnique" src/` — every result on a user/org-owned resource must have an ownership `where` clause.

4. **Multitenancy & Tenant Isolation** `[ARCH]`
   Cross-tenant data leakage — the SaaS-specific IDOR. Prisma queries without organization scope, background jobs without tenant context, existence disclosure.
   See `references/multitenancy.md`.
   *Verify:* Grep for `findMany({` without `organizationId` in the where clause.

5. **Rate Limiting & Abuse Prevention** `[MEDIUM]`
   Auth endpoints, AI API calls, email/SMS, CAPTCHA on registration/reset forms.
   See `references/rate-limiting.md`.
   *Verify:* Rate limiting middleware is imported AND mounted on auth routes — not just defined.

6. **Payment Security** `[QUICK]`
   Client-side price manipulation, webhook signature verification, server-side payment confirmation.
   See `references/payments.md`.
   *Verify:* Search for `req.body.price` or `req.body.amount` — prices must come from the database.

7. **Mobile Security** `[QUICK]`
   Token storage, API key proxy, deep link validation. See `references/mobile.md`.

8. **AI / LLM Integration** `[MEDIUM]`
   API key exposure, usage caps, prompt injection, unsafe output rendering, semantic cache poisoning.
   See `references/ai-integration.md`.
   *Verify:* `grep -rn "NEXT_PUBLIC_.*OPENAI\|NEXT_PUBLIC_.*ANTHROPIC" .` — must return nothing.

9. **Deployment & Infrastructure** `[MEDIUM]`
   Security headers, CORS (allowlist only, never wildcard), GraphQL introspection disabled in production, source maps off, IaC security (Checkov/tfsec), Vercel environment scoping.
   See `references/deployment.md`.
   *Verify:* `curl -I https://yourdomain.com | grep -E 'Strict-Transport|Content-Security|X-Frame'`

10. **SSRF — Server-Side Request Forgery** `[MEDIUM]`
    Present in 100% of AI-generated apps that make server-side HTTP requests. Any `fetch(userUrl)` is an SSRF vector. Webhook registration, avatar fetching, link previews, PDF generation.
    See `references/ssrf.md`.
    *Verify:* `grep -rn "fetch(" src/ | grep -v "process.env\|localhost"` — audit every external fetch where the URL isn't hardcoded.

11. **File Upload Security** `[MEDIUM]`
    Path traversal via filename, MIME type spoofing, SVG XSS, polyglot files, missing size limits, zip bombs.
    See `references/file-uploads.md`.
    *Verify:* Any upload handler that uses `file.name` directly in a storage path is vulnerable.

12. **XSS, Injection & DOM Attacks** `[QUICK/MEDIUM]`
    `dangerouslySetInnerHTML` without DOMPurify, `javascript:` URI injection, postMessage origin bypass, prototype pollution, template injection, missing CSP, CDN scripts without SRI.
    See `references/xss-injection.md`.
    *Verify:* `grep -rn "dangerouslySetInnerHTML" src/` — every hit needs a DOMPurify sanitize call.

13. **Cryptographic Failures** `[MEDIUM]`
    OWASP A04:2025. Password hashing (bcrypt/Argon2 required), AES-GCM over AES-CBC, nonce uniqueness, timing-safe comparison, weak random number generation.
    See `references/cryptography.md`.
    *Verify:* `grep -rn "createHash\|Math.random\|AES-CBC\|sha256\|md5" src/` in security-relevant code.

14. **Data Access & Input Validation** `[MEDIUM]`
    SQL injection, Prisma operator injection (`findFirst({ where: req.body })`), mass assignment, ReDoS from AI-generated regex, insecure deserialization, TOCTOU race conditions.
    See `references/data-access.md`.

15. **Error Handling & Logging** `[QUICK]`
    Stack trace leakage in API responses, structured server-side logging, write-once external log storage, never logging passwords/tokens/PII.
    See `references/error-handling-logging.md`.
    *Verify:* `grep -rn "err.stack\|console.error.*err\b" src/api` — stack traces must not be in the response body.

16. **Data Privacy & Compliance** `[ARCH]`
    Data minimisation, bcrypt ≥ 12, AES-256-GCM for sensitive fields, right to deletion, GDPR/CCPA, Australian Privacy Principles (APP 1/3/6/11/13).
    See `references/data-privacy.md`.

17. **MCP & AI Agent Security** `[QUICK]`
    Tool poisoning (CVE-2025-54136), indirect prompt injection, 8 specific CVEs with version numbers, SSRF via agent HTTP calls, confused deputy attacks.
    See `references/mcp-and-agents.md`.
    *Verify:* Claude Code ≥ 1.0.111, Claude Code GitHub Action ≥ v1.0.94, `mcp-remote` ≥ 0.1.16.

18. **Supply Chain** `[MEDIUM]`
    Slopsquatting (19.7% AI package hallucination rate), SANDWORM_MODE npm worm, bait-and-switch versioning, dependency pinning, rules file backdoor via Unicode.
    See `references/supply-chain.md`.
    *Verify:* Every package added by AI this session is verified on npmjs.com before install.

---

Skip any step where the technology is not in use (e.g., no WebSockets → skip that section, no file uploads → skip that section).


## Core Instructions

- Report only genuine security issues. Do not nitpick style or non-security concerns.
- When multiple issues exist, prioritize by exploitability and real-world impact.
- If you find a Critical issue (exposed secret, disabled RLS, auth bypass, unauthenticated endpoint with data access), flag it at the top of your response before the organized findings.
- When generating new code, consult the relevant reference file proactively before writing anything that touches auth, payments, database access, encryption, or file handling.


## Output Format

**Start with:** Repository visibility (public/private) from Step 0. If public and secrets found: escalate immediately before any other output.

**Then:** Findings by severity: **Critical** → **High** → **Medium** → **Low**.

For each finding:
1. File and line(s)
2. Vulnerability name + OWASP reference where applicable
3. Concrete impact (what an attacker does, not abstract risk)
4. Tag: `[QUICK]` / `[MEDIUM]` / `[ARCH]`
5. Before/after code fix

**End with:** A prioritized summary table.

### Example Output

---

**Repository:** Public (github.com/acme/myapp) — any found secrets are Critical and already compromised.

---

#### Critical

**`lib/supabase.ts:3` — Supabase `service_role` key in client bundle** `[QUICK]`

The `service_role` key bypasses all Row-Level Security. Anyone can extract it from the browser bundle and read, modify, or delete every row in your database. **Rotate this key now.** This is the Moltbook pattern: 1.5 million tokens exposed via a single `curl`.

```typescript
// Before
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_KEY!)
// After
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!)
```

#### High

**`app/api/invoices/[id]/route.ts:12` — Missing ownership check (IDOR / OWASP API3:2023)** `[QUICK]`

Any authenticated user can read any other user's invoice by guessing the ID.

```typescript
// Before
const invoice = await db.invoices.findUnique({ where: { id: params.id } });
// After
const invoice = await db.invoices.findUnique({
  where: { id: params.id, userId: session.user.id }
});
if (!invoice) return new Response('Not found', { status: 404 });
```

### Summary

| # | Issue | Severity | Tag |
|---|-------|----------|-----|
| 1 | Service role key in client bundle | Critical | QUICK |
| 2 | IDOR on invoices endpoint | High | QUICK |


## References

- `references/secrets-and-env.md` — API keys, env variable config, MCP config secrets
- `references/database-security.md` — Supabase RLS, Firebase Rules, Convex
- `references/authentication.md` — MFA, RBAC, IDOR/BOLA, JWT, OAuth, Server Actions
- `references/multitenancy.md` — Cross-tenant isolation, tenant-scoped queries, background jobs
- `references/rate-limiting.md` — Rate limiting, CAPTCHA, abuse prevention
- `references/payments.md` — Stripe security, webhook verification
- `references/mobile.md` — React Native / Expo
- `references/ai-integration.md` — LLM API security, prompt injection
- `references/deployment.md` — Headers, CORS, GraphQL, IaC security
- `references/ssrf.md` — Server-side request forgery, webhook SSRF, Next.js image SSRF
- `references/file-uploads.md` — Path traversal, SVG XSS, MIME bypass, size limits
- `references/xss-injection.md` — dangerouslySetInnerHTML, javascript: URIs, postMessage, prototype pollution
- `references/cryptography.md` — Password hashing, AES-GCM, nonce reuse, timing attacks
- `references/data-access.md` — SQL injection, Prisma operator injection, ReDoS, race conditions
- `references/error-handling-logging.md` — Stack trace leakage, logging, monitoring
- `references/data-privacy.md` — PII, encryption at rest, privacy regulations
- `references/mcp-and-agents.md` — MCP tool poisoning, agent security, CVEs
- `references/supply-chain.md` — Slopsquatting, malicious npm, dependency pinning
