# IronSights Vibe Security — Paste-Anywhere Prompt

Copy everything below this line and paste it into any AI tool (ChatGPT, Copilot, Gemini, Cursor, Codex, etc.) to run a full security audit on your codebase.

---

Audit this codebase for security vulnerabilities that AI coding tools consistently introduce. Work through all 18 categories below. Skip any category where the technology is not in use.

**Three principles to apply throughout:**
- Never trust the client — every price, user ID, role, and permission must be enforced server-side
- AI checks authentication ("is the user logged in?") but skips authorization ("does this user own this resource?") — IDOR is the #1 vulnerability in AI-generated code
- Middleware defined ≠ middleware wired — verify every protection is actually mounted on the routes that need it

---

**Start here — Repository Exposure Check**

Determine if the repo is public or private. If public, any secret found in the current code or git history is already compromised and must be rotated immediately before anything else is fixed.

Check for secrets in git history:
```
git grep -I "sk_live_\|AKIA\|ghp_\|xoxb-\|service_role" $(git log --all --format='%H') 2>/dev/null | head -20
```

Check if .git is exposed on the live domain:
```
curl -s https://yourdomain.com/.git/HEAD
```
If this returns `ref: refs/heads/main`, the entire source is downloadable by anyone.

Report the repository visibility at the top of all findings.

---

**18 Audit Categories**

Each finding should be tagged [QUICK] (single file fix), [MEDIUM] (multi-file), or [ARCH] (design decision required).

1. **Secrets & Environment Variables** [QUICK]
   - Hardcoded API keys, passwords, or tokens in source files
   - Secret keys exposed via NEXT_PUBLIC_ / VITE_ / REACT_APP_ prefixes (these go into the browser bundle)
   - .env files tracked in git
   - MCP config files (claude_desktop_config.json, .mcp.json) containing API keys committed to the repo
   - Verify: `git ls-files | grep -E '\.env'` returns nothing

2. **Database Access Control** [ARCH]
   - Supabase: RLS disabled on any table, or service_role key used client-side
   - Firebase: Security Rules missing or set to allow read/write: true
   - Convex: auth guards missing on queries/mutations
   - Verify (Supabase): `curl 'https://xxx.supabase.co/rest/v1/tablename?select=*' -H "apikey: ANON_KEY"` should return 0 rows or 401

3. **Authentication & Authorization — IDOR, MFA, RBAC** [MEDIUM]
   - IDOR/BOLA: API endpoints that fetch resources by ID without checking the requesting user owns that ID
   - JWT: algorithm confusion attacks (accepting "none" or RS256/HS256 swap)
   - MFA: available but not enforced on sensitive actions
   - RBAC: roles checked client-side only
   - Next.js middleware bypass: CVE-2025-29927 — middleware skipped when x-middleware-subrequest header is present
   - OAuth: state parameter missing (CSRF), open redirect on callback
   - Verify: grep for findMany/findFirst/findUnique — every result on user-owned data needs an ownership where clause

4. **Multitenancy & Tenant Isolation** [ARCH]
   - Database queries without organization/tenant scoping
   - Background jobs that process data across all tenants
   - Existence disclosure: returning 404 vs 403 leaks whether a resource exists

5. **Rate Limiting & Abuse Prevention** [MEDIUM]
   - Auth endpoints (login, register, password reset) without rate limiting
   - AI API calls without per-user usage caps
   - Email/SMS sending without limits
   - CAPTCHA present in UI but token not verified server-side
   - Verify: rate limiting middleware is imported AND mounted — not just defined

6. **Payment Security** [QUICK]
   - Price or amount coming from the client request body (must come from the database)
   - Stripe/payment webhook signature not verified
   - Subscription status checked client-side only
   - Verify: grep for req.body.price or req.body.amount — these must not exist

7. **Mobile Security** [QUICK]
   - API keys or secrets in the mobile bundle (React Native / Expo)
   - Tokens stored in AsyncStorage (unencrypted) instead of SecureStore
   - Deep link handlers that don't validate the incoming URL

8. **AI / LLM Integration** [MEDIUM]
   - AI API keys (OpenAI, Anthropic, etc.) with NEXT_PUBLIC_ / VITE_ prefix — goes into browser bundle
   - No per-user token/spend limits on AI calls
   - User input passed directly to AI without sanitization (prompt injection)
   - AI output rendered as HTML without sanitization (XSS via AI)
   - Semantic cache: different users' queries returning each other's cached AI responses

9. **Deployment & Infrastructure** [MEDIUM]
   - Missing security headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options
   - CORS: wildcard (*) origin allowed, or credentials sent with wildcard
   - GraphQL introspection enabled in production
   - Source maps deployed to production (exposes full source)
   - Next.js CVEs: verify running ≥15.2.3 (CVE-2025-29927 CVSS 9.1) and ≥15.3.3 (CVE-2025-55182 CVSS 10.0)

10. **SSRF — Server-Side Request Forgery** [MEDIUM]
    - Any server-side fetch() where the URL comes from user input
    - Webhook registration that fetches a user-supplied URL
    - Avatar/image fetching from user-supplied URLs
    - PDF generation or link preview services
    - Next.js image optimizer: remote patterns not restricted (fetch any URL via /_next/image)
    - Fix: validate URLs against an allowlist of domains; block private IP ranges (10.x, 172.16.x, 192.168.x, 127.x, 169.254.x)

11. **File Upload Security** [MEDIUM]
    - Filename used directly in storage path (path traversal: `../../../etc/passwd`)
    - MIME type checked from Content-Type header only (client-controlled — spoof with magic bytes)
    - SVG uploads rendered in browser (SVG can contain JavaScript)
    - No file size limit (zip bomb / storage exhaustion)
    - Executable files (.php, .exe, .sh) not blocked

12. **XSS, Injection & DOM Attacks** [QUICK/MEDIUM]
    - dangerouslySetInnerHTML used without DOMPurify sanitization
    - href or src set from user input without checking for javascript: URIs
    - postMessage handlers that don't verify event.origin
    - innerHTML assignments in vanilla JS
    - Prototype pollution via object spread of unvalidated input
    - CDN scripts loaded without integrity (SRI) attributes

13. **Cryptographic Failures** [MEDIUM]
    - Passwords hashed with SHA-256/MD5 instead of bcrypt (cost ≥12) or Argon2
    - AES-CBC used instead of AES-GCM (no authentication)
    - Nonce/IV reused across encryptions
    - Math.random() used for security tokens (not cryptographically random)
    - String comparison for secrets instead of timing-safe comparison

14. **Data Access & Input Validation** [MEDIUM]
    - SQL injection via string concatenation or template literals in queries
    - Prisma operator injection: passing req.body directly as a where clause (allows $not, $or, $gt operators)
    - Mass assignment: spreading req.body directly into a database create/update
    - ReDoS: AI-generated regex with catastrophic backtracking on user input
    - Race conditions on operations that should be atomic (e.g., check-then-act on account balances)

15. **Error Handling & Logging** [QUICK]
    - Stack traces or internal error details returned in API responses
    - Passwords, tokens, or PII written to logs
    - No structured logging (makes security incidents hard to investigate)
    - Verify: grep for err.stack in API response bodies — must not exist

16. **Data Privacy & Compliance** [ARCH]
    - Collecting more data than needed for the stated purpose
    - No mechanism to delete a user's personal data on request
    - Personal data not encrypted at rest (AES-256-GCM minimum for sensitive fields)
    - Australian Privacy Principles (APP) if operating in Australia: APP 1 (privacy policy), APP 3 (collection), APP 11 (security), APP 13 (correction)
    - GDPR if handling EU residents: lawful basis, right to erasure, DPA if using processors

17. **MCP & AI Agent Security** [QUICK]
    - MCP tool poisoning: CVE-2025-54136 — malicious MCP server returning instructions in tool descriptions
    - Indirect prompt injection: AI agent reads attacker-controlled content (email, webpage) containing hidden instructions
    - SSRF via agent: agent making HTTP requests to internal services on behalf of an attacker
    - Verify versions: Claude Code ≥1.0.111, Claude Code GitHub Action ≥v1.0.94, mcp-remote ≥0.1.16

18. **Supply Chain** [MEDIUM]
    - Slopsquatting: AI hallucinated a package name that doesn't exist or matches a malicious one (19.7% hallucination rate)
    - Verify every package the AI suggested actually exists on npmjs.com/pypi.org before installing
    - Dependencies not pinned to exact versions (bait-and-switch attack: maintainer publishes malicious version)
    - .cursorrules / CLAUDE.md / system prompt files checked for Unicode invisible characters or hidden instructions

---

**Output format:**

Start with repository visibility (public/private) and any Critical findings first.

Then list findings by severity: Critical → High → Medium → Low.

For each finding include:
1. File and line number
2. Vulnerability name and OWASP category where applicable
3. What an attacker can actually do (not abstract risk)
4. Tag: [QUICK] / [MEDIUM] / [ARCH]
5. Code fix (before and after)

End with a summary table of all findings.

---

*Prompt maintained by [IronSights](https://ironsights.com.au) — Australian cybersecurity specialists. For a professional security review: [ironsights.com.au/vibe-security](https://ironsights.com.au/vibe-security)*
