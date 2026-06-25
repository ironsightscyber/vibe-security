# IronSights Vibe Check

Audit code for security vulnerabilities that AI code generation consistently introduces. Vibe-coded apps — built rapidly with Claude Code, Cursor, Lovable, Bolt, v0, or similar tools — are breached in predictable ways.

The pattern is documented: in January 2026, Moltbook launched publicly after its founder said "I didn't write a single line of code." A single `curl` command exposed 1.5 million AI agent tokens, 35,000 user emails, and 4,060 private messages — all from a hardcoded Supabase key with zero RLS. In May 2025, CVE-2025-48757 documented the same class of defect across 170 Lovable-generated apps. RedHunt Labs scanned ~130,000 vibe-coded sites and found secrets in 1 in 5 of them.

These aren't edge cases. They're the default output of AI code generation under time pressure.


## The Core Principle

**Never trust the client.** Every price, user ID, role, subscription status, feature flag, and rate limit counter must be validated or enforced server-side. If it exists only in the browser, mobile bundle, or request body, an attacker controls it.

The second principle: **AI verifies authentication but skips authorization.** It checks "is the user logged in" but rarely checks "does this user own this specific resource." IDOR (Insecure Direct Object Reference) is the #1 vulnerability class in AI-generated code — 1.91× more likely than in human-written code per CSA 2025.


## Audit Process

Examine the codebase systematically. For each step, load the relevant reference file only if the codebase uses that technology or pattern.

1. **Secrets & Environment Variables** — Hardcoded keys, client-side env prefixes, MCP config file exposure. See `references/secrets-and-env.md`.

2. **Database Access Control** — Supabase RLS policies, Firebase Security Rules, Convex auth guards. The #1 critical vulnerability source. See `references/database-security.md`.

3. **Authentication & Authorization** — JWT algorithm confusion, middleware bypass, Server Action protection, IDOR/BOLA, OAuth misconfigurations. See `references/authentication.md`.

4. **Rate Limiting & Abuse Prevention** — Auth endpoints, AI calls, email/SMS, tamper-proof counters. See `references/rate-limiting.md`.

5. **Payment Security** — Client-side price manipulation, webhook signature verification, subscription status. See `references/payments.md`.

6. **Mobile Security** — Token storage, API key proxy, deep link validation. See `references/mobile.md`.

7. **AI / LLM Integration** — API key exposure, usage caps, prompt injection, unsafe output rendering. See `references/ai-integration.md`.

8. **Deployment Configuration** — Security headers, source maps, CORS, GraphQL introspection, `.git` exposure. See `references/deployment.md`.

9. **Data Access & Input Validation** — SQL injection, ORM misuse, mass assignment, ReDoS, insecure deserialization, race conditions. See `references/data-access.md`.

10. **MCP & AI Agent Security** — Tool poisoning, indirect prompt injection, MCP CVEs, agent confused-deputy attacks. See `references/mcp-and-agents.md`.

11. **Supply Chain** — Slopsquatting (AI-hallucinated packages), malicious npm packages targeting AI workflows, dependency pinning. See `references/supply-chain.md`.

If doing a partial review or generating code in a specific area, load only the relevant reference files.


## Core Instructions

- Report only genuine security issues. Do not nitpick style or non-security concerns.
- When multiple issues exist, prioritize by exploitability and real-world impact.
- If the codebase doesn't use a particular technology (e.g., no Supabase), skip that section entirely.
- When generating new code, consult the relevant reference files proactively to avoid introducing vulnerabilities in the first place.
- If you find a critical issue (exposed secrets, disabled RLS, auth bypass), flag it immediately at the top of your response — don't bury it in a long list.


## Output Format

Organize findings by severity: **Critical** → **High** → **Medium** → **Low**.

For each issue:
1. State the file and relevant line(s).
2. Name the vulnerability.
3. Explain what an attacker could do (concrete impact, not abstract risk).
4. Show a before/after code fix.

Skip areas with no issues. End with a prioritized summary.

### Example Output

#### Critical

**`lib/supabase.ts:3` — Supabase `service_role` key exposed in client bundle**

The `service_role` key bypasses all Row-Level Security. Anyone can extract it from the browser bundle and read, modify, or delete every row in your database. This is exactly what happened to Moltbook (January 2026): 1.5 million tokens exposed via a single `curl` command.

```typescript
// Before
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_KEY!)

// After — use the anon key client-side; service_role belongs only in server-side code
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!)
```

#### High

**`app/api/invoices/[id]/route.ts:12` — Missing ownership check (IDOR)**

Authentication confirms the user is logged in, but there's no check that this user owns invoice `:id`. Any authenticated user can read any other user's invoices by enumerating IDs.

```typescript
// Before
const invoice = await db.invoices.findUnique({ where: { id: params.id } });

// After — scope query to the authenticated user
const invoice = await db.invoices.findUnique({
  where: { id: params.id, userId: session.user.id }
});
if (!invoice) return new Response('Not found', { status: 404 });
```

### Summary

1. **Service role key exposed (Critical):** Rotate the key immediately. Move it to server-side only.
2. **IDOR on invoices (High):** Any user can read any invoice. Add ownership check to all resource queries.


## When Generating Code

These rules also apply proactively. Before writing code that touches auth, payments, database access, API keys, or user data, consult the relevant reference file to avoid introducing the vulnerability in the first place. Prevention is better than detection.

AI assistants are statistically worse at security than human developers: 2.74× more XSS, 1.91× more IDOR, 2.14× more secrets exposure (Veracode + CSA, 2025). Every iterative refinement round makes it worse — 5 rounds of prompting produces 37% more critical vulnerabilities than the initial generation (arxiv:2506.11022). Audit early, not after launch.


## References

- `references/secrets-and-env.md` — API keys, tokens, env variable config, MCP config secrets, `.gitignore` rules.
- `references/database-security.md` — Supabase RLS, Firebase Security Rules, Convex auth patterns.
- `references/authentication.md` — JWT verification, IDOR/BOLA, middleware bypass, OAuth misconfigs, Server Actions.
- `references/rate-limiting.md` — Rate limiting strategies and abuse prevention.
- `references/payments.md` — Stripe security, webhook verification, price validation.
- `references/mobile.md` — React Native and Expo: secure storage, API proxy, deep links.
- `references/ai-integration.md` — LLM API key protection, usage caps, prompt injection, output sanitization.
- `references/deployment.md` — Security headers, CORS, GraphQL introspection, source maps, environment separation.
- `references/data-access.md` — SQL injection, ORM safety, mass assignment, ReDoS, insecure deserialization, race conditions.
- `references/mcp-and-agents.md` — MCP tool poisoning, indirect prompt injection, agent security, CVE reference.
- `references/supply-chain.md` — Slopsquatting, malicious npm packages targeting AI workflows, dependency pinning.
