# Deployment Security

## Production Configuration

- **Disable debug mode** in production. Debug pages often leak stack traces, environment variables, and internal paths.
- **Disable source maps** in production. Source maps expose your entire source code to anyone who opens DevTools. In Next.js: `productionBrowserSourceMaps: false` (the default) — confirm it hasn't been enabled.
- **Verify `.git` directory is not accessible** in production. If `https://yoursite.com/.git/HEAD` returns content, your entire source code and commit history (including any secrets ever committed) are exposed.

## Next.js-Specific CVEs

These are patched but the vulnerable code patterns persist in AI-generated codebases long after the fix is released.

**CVE-2025-29927 — Middleware Auth Bypass (CVSS 9.1):** Next.js middleware could be completely bypassed by adding `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` to any request. Fixed in Next.js 15.2.3+ / 14.2.25+.

The correct response is not just upgrading Next.js — it's ensuring every Route Handler and Server Action independently validates auth, regardless of middleware. Middleware is a convenience layer, not a security boundary.

**CVE-2025-55182 — React Server Components RCE (CVSS 10.0):** Maliciously crafted POST to any RSC endpoint enables arbitrary code execution. Real-world exploitation (cryptocurrency miners) began December 5, 2025. Fixed in React 19.0.1 / 19.1.2 / 19.2.1. Verify your React version: `npm list react`.

**CVE-2024-46982 / CVE-2025-49826 — Cache Poisoning:** The `x-invoke-status` and `x-middleware-prefetch` headers are user-controllable and can poison CDN caches with empty/error responses, causing DoS. Fixed in Next.js 14.2.25+.

**Server Component cache shared across users:** `fetch()` inside Server Components is cached by default and shared across all requests. User-specific data becomes global cache — user A sees user B's data.

```typescript
// BAD: fetch() in a Server Component caches the response globally
async function UserDashboard() {
  const data = await fetch('/api/user-data'); // cached! all users see the same data
}

// GOOD: opt out of caching for user-specific data
const data = await fetch('/api/user-data', { cache: 'no-store' });
// or with Next.js revalidation:
const data = await fetch('/api/user-data', { next: { revalidate: 0 } });
```

**Vercel environment scope misconfiguration:** Variables set for "All Environments" in Vercel are available in preview deployments, which are publicly accessible URLs. Scope production secrets (database URLs, Stripe secret keys, API keys) to "Production" only. Preview environments should use test/staging credentials.

**Serverless global state leakage:** Serverless functions reuse execution contexts across requests. Mutable global variables persist between requests in the same container:

```typescript
// BAD: global state persists between requests in reused containers
let currentUser: User | null = null;
export async function GET() {
  currentUser = await getSession(); // leaks to next request in this container
}

// GOOD: all state local to the handler
export async function GET(req: Request) {
  const user = await getSession(req); // scoped to this invocation
}
```

## Environment Separation

Use separate environment variables for each environment in Vercel (or equivalent):

| Environment | Purpose |
|-------------|---------|
| Production | Live users, real keys |
| Preview | PR previews, should use test/staging keys |
| Development | Local dev, uses local/test keys |

Preview deployments should **never** use production API keys, database credentials, or payment keys. A preview deployment is often accessible to anyone with the URL.

## Security Headers

Set these headers on all responses. In Next.js, configure in `next.config.ts`:

```javascript
const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-XSS-Protection', value: '1; mode=block' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  {
    key: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
  },
];
```

Start restrictive and loosen as needed — not the other way around. CSP violations will appear in the browser console.

## CORS Configuration

AI-generated code routinely sets `origin: '*'` or reflects `req.headers.origin` without validation. Both are dangerous on authenticated endpoints.

```typescript
// BAD: allows any origin (including attacker.com) to make credentialed requests
app.use(cors({ origin: '*' }));

// BAD: reflects the request origin — functionally identical to wildcard
app.use(cors({ origin: req.headers.origin }));

// GOOD: explicit allowlist
const ALLOWED_ORIGINS = ['https://yourdomain.com', 'https://app.yourdomain.com'];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
}));
```

`Access-Control-Allow-Credentials: true` must be paired with a specific origin, never `*`. A wildcard + credentials header is rejected by all modern browsers, but some frameworks silently drop the credentials flag — verify yours.

**CSA 2025 finding:** Overly permissive CORS headers were present across all 15 tested AI-generated production applications.

## GraphQL Introspection

AI generates Apollo Server, express-graphql, and Hasura with **introspection enabled by default**. In production, this lets attackers enumerate your complete schema — including fields named `password`, `apiKey`, `adminNotes`, or `ssn`.

```typescript
// BAD: introspection enabled in production (Apollo Server default)
const server = new ApolloServer({ typeDefs, resolvers });

// GOOD: disable in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
});
```

Also disable field-level suggestions in production (they help attackers enumerate near-matches on schema fields):
```typescript
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: false,
  plugins: [ApolloServerPluginDisableDefaultSuggestions()],
});
```

## Infrastructure as Code (IaC) Security

If the project uses Terraform, CloudFormation, Pulumi, or CDK to provision cloud infrastructure, those files must be audited alongside the application code. Misconfigured IaC is a frequent source of publicly exposed S3 buckets, overly-permissive IAM roles, and unencrypted databases.

**Common IaC misconfigurations in AI-generated code:**

```hcl
# BAD: S3 bucket publicly accessible
resource "aws_s3_bucket_public_access_block" "example" {
  block_public_acls   = false
  block_public_policy = false
}

# GOOD: block all public access
resource "aws_s3_bucket_public_access_block" "example" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

```hcl
# BAD: overly broad IAM role (AI generates AdministratorAccess for convenience)
resource "aws_iam_role_policy_attachment" "lambda" {
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# GOOD: least-privilege — only the specific actions the Lambda needs
resource "aws_iam_role_policy" "lambda" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "arn:aws:s3:::my-bucket/*"
    }]
  })
}
```

**Scan IaC with automated tools:**
- [Checkov](https://www.checkov.io/) — static analysis for Terraform, CloudFormation, Kubernetes, Dockerfiles
- [tfsec](https://aquasecurity.github.io/tfsec/) — Terraform-specific security scanner
- [cfn-nag](https://github.com/stelligent/cfn_nag) — CloudFormation security linter

```bash
# Run Checkov against Terraform files
checkov -d ./infra --framework terraform

# Run tfsec
tfsec ./infra
```

Add these to your CI/CD pipeline — IaC security issues should block merges, not be caught post-deployment.

**Database encryption:** Verify RDS/Aurora instances have encryption at rest enabled. AI often generates these resources without it:

```hcl
# GOOD: encryption at rest enabled
resource "aws_db_instance" "main" {
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}
```

## Pre-Ship Checks

Before deploying:
- Run `gitleaks detect` on your repo to scan for leaked secrets in git history
- Verify `.env` files and MCP config files with secrets are in `.gitignore`
- Confirm debug mode / verbose logging is disabled
- Check that error responses don't leak stack traces
- Verify CORS is configured to allow only your domains
- Test that `https://yoursite.com/.git/HEAD` returns 404
- Confirm GraphQL introspection returns 403 or a disabled-introspection error
- Verify security headers are present on all responses (use securityheaders.com)
