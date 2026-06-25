# Deployment Security

## Production Configuration

- **Disable debug mode** in production. Debug pages often leak stack traces, environment variables, and internal paths.
- **Disable source maps** in production. Source maps expose your entire source code to anyone who opens DevTools. In Next.js: `productionBrowserSourceMaps: false` (the default) — confirm it hasn't been enabled.
- **Verify `.git` directory is not accessible** in production. If `https://yoursite.com/.git/HEAD` returns content, your entire source code and commit history (including any secrets ever committed) are exposed.

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
