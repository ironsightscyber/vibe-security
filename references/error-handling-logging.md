# Error Handling & Logging

## Don't Leak Stack Traces to Users

AI-generated apps routinely return raw error objects, stack traces, or internal paths in API responses. This hands attackers a map of your system.

```typescript
// BAD: leaks stack trace, file paths, and database schema to the client
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

// BAD: Next.js — returning the caught error directly
export async function POST(req: Request) {
  try {
    const data = await db.users.findUnique({ ... });
    return Response.json(data);
  } catch (err) {
    return Response.json({ error: err }, { status: 500 }); // leaks everything
  }
}

// GOOD: generic message to client, full detail to server logs only
export async function POST(req: Request) {
  try {
    const data = await db.users.findUnique({ ... });
    return Response.json(data);
  } catch (err) {
    console.error('[POST /api/users]', err); // full detail server-side
    return Response.json({ error: 'Something went wrong' }, { status: 500 });
  }
}
```

**What leaks in a stack trace:**
- File paths (revealing your project structure)
- ORM query details (revealing your schema)
- Library versions (revealing exploitable CVEs)
- Environment names and configuration

For validation errors, return a structured response without internal detail:

```typescript
// GOOD: structured validation error — useful to the client, safe
return Response.json({
  error: 'Validation failed',
  fields: { email: 'Invalid email address' }
}, { status: 400 });
```

## Distinguish Error Types for Logging

Not all errors need the same response. Log and handle them differently:

| Error type | Client response | Log level |
|------------|----------------|-----------|
| Validation error (400) | Specific field errors | `info` |
| Auth failure (401/403) | "Unauthorized" | `warn` — potential attack |
| Not found (404) | "Not found" | `info` |
| Rate limit (429) | "Too many requests" | `warn` — potential abuse |
| Unexpected server error (500) | "Something went wrong" | `error` with full stack |

Log 401/403 responses with the IP and user agent. A spike of 401s from one IP is a credential stuffing attempt.

## Server-Side Logging

Use a structured logging library rather than bare `console.log`:

```typescript
// BAD: unstructured, hard to query, lost in production
console.log('User deleted:', userId);

// GOOD: structured — queryable in Sentry, Datadog, CloudWatch, etc.
logger.info({ event: 'user.deleted', userId, actorId: session.user.id });
```

Log these events server-side:
- Authentication: login success/failure, password reset requests, MFA events
- Authorization failures: any 401/403 with source IP and endpoint
- Sensitive data access: any query touching PII, payment data, or admin records
- Configuration changes: role changes, permission updates, API key rotations

## Protect Logs from Tampering

Logs are only useful for incident response if they haven't been altered. Store logs:
- In a write-once external service (Sentry, Datadog, CloudWatch, Logtail)
- Separate from the application server — an attacker who owns your server shouldn't be able to cover their tracks
- With sufficient retention (90 days minimum for security events)

## Monitoring and Alerting

AI-generated apps ship with no monitoring. Add at minimum:

**Error monitoring:** Integrate Sentry or equivalent. Configure alerts for error rate spikes (a sudden increase in 500s often indicates an active exploit).

**Billing alerts:** Set threshold alerts on every cloud provider (Vercel, AWS, GCP) and every AI API provider (OpenAI, Anthropic). A compromised API key will drain your account before the morning.

**Anomaly detection:** Alert on:
- Unusual request volumes from a single IP or user
- Auth failure spikes
- Requests at hours inconsistent with your user base
- Large data exports (high-row queries on user tables)

```typescript
// Example: Sentry setup in Next.js
import * as Sentry from '@sentry/nextjs';

Sentry.init({
  dsn: process.env.SENTRY_DSN, // server-side only, not NEXT_PUBLIC_
  environment: process.env.NODE_ENV,
  tracesSampleRate: 0.1,
});
```

Note: `SENTRY_DSN` should NOT use the `NEXT_PUBLIC_` prefix on the server-side Sentry config — the DSN itself is semi-public but there's no reason to expose it unnecessarily.

## Never Log Sensitive Data

Common logging mistakes in AI-generated code:

```typescript
// BAD: logs the password in plaintext
logger.info('Login attempt', { email, password });

// BAD: logs the full request body (may contain credit card numbers, SSNs)
logger.info('API request', { body: req.body });

// BAD: logs the JWT (allows session hijacking from log access)
logger.debug('Session token', { token: req.headers.authorization });

// GOOD: log identifiers and outcomes, not sensitive values
logger.info('Login attempt', { email, success: false, ip });
logger.info('API request', { endpoint: req.url, method: req.method, userId });
```

Strip PII and secrets from logs before shipping to external services. Most logging platforms (Sentry, Datadog) have scrubbing rules you can configure.
