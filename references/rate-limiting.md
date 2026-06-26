# Rate Limiting & Abuse Prevention

## The Wiring Gap

Research consistently finds that rate limiting middleware is *defined* in AI-generated codebases but never *mounted* on the routes that need it. The middleware exists; it's just not connected.

After implementing rate limiting, verify it is actually applied:

```typescript
// BAD: defined but not used
const ratelimit = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(10, '1m') });

export async function POST(req: Request) {
  // ratelimit is never called here — the import does nothing
  return handleLogin(req);
}

// GOOD: called at the top of every protected handler
export async function POST(req: Request) {
  const ip = req.headers.get('x-forwarded-for') ?? '127.0.0.1';
  const { success } = await ratelimit.limit(ip);
  if (!success) return new Response('Too many requests', { status: 429 });

  return handleLogin(req);
}
```

**Test that rate limiting actually fires:** Make 11 rapid requests to an auth endpoint — the 11th should return 429. If it doesn't, the middleware isn't wired.

## Where Rate Limiting Is Required

Every one of these endpoints needs rate limiting. AI assistants almost never add it:

- **Auth endpoints** — login, register, password reset, OTP verification, magic link. Without limits, attackers can brute-force passwords or enumerate accounts.
- **AI API calls** — any endpoint that calls OpenAI, Anthropic, or similar. A single user can drain your entire monthly budget in minutes.
- **Email / SMS sending** — attackers can use your app as a spam relay.
- **File processing** — upload, resize, convert. CPU-intensive operations without limits enable denial-of-service.
- **Webhook-like endpoints** — anything accepting external input at scale.

## Don't Store Rate Limits in Public Tables

If rate limit counters live in a Supabase public table, users can reset their own counters via the REST API. Use:

- **Upstash Redis** — serverless Redis with built-in rate limiting primitives
- **Private schema table** — not exposed via PostgREST
- **Middleware-level limiting** — at the edge or API gateway
- **In-memory stores** — for single-server deployments (Redis for multi-server)

## Combine Per-IP and Per-User Limiting

- IP-only limits are defeated by rotating IPs (trivial with VPNs or botnets)
- User-only limits are defeated by creating new accounts
- Use both together for effective protection

## Billing Protection

- Set billing alerts on every cloud provider (AWS, GCP, Vercel, etc.)
- Set **hard spending caps** on AI API providers (OpenAI, Anthropic)
- Use per-user usage quotas with hard limits, not just soft warnings
- Monitor for anomalous usage patterns (sudden spikes, requests at odd hours)

## CAPTCHA for Bot Prevention

Rate limiting alone doesn't stop automated attacks — a botnet with 10,000 IPs each making one request per minute bypasses per-IP limits entirely. CAPTCHA adds a human verification layer.

**Where CAPTCHA is appropriate:**
- Signup / registration forms (stops account farming)
- Password reset requests (stops enumeration attacks)
- Contact / feedback forms (stops spam)
- Any form that triggers expensive operations or sends email

**Where CAPTCHA is NOT appropriate:**
- Login (use rate limiting instead — CAPTCHA on login degrades UX significantly)
- Authenticated API endpoints (users are already verified)

**Implementation options:**
- [Cloudflare Turnstile](https://www.cloudflare.com/products/turnstile/) — invisible, no "click the traffic lights", privacy-respecting
- [hCaptcha](https://www.hcaptcha.com/) — GDPR-friendly alternative to reCAPTCHA
- Google reCAPTCHA v3 — invisible score-based, note: shares data with Google

Always verify the CAPTCHA token **server-side**. A client-side-only check is trivially bypassed:

```typescript
// GOOD: verify the Cloudflare Turnstile token server-side
export async function POST(req: Request) {
  const { token, ...formData } = await req.json();

  const verifyRes = await fetch(
    'https://challenges.cloudflare.com/turnstile/v0/siteverify',
    {
      method: 'POST',
      body: JSON.stringify({
        secret: process.env.TURNSTILE_SECRET_KEY,
        response: token,
      }),
    }
  );

  const { success } = await verifyRes.json();
  if (!success) return new Response('CAPTCHA failed', { status: 400 });

  // ... process the form
}
```

## Implementation Pattern

```typescript
// Example: rate limiting with Upstash Redis
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '1 m'), // 10 requests per minute
});

export async function POST(request: Request) {
  const ip = request.headers.get('x-forwarded-for') ?? '127.0.0.1';
  const { success } = await ratelimit.limit(ip);
  if (!success) {
    return new Response('Too many requests', { status: 429 });
  }
  // ... handle request
}
```

For authenticated endpoints, rate limit on user ID (from session) in addition to IP:

```typescript
const identifier = session?.user?.id ?? ip;
const { success } = await ratelimit.limit(identifier);
```
