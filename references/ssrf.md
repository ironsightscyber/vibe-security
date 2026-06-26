# Server-Side Request Forgery (SSRF)

**OWASP API Security Top 10:** API7:2023 — present in 100% of AI-generated apps tested (OX Security, 15 production codebases). This is the most universally present vulnerability in AI-generated apps that make server-side HTTP requests.

**Why AI gets it wrong:** AI generators produce `fetch(userControlledUrl)` without any awareness that the server is making the request — not the browser. When a server fetches an attacker-controlled URL, the attacker can target internal services that are not publicly routable: cloud provider metadata endpoints, internal databases, Redis instances, and admin APIs.

## The Core Pattern

```typescript
// BAD: server fetching a user-supplied URL
export async function POST(req: Request) {
  const { url } = await req.json();
  const response = await fetch(url); // attacker sends http://169.254.169.254/latest/meta-data/
  return Response.json(await response.json());
}
```

**What an attacker does:**
1. Send `url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"` (AWS EC2 metadata)
2. Response contains `AccessKeyId`, `SecretAccessKey`, `Token` for your IAM role
3. Full AWS account compromise from a single API call

On non-EC2 environments: `http://169.254.169.254/` (GCP), `http://100.100.100.200/` (Alibaba Cloud), `http://localhost:6379/` (Redis), `http://localhost:5432/` (PostgreSQL).

## Where SSRF Appears in Vibe-Coded Apps

- **URL preview / link unfurling** — fetch the target URL to generate a preview
- **Avatar/profile image from URL** — fetch and re-host a user-supplied image URL
- **Webhook registration** — accept a URL from users that your server will POST events to
- **PDF/screenshot generation** — headless browser fetches a URL; attacker supplies an internal one
- **Import by URL** — "paste a URL to import data"
- **Proxy endpoints** — any `/api/proxy?url=...` pattern

## Fix: Block Private IP Ranges Before Fetching

```typescript
import dns from 'dns/promises';

const BLOCKED_PATTERNS = [
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,      // AWS/GCP metadata
  /^100\.100\./,      // Alibaba metadata
  /^::1$/,
  /^fc00:/,
  /^fd/,
];

export async function safeFetch(userUrl: string): Promise<Response> {
  let parsed: URL;
  try {
    parsed = new URL(userUrl);
  } catch {
    throw new Error('Invalid URL');
  }

  // Allowlist schemes
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('URL scheme not allowed');
  }

  // Resolve hostname to IP and check against private ranges
  const { address } = await dns.lookup(parsed.hostname);
  if (BLOCKED_PATTERNS.some(p => p.test(address))) {
    throw new Error('Requests to internal addresses are not allowed');
  }

  return fetch(userUrl, {
    redirect: 'follow',
    signal: AbortSignal.timeout(5000),
  });
}
```

**DNS rebinding caveat:** An attacker can register a hostname that resolves to a public IP during your check, then changes to a private IP before your fetch. Mitigations:
- Use a library that validates the *connected* IP, not the DNS resolution (e.g., `ssrf-filter` npm package)
- For webhook URLs: register the URL, send a test request, require the endpoint to echo back a one-time secret you included in the request

## Next.js Image Optimizer SSRF (CVE-2024-34351)

The `/_next/image` optimizer accepted a `url` parameter. Insufficient `remotePatterns` validation enabled blind SSRF via the image route.

Check `next.config.js`:

```javascript
// BAD: wildcard hostname — fetches any server on behalf of your Next.js instance
images: {
  remotePatterns: [{ hostname: '**' }]
}

// GOOD: allowlist only the specific domains you serve images from
images: {
  remotePatterns: [
    { protocol: 'https', hostname: 'cdn.yourapp.com' },
    { protocol: 'https', hostname: 'images.unsplash.com' },
  ]
}
```

## Webhook URL Registration

Any feature that accepts a URL and later POSTs to it is a persistent SSRF channel. An attacker registers `http://internal-admin:8080/admin/users` and waits for your system to POST events.

```typescript
// Validate webhook URLs at registration time
async function registerWebhook(url: string, userId: string) {
  // 1. Block private IPs
  const safeUrl = await validatePublicUrl(url);

  // 2. Send a verification request with a secret the endpoint must echo
  const secret = crypto.randomBytes(32).toString('hex');
  const verifyRes = await safeFetch(safeUrl, {
    method: 'POST',
    body: JSON.stringify({ type: 'webhook.verify', secret }),
  });

  const body = await verifyRes.json();
  if (body.secret !== secret) throw new Error('Webhook verification failed');

  await db.webhooks.create({ data: { url: safeUrl, userId } });
}
```
