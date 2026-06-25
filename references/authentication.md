# Authentication & Authorization

## Multi-Factor Authentication (MFA)

AI-generated apps almost never implement MFA. For any app handling sensitive data, payments, or admin access, MFA is a baseline control — not an optional upgrade.

**Where MFA matters most:**
- Admin and staff accounts (always)
- Any account with elevated permissions or billing access
- Accounts with access to PII or financial data

**Implementation options in order of strength:**
1. **Hardware key (FIDO2/WebAuthn)** — strongest, phishing-resistant, eliminates SMS interception attacks
2. **TOTP (Google Authenticator, Authy)** — strong, works offline, vulnerable to real-time phishing
3. **Email OTP** — acceptable for low-sensitivity apps, vulnerable to account takeover via email compromise
4. **SMS OTP** — weakest, vulnerable to SIM-swap attacks; avoid for high-value accounts

If you're using Clerk, Auth0, or Supabase Auth, MFA is a configuration flag — there's no reason not to enable it:

```typescript
// Clerk: enable MFA in the Clerk Dashboard, then enforce it for specific roles
// Auth0: enable MFA in the Auth0 Dashboard under Security → Multi-factor Auth
// Supabase: MFA available via supabase.auth.mfa.*
```

For admin routes, verify MFA was used in the current session — don't rely on the user having MFA enabled, verify it was actually completed:

```typescript
// Clerk: check the session's second factor
const { sessionClaims } = auth();
if (!sessionClaims?.metadata?.mfaVerified) {
  redirect('/verify-mfa');
}
```

## Role-Based Access Control (RBAC)

RBAC ensures users can only access functions and data relevant to their role. AI assistants generate a single auth check ("is logged in?") and rarely model role hierarchies.

**Principle of least privilege:** every user, service, and API key should have the minimum permissions needed to do their job.

```typescript
// BAD: any authenticated user can access admin endpoints
export async function GET(req: Request) {
  const session = await auth();
  if (!session) return new Response('Unauthorized', { status: 401 });
  // ... returns admin data
}

// GOOD: check role explicitly
export async function GET(req: Request) {
  const session = await auth();
  if (!session) return new Response('Unauthorized', { status: 401 });
  if (session.user.role !== 'admin') return new Response('Forbidden', { status: 403 });
  // ... returns admin data
}
```

**Store roles server-side, never client-side.** Roles must come from your database or identity provider — never from a cookie, localStorage value, or JWT claim that the user controls.

**Common RBAC patterns:**
- `user` / `admin` — simple two-tier, suitable for most apps
- `user` / `moderator` / `admin` — three-tier for community platforms
- Resource-level permissions — "user owns resource" + "admin can access all" combination

**Permission checks on every mutation:** role checks aren't just for read access. Delete, update, and publish operations all need role verification:

```typescript
// Define a helper to avoid repeating role checks
async function requireRole(session: Session | null, role: string) {
  if (!session?.user) redirect('/login');
  if (session.user.role !== role) throw new Error('Forbidden');
  return session;
}

export async function deletePost(postId: string) {
  'use server';
  const session = await auth();
  const post = await db.posts.findUnique({ where: { id: postId } });

  // Either the post owner or an admin can delete
  const isOwner = post?.authorId === session?.user?.id;
  const isAdmin = session?.user?.role === 'admin';
  if (!isOwner && !isAdmin) throw new Error('Forbidden');

  await db.posts.delete({ where: { id: postId } });
}
```

## IDOR / Broken Object-Level Authorization (BOLA)

**This is the #1 vulnerability class in AI-generated code** — 1.91× more likely than in human-written code (CSA 2025). AI assistants reliably add authentication ("is the user logged in?") but skip authorization ("does this user own this resource?"). Traditional SAST tools miss approximately 0% of authorization bugs; they require semantic understanding of ownership.

The pattern appears in almost every AI-generated REST API:

```typescript
// BAD: authentication only — any user can read any invoice
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return new Response('Unauthorized', { status: 401 });

  const invoice = await db.invoices.findUnique({ where: { id: params.id } });
  return Response.json(invoice);
}

// GOOD: authentication + authorization — scoped to the owner
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return new Response('Unauthorized', { status: 401 });

  const invoice = await db.invoices.findUnique({
    where: { id: params.id, userId: session.user.id }
  });
  if (!invoice) return new Response('Not found', { status: 404 });
  return Response.json(invoice);
}
```

The rule: **every data access query on a user-owned resource must include `WHERE userId = currentUserId`** (or equivalent ownership condition).

Real-world confirmation: A Lovable BOLA flaw (reported February 2026) exposed 18,697 user records and 4,538 student accounts — remaining unpatched for 48 days after disclosure.

## JWT Handling

- **Use `jwt.verify()`, never `jwt.decode()` alone.** `decode` reads the payload without checking the signature — an attacker can forge any payload.
- **Explicitly allowlist algorithms.** Some JWT libraries accept unsigned tokens (`"alg": "none"`) or allow algorithm confusion attacks (RS256 → HS256). Never read the `alg` field from the token header to decide how to verify; hardcode the expected algorithm in your verification options.

**Algorithm confusion attack:** If a server uses RS256 (asymmetric), an attacker can change the header to `{"alg": "HS256"}`, then sign the token with the server's *public* key. A vulnerable verifier using the public key as its HMAC "secret" accepts it. Multiple CVEs in 2026 document this exact pattern in AI-generated code (CVE-2026-22817, CVE-2026-27804, CVE-2026-23552).

```typescript
// BAD: reads alg from the token header, vulnerable to algorithm confusion
const payload = jwt.verify(token, publicKey);

// BAD: reads payload without verifying signature
const payload = jwt.decode(token);

// GOOD: explicit algorithm allowlist, validates issuer and expiry
const payload = jwt.verify(token, secret, {
  algorithms: ['HS256'],  // never ['RS256', 'HS256'] — pick one
  issuer: 'your-app',
});
```

## OAuth Misconfigurations

AI-generated OAuth flows commonly omit three critical defences:

**1. State parameter (CSRF on OAuth callbacks)**
```typescript
// BAD: no state — attacker can forge the callback
router.get('/auth/github', (req, res) => {
  res.redirect(`https://github.com/login/oauth/authorize?client_id=${CLIENT_ID}`);
});

// GOOD: generate and store a random state, verify on callback
const state = crypto.randomBytes(16).toString('hex');
req.session.oauthState = state;
res.redirect(`https://github.com/login/oauth/authorize?client_id=${CLIENT_ID}&state=${state}`);

// In the callback handler:
if (req.query.state !== req.session.oauthState) {
  return res.status(403).send('Invalid state');
}
```

**2. redirect_uri validation**
The `redirect_uri` must be validated against a hardcoded allowlist on the server, not just trusted as-is from the request. An unvalidated redirect_uri allows token theft via open redirect.

**3. PKCE for public clients (now mandatory per RFC 9700)**
SPAs, mobile apps, and CLIs must use PKCE (`code_challenge` + `code_verifier`). Without it, the authorization code can be intercepted and exchanged by an attacker.

## Next.js Middleware Is Not Enough

Next.js middleware runs at the edge and is convenient for auth checks, but it is **not a reliable sole auth layer**. CVE-2025-29927 demonstrated that middleware could be completely bypassed via a spoofed `x-middleware-subrequest` header.

Always verify auth again in:
- Server Actions
- Route Handlers (`app/api/`)
- Data access functions / database queries

Middleware is a convenience layer, not the only wall between an attacker and your data.

## Server Actions Are Public Endpoints

Server Actions compile into public POST endpoints. Anyone can call them with `curl`. AI assistants frequently generate Server Actions that assume they're only called by the UI:

```typescript
// BAD: no auth check, no input validation, no ownership check
'use server';
export async function deleteItem(id: string) {
  await db.items.delete({ where: { id } });
}

// GOOD: validates input, authenticates, and authorizes ownership
'use server';
export async function deleteItem(input: unknown) {
  const parsed = z.object({ id: z.string().cuid() }).safeParse(input);
  if (!parsed.success) return { error: 'Invalid input' };

  const session = await auth();
  if (!session?.user) redirect('/login');

  await db.items.deleteMany({
    where: { id: parsed.data.id, userId: session.user.id }
  });
}
```

Every Server Action needs three things at the top:
1. **Input validation** (Zod or similar)
2. **Authentication** (verify the user is logged in)
3. **Authorization** (verify the user owns the resource)

## Data Leakage to Client Components

Never pass entire database objects to Client Components. They may contain sensitive fields (hashed passwords, internal IDs, admin flags). Select only the fields the client needs:

```typescript
// BAD: leaks all fields including passwordHash, isAdmin, stripeCustomerId
const user = await db.users.findUnique({ where: { id } });
return <UserProfile user={user} />;

// GOOD: select only needed fields
const user = await db.users.findUnique({
  where: { id },
  select: { name: true, avatarUrl: true }
});
return <UserProfile user={user} />;
```

Use `import 'server-only'` at the top of data access modules to prevent them from being accidentally imported into Client Components.

## Session & Token Storage

- Store tokens in `HttpOnly + Secure + SameSite=Lax` cookies, **not localStorage**.
- localStorage is accessible to any JavaScript on the page — a single XSS vulnerability exposes all tokens.
- `HttpOnly` cookies are invisible to JavaScript and sent automatically by the browser.
