# Data Access & Input Validation

## SQL Injection

Always use parameterized queries or ORM methods. Never concatenate user input into SQL strings:

```typescript
// BAD: SQL injection via string concatenation
const result = await db.query(`SELECT * FROM users WHERE id = '${userId}'`);

// GOOD: parameterized query
const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
```

## Prisma Operator Injection (Auth Bypass)

Distinct from general ORM misuse — this specific pattern enables authentication bypass. If an unvalidated request body is passed directly to Prisma's `findFirst`, an attacker can inject MongoDB-style operators as JSON values.

```typescript
// BAD: req.body = { email: "admin@co.com", password: { "not": "" } }
// Prisma runs: WHERE email = ? AND password != ''
// Finds the user and returns them regardless of actual password
const user = await prisma.user.findFirst({ where: req.body });

// GOOD: use Zod to validate scalar types before Prisma; use findUnique for auth
const { email, password } = z.object({
  email: z.string().email(),
  password: z.string().min(1),
}).parse(req.body);

// findUnique rejects operator objects at the TypeScript level
const user = await prisma.user.findUnique({ where: { email } });
if (!user || !await bcrypt.compare(password, user.passwordHash)) {
  return new Response('Invalid credentials', { status: 401 });
}
```

The deeper fix: never use `findFirst` for authentication. Use `findUnique` on a uniquely constrained field (email, username), then validate the password separately.

## ORM Safety (Prisma)

Even with an ORM, injection is possible:

- **Validate input types with Zod before passing to Prisma.** `findFirst` and similar methods are vulnerable to operator injection if unvalidated objects are passed as filter values. An attacker can send `{ "email": { "contains": "" } }` to match all records.

```typescript
// BAD: raw request body passed directly to Prisma
const user = await prisma.user.findFirst({ where: req.body });

// GOOD: validate with Zod first
const schema = z.object({ email: z.string().email() });
const parsed = schema.parse(req.body);
const user = await prisma.user.findFirst({ where: { email: parsed.email } });
```

- **Never use `$queryRawUnsafe` or `$executeRawUnsafe` with user-supplied input.**

```typescript
// BAD: raw SQL with user input
const results = await prisma.$queryRawUnsafe(
  `SELECT * FROM users WHERE name = '${name}'`
);

// GOOD: safe tagged template literal
const results = await prisma.$queryRaw`
  SELECT * FROM users WHERE name = ${name}
`;
```

## Input Validation

Validate all external input at system boundaries using a runtime schema validator (Zod, Yup, Joi, etc.):

- API route handlers
- Server Actions
- Webhook handlers
- Form submissions
- URL parameters and query strings

Don't rely on TypeScript types alone — they're compile-time only and don't exist at runtime. An attacker sending a malformed request bypasses all TypeScript checks.

## Mass Assignment

Don't spread request bodies directly into database operations. An attacker can add unexpected fields:

```typescript
// BAD: attacker can add { isAdmin: true, credits: 99999, subscriptionTier: 'enterprise' }
await db.users.update({ where: { id }, data: req.body });

// GOOD: pick only allowed fields
const { name, email } = validated.data;
await db.users.update({ where: { id }, data: { name, email } });
```

## ReDoS from AI-Generated Regex

AI generates regex patterns that look correct but have catastrophic backtracking behaviour. These crash or hang a Node.js server under targeted input.

Common catastrophic patterns AI produces:
- `(a+)+` — nested quantifiers
- `(a|aa)+` — alternation with overlapping matches
- Email validators with ambiguous middle sections: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$` is generally safe; variants adding optional groups or nested character classes often aren't

**Mitigation:**
- Test regex patterns with `safe-regex` or `vuln-regex-detector` before deploying
- For user-facing input validation, prefer a well-maintained library (e.g., `validator.js`) over hand-rolled regex
- Set a timeout on any regex operation applied to untrusted input if your runtime supports it

```typescript
// DANGEROUS: catastrophic backtracking on crafted input
const emailRegex = /^([a-zA-Z0-9]+(\.?[a-zA-Z0-9])+)+@([\w-]+\.)+[\w]{2,}$/;

// SAFER: use a tested library
import { isEmail } from 'validator';
if (!isEmail(input)) throw new Error('Invalid email');
```

## Insecure Deserialization

AI-generated Python code frequently uses `pickle.loads()` on untrusted data. AI-generated Node.js code sometimes uses `eval()` for JSON-like parsing. CSA 2025 found AI-generated code is 1.82× more likely to include insecure deserialization vulnerabilities.

```python
# BAD: arbitrary code execution — pickle can execute anything on deserialize
data = pickle.loads(user_supplied_bytes)

# GOOD: use JSON for data exchange
data = json.loads(user_supplied_string)
```

```typescript
// BAD: executes arbitrary code
const data = eval(`(${userInput})`);

// GOOD: JSON.parse with error handling
const data = JSON.parse(userInput);
```

Never deserialize data from untrusted sources (user uploads, external APIs you don't control) using formats that support arbitrary code execution.

## Race Conditions / TOCTOU in Async Code

AI applies synchronous check-then-act patterns to async contexts, creating race windows between `await` calls. Two concurrent requests can both pass a balance check before either debit executes.

```typescript
// BAD: TOCTOU — two requests can both pass the balance check
const user = await db.users.findUnique({ where: { id } });
if (user.credits < cost) return { error: 'Insufficient credits' };
// race window here — another request can run this same check
await db.users.update({ where: { id }, data: { credits: user.credits - cost } });

// GOOD: atomic update with condition
const result = await db.users.updateMany({
  where: { id, credits: { gte: cost } },
  data: { credits: { decrement: cost } },
});
if (result.count === 0) return { error: 'Insufficient credits' };
```

For complex multi-step operations touching shared state, use database transactions:

```typescript
// GOOD: transaction ensures atomicity
await db.$transaction(async (tx) => {
  const user = await tx.users.findUnique({ where: { id }, select: { credits: true } });
  if (user.credits < cost) throw new Error('Insufficient credits');
  await tx.users.update({ where: { id }, data: { credits: { decrement: cost } } });
  await tx.orders.create({ data: { userId: id, amount: cost } });
});
```
