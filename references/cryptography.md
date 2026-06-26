# Cryptographic Failures

**OWASP:** A04:2025. Moved up from A02 in 2021 due to increased prevalence.

**Why AI gets it worse with prompting:** arXiv:2506.11022 found that asking AI to "make it more secure" produces the most cryptographic errors (21.1% of failures). AI replaces standard library calls with custom implementations, swaps bcrypt for SHA-256, and removes authentication from encryption modes. More prompting = worse crypto. Run this audit after every significant refinement pass.

## Password Hashing

Passwords must never be stored in plaintext, and must not be hashed with a general-purpose hash function.

**Why SHA-256/SHA-1/MD5 are wrong for passwords:** No work factor — a GPU can compute billions of SHA-256 hashes per second. A 6-character password is cracked in seconds. Rainbow tables cover all common passwords.

**Required:** Use bcrypt (cost ≥ 12), Argon2id, or scrypt:

```typescript
// BAD: plaintext
await db.users.create({ data: { email, password } });

// BAD: unsalted hash
const hash = crypto.createHash('sha256').update(password).digest('hex');

// BAD: MD5 (also used as "stronger" by AI when asked to "improve")
const hash = crypto.createHash('md5').update(password + salt).digest('hex');

// GOOD: bcrypt, cost factor ≥ 12 (higher = slower to brute force)
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12);
await db.users.create({ data: { email, passwordHash: hash } });

// ALSO GOOD: Argon2id (stronger than bcrypt, NIST recommended)
import argon2 from 'argon2';
const hash = await argon2.hash(password, { type: argon2.argon2id });
```

Verification:
```typescript
// GOOD: bcrypt.compare handles timing-safe comparison internally
const valid = await bcrypt.compare(submittedPassword, stored.passwordHash);
```

## Symmetric Encryption

For encrypting data at rest (SSNs, bank account numbers, health data):

**Use AES-256-GCM** — provides both encryption (confidentiality) AND authentication (integrity). Without authentication, an attacker can tamper with ciphertext and cause predictable decryption errors.

```typescript
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

// GOOD: AES-256-GCM with random nonce
function encrypt(plaintext: string, key: Buffer) {
  const iv = randomBytes(12); // MUST be unique per encryption
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { ciphertext: encrypted.toString('base64'), iv: iv.toString('base64'), tag: authTag.toString('base64') };
}

function decrypt(ciphertext: string, iv: string, tag: string, key: Buffer) {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}
```

**Why AES-CBC is wrong:** No authentication — padding oracle attacks decrypt arbitrary ciphertext without the key. CVE-2023-XXXX-class vulnerabilities. If you see AES-CBC in AI-generated code, replace it with AES-GCM.

**Why ECB mode is wrong:** Identical plaintext blocks produce identical ciphertext blocks — structural patterns are visible even without decryption. The classic "ECB penguin" demonstrates this.

## Nonce / IV Reuse is Catastrophic in AES-GCM

Reusing the same nonce with the same key in AES-GCM allows an attacker to recover both plaintexts and the authentication key — meaning they can forge any future ciphertext.

```typescript
// BAD: fixed nonce
const iv = Buffer.alloc(12, 0); // always zero

// BAD: derived from known data (timestamp in seconds — likely to repeat)
const iv = Buffer.from(Date.now().toString(36));

// GOOD: cryptographically random, generated fresh per encryption
const iv = randomBytes(12); // 96 bits, stored alongside ciphertext
```

Store the IV with the ciphertext — it's not secret, it just must be unique.

## Timing Attacks on Secret Comparison

JavaScript's `===` operator short-circuits on the first mismatched byte, returning faster for earlier mismatches. An attacker making thousands of requests can measure response times to determine secret values one byte at a time. This applies to:
- HMAC signature validation (Stripe webhooks, etc.)
- Session token comparison
- API key validation
- TOTP/OTP code comparison

```typescript
import { timingSafeEqual } from 'crypto';

// BAD: early exit leaks byte positions
if (providedSignature === expectedSignature) { ... }

// GOOD: constant-time comparison
const provided = Buffer.from(providedSignature);
const expected = Buffer.from(expectedSignature);
if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
  return new Response('Invalid signature', { status: 401 });
}
```

This is most critical on webhook signature validation and authentication endpoints.

## Weak Random Number Generation

`Math.random()` is not cryptographically secure — it uses a predictable PRNG. Never use it for security-sensitive values.

```typescript
// BAD: Math.random() is predictable
const resetToken = Math.random().toString(36).substring(2);
const sessionId = Date.now().toString(36) + Math.random().toString(36);

// GOOD: cryptographically secure random bytes
import { randomBytes } from 'crypto';
const resetToken = randomBytes(32).toString('hex'); // 64-char hex string
const sessionId = randomBytes(32).toString('base64url');
```

## HTTPS and TLS Configuration

Verify TLS 1.2+ is enforced — TLS 1.0 and 1.1 have known attacks (POODLE, BEAST). On Vercel and modern managed platforms this is automatic. On self-hosted: configure explicitly and test with `ssl-enum-tls` or SSL Labs.

Check certificates:
- Certificates auto-renewed (Let's Encrypt Certbot, or managed by the platform)
- No SHA-1 certificates in the chain
- HSTS header set with `max-age` ≥ 1 year: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

## Key Management

Encryption keys must not live in the database alongside the data they protect — if the database is compromised, the encrypted data is too.

```typescript
// BAD: key stored in the same database as encrypted data
const key = Buffer.from(await db.settings.findFirst({ where: { name: 'encryptionKey' } }).value, 'hex');

// GOOD: key from environment variable / secrets manager
const key = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex'); // 64 hex chars = 32 bytes
// Or: AWS KMS, HashiCorp Vault, Vercel environment secrets
```

Rotate keys periodically. When rotating: re-encrypt existing data with the new key using a key versioning scheme, don't just update the key in place.
