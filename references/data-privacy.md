# Data Privacy & Compliance

AI-generated apps frequently collect more data than they need, store it without encryption, and have no mechanism to delete it. In Australia, this creates liability under the Privacy Act 1988 (Australian Privacy Principles). For apps with EU users: GDPR. For Californian users: CCPA.

This section focuses on the technical controls — not the legal text. A lawyer handles the legal text; this skill handles the code.

## Collect Only What You Need (Data Minimisation)

AI assistants tend to generate schemas that capture everything "just in case." Review every field in every table and ask: is this actually used? If not, don't collect it.

```typescript
// BAD: collecting full date of birth when only age verification is needed
const schema = z.object({
  name: z.string(),
  email: z.string().email(),
  dateOfBirth: z.string(), // stored permanently in DB
  phone: z.string(),
  address: z.string(),
  nationality: z.string(),
});

// GOOD: collect only what the feature requires
const schema = z.object({
  name: z.string(),
  email: z.string().email(),
  isOver18: z.boolean(), // derive this at signup, discard the DOB
});
```

**PII to audit for:** government IDs, full DOB, biometric data, precise location history, race/ethnicity, health data, financial account numbers. If you're storing these, you need a specific reason and appropriate controls.

## Encrypt Sensitive Data at Rest

Passwords must never be stored in plaintext. Use bcrypt, Argon2, or scrypt with appropriate cost factors.

```typescript
// BAD: plaintext password
await db.users.create({ data: { email, password } });

// BAD: MD5 or SHA-1 (reversible with rainbow tables)
const hash = crypto.createHash('md5').update(password).digest('hex');

// GOOD: bcrypt with cost factor ≥ 12
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12);
await db.users.create({ data: { email, passwordHash: hash } });
```

For other sensitive fields (SSNs, bank account numbers, health data), encrypt at the application layer before storing:

```typescript
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

// Use AES-256-GCM — provides both encryption and integrity
function encrypt(plaintext: string, key: Buffer): { ciphertext: string; iv: string; tag: string } {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    ciphertext: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
  };
}
```

Store the encryption key in your secrets manager (AWS KMS, Vault, or at minimum a non-`NEXT_PUBLIC_` env var), never in the database.

## Right to Deletion (GDPR Article 17 / APP 13)

AI-generated apps almost never implement account deletion. Users have a legal right to have their data deleted under GDPR and the Australian Privacy Act.

This isn't just a button — it requires:

1. **Identify all tables containing the user's data** — not just `users`, but also audit logs, message threads, uploaded files in storage, Stripe customer records, third-party integrations
2. **Cascade-delete or anonymise** — deleting the user row isn't enough if other tables have foreign keys or denormalised copies
3. **Handle third-party data** — you may need to call Stripe's API to delete the customer, delete files from S3, purge from your email provider

```typescript
// Example: comprehensive user deletion
export async function deleteUser(userId: string) {
  await db.$transaction([
    db.auditLogs.updateMany({ where: { userId }, data: { userId: null } }), // anonymise logs
    db.messages.deleteMany({ where: { senderId: userId } }),
    db.userFiles.deleteMany({ where: { userId } }),
    db.users.delete({ where: { id: userId } }),
  ]);

  // External cleanup
  await stripe.customers.del(user.stripeCustomerId);
  await deleteS3Folder(`users/${userId}/`);
}
```

## Data Retention Limits

Don't keep data indefinitely. Define and enforce retention periods:

- **Inactive account data:** 12 months of inactivity → notify → 30 days → delete
- **Audit logs:** 90 days for security events, 7 years for financial records (check your jurisdiction)
- **Session tokens:** expire and delete after a reasonable period

Implement a scheduled job (cron) to enforce these limits, not a one-time migration.

## User Consent

If you collect marketing data, use cookies for tracking, or process data beyond the purpose of the service:

- **Display a cookie consent banner** before loading analytics or marketing scripts
- **Don't pre-tick marketing consent checkboxes** — consent must be explicit, not opt-out
- **Log consent with a timestamp** — you need to prove consent was given

```typescript
// BAD: loading analytics before consent
useEffect(() => {
  gtag('config', GA_TRACKING_ID); // runs immediately on page load
}, []);

// GOOD: only load analytics after consent is given
useEffect(() => {
  if (consentGiven) {
    gtag('config', GA_TRACKING_ID);
  }
}, [consentGiven]);
```

## Australian Privacy Principles (APP) — Key Technical Requirements

For apps with Australian users (and IronSights clients specifically):

| Principle | Technical requirement |
|-----------|----------------------|
| APP 1 — Open and transparent | Privacy policy accessible from the app |
| APP 3 — Collection of solicited PI | Only collect what's needed for the stated purpose |
| APP 6 — Use or disclosure | Don't use data for purposes beyond what was disclosed at collection |
| APP 11 — Security of PI | Reasonable technical measures to protect from misuse, loss, unauthorised access |
| APP 13 — Correction of PI | Users can correct inaccurate data |

APP 11 is the most technically relevant. "Reasonable technical measures" includes: encryption at rest, access controls, audit logging, and breach detection/notification capability.

**Notifiable Data Breaches (NDB) scheme:** If a breach is likely to result in serious harm to any individual, you must notify the Office of the Australian Information Commissioner (OAIC) and affected individuals as soon as practicable. Have an incident response runbook before you need it.

## GDPR Essentials (EU users)

- **Privacy by design:** default settings should be the most privacy-preserving
- **Data Processing Agreement (DPA):** required with any third-party processor (Stripe, Sentry, email providers)
- **Data Subject Access Request (DSAR):** users can request all data you hold about them — build an export feature before someone asks
- **Breach notification:** 72 hours to notify the supervisory authority of a breach

## Transmission Security

All data in transit must use TLS 1.2+. Verify:
- HTTPS enforced (HTTP redirects to HTTPS, HSTS header set)
- No sensitive data in URL query parameters (logs, referrer headers capture these)
- API responses include `Cache-Control: no-store` for endpoints returning PII

```typescript
// BAD: sensitive data in URL (appears in server logs and browser history)
fetch(`/api/users?email=${userEmail}&ssn=${ssn}`);

// GOOD: sensitive data in request body
fetch('/api/users', { method: 'POST', body: JSON.stringify({ email, ssn }) });
```
