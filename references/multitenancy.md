# Multitenancy & Tenant Isolation

Most vibe-coded SaaS apps are multi-user by design — multiple customers share the same database. AI generates single-tenant examples from training data, then scales them to multi-tenant without adding the isolation layer.

**Result:** any authenticated user can read, modify, or delete any other user's data. This is the exact failure behind Moltbook (January 2026, 1.5 million tokens exposed), CVE-2025-48757 (170 Lovable apps, cross-tenant reads via `?select=*`), and the Lovable BOLA disclosure (18,697 users, 48 days unpatched).

The OWASP API Security Top 10 labels this BOLA (Broken Object Level Authorization) — the #1 API security risk.

## The Core Failure: Missing Scope on Every Query

```typescript
// BAD: returns ALL projects for ALL organizations
const projects = await db.project.findMany();

// BAD: returns this project regardless of who owns it
const project = await db.project.findUnique({ where: { id: params.id } });

// GOOD: scoped to the current session's organization
const projects = await db.project.findMany({
  where: { organizationId: session.user.organizationId }
});

// GOOD: scoped + 404 if not found or not owned
const project = await db.project.findUnique({
  where: { id: params.id, organizationId: session.user.organizationId }
});
if (!project) return new Response('Not found', { status: 404 });
```

**Note on 403 vs 404:** Return 404 (not 403) for resources the user doesn't own. A 403 confirms the resource exists and belongs to another tenant — information leakage that enables targeted attacks.

## The Tenant Scope Audit

Run these searches across your codebase before considering isolation complete:

```bash
# Find all Prisma queries that might be missing tenant scope
grep -rn "findMany\(\)" src/
grep -rn "findFirst({" src/
grep -rn "findUnique({" src/

# Each result needs: where.organizationId (or where.userId for user-scoped resources)
# Review every hit manually — this cannot be automated away
```

## Dangerous Patterns

### Background Jobs Without Tenant Context

```typescript
// BAD: cron job processes ALL records from ALL tenants
// If it processes them in bulk, tenant A's logic runs on tenant B's data
async function dailyCleanupJob() {
  const expiredItems = await db.items.findMany({
    where: { expiresAt: { lt: new Date() } }
  });
  await Promise.all(expiredItems.map(processItem));
}

// GOOD: always scope background jobs to one tenant at a time
async function dailyCleanupJob() {
  const orgs = await db.organization.findMany({ select: { id: true } });
  for (const org of orgs) {
    const expiredItems = await db.items.findMany({
      where: { organizationId: org.id, expiresAt: { lt: new Date() } }
    });
    await Promise.all(expiredItems.map(item => processItem(item, org.id)));
  }
}
```

### Raw `$queryRaw` Bypasses Application Scoping

Prisma's `$queryRaw` and `$queryRawUnsafe` bypass all middleware and application-level tenant logic. Every raw query must explicitly include the `organization_id` filter:

```typescript
// BAD: no tenant scope
const results = await prisma.$queryRaw`SELECT * FROM "Document" WHERE id = ${id}`;

// GOOD: tenant scope in the raw query
const results = await prisma.$queryRaw`
  SELECT * FROM "Document" WHERE id = ${id} AND organization_id = ${session.organizationId}
`;
```

### Existence Disclosure

Distinguishable error responses reveal whether a resource belongs to another tenant:

```typescript
// BAD: tells attacker the ID exists but belongs to someone else
if (!project) return new Response('Forbidden', { status: 403 });

// GOOD: same response whether it doesn't exist or isn't yours
if (!project) return new Response('Not found', { status: 404 });
```

### Predictable IDs Enable Enumeration

If resource IDs are auto-increment integers (1, 2, 3...), an attacker can iterate through IDs to harvest data across tenants. Use UUIDs or CUID2 for all resource IDs:

```prisma
// BAD: sequential integer IDs
model Document {
  id Int @id @default(autoincrement())
}

// GOOD: random UUIDs
model Document {
  id String @id @default(cuid())
}
```

Even with random IDs, ownership checks are still mandatory — random isn't the security control, it's just defense-in-depth.

## Supabase Multitenancy

Supabase RLS is your primary tenant isolation layer when the public PostgREST API is in use. Without RLS, every anon-key request can access every tenant's data.

The RLS policy must scope to both the authenticated user AND their organization:

```sql
-- For user-owned resources
CREATE POLICY "user_owned" ON public.documents
  FOR ALL TO authenticated
  USING ((SELECT auth.uid()) = user_id)
  WITH CHECK ((SELECT auth.uid()) = user_id);

-- For organization-owned resources (users belong to an org)
CREATE POLICY "org_owned" ON public.documents
  FOR SELECT TO authenticated
  USING (
    organization_id IN (
      SELECT organization_id FROM public.memberships
      WHERE user_id = (SELECT auth.uid())
    )
  );
```

See `references/database-security.md` for full Supabase RLS guidance.

## PostgreSQL RLS Optimizer Bug

CVE-2024-10976 and CVE-2025-8713 confirm that PostgreSQL's query planner can leak RLS-protected data in specific cases involving lateral joins and parallel queries. If you have RLS configured but are still seeing cross-tenant data, check your PostgreSQL version and update to the patched release.

## Validate in the Correct Layer

Tenant isolation must be enforced at the database query level — not just in API route middleware. Middleware that checks "is this user in this org?" before routing is not sufficient if the database queries themselves aren't scoped. An SSRF bypass, a direct API call, or a background job context all skip route-level middleware.

The rule: **every database query that returns tenant data must include a tenant scope condition, regardless of where it's called from.**
