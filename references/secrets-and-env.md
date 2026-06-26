# Secrets & Environment Variables

## Hardcoded Credentials

Never hardcode API keys, tokens, passwords, or credentials in source code. This includes:
- Strings that look like API keys in source files
- Connection strings with embedded passwords
- Private keys or certificates in the repo

If a secret was ever committed to Git history, consider it compromised — deleting the file doesn't remove it from history. The key must be rotated immediately. Run `gitleaks detect` to scan for leaked secrets.

## Client-Side Environment Variable Prefixes

These prefixes cause env vars to be inlined into the client bundle at build time. Everything in the bundle is visible to anyone:

| Framework | Client Prefix | Danger |
|-----------|--------------|--------|
| Next.js | `NEXT_PUBLIC_` | Inlined into browser JS at build time |
| Vite | `VITE_` | Inlined into browser JS at build time |
| Expo / React Native | `EXPO_PUBLIC_` | Baked into the app bundle |
| Create React App | `REACT_APP_` | Inlined into browser JS at build time |

**What belongs client-side:**
- Stripe publishable key (`pk_live_*`, `pk_test_*`)
- Supabase anon key
- Firebase client config (apiKey, authDomain, projectId)
- Public analytics IDs (GA4, GTM)

**What must NEVER be client-side:**
- Supabase `service_role` key (bypasses all RLS)
- Stripe secret key (`sk_live_*`, `sk_test_*`)
- Any database connection string
- Any third-party API secret key
- JWT signing secrets
- OAuth client secrets
- OpenAI / Anthropic / Google AI API keys

## MCP Configuration Files — New High-Risk Vector (2025)

MCP config files are now a leading secret-leak category. GitGuardian State of Secrets Sprawl 2026 found 24,008 unique exposed secrets specifically in MCP configuration files in 2025. These files often contain API keys, database credentials, and service tokens.

Files to check for committed secrets:
- `.mcp.json` at project root
- `.claude/settings.json`
- `.cursor/mcp.json`
- Any `*mcp*.json` or `*mcp*.yaml` file

These files should be in `.gitignore` if they contain credentials, or use environment variable references (`${MY_SECRET}`) rather than inline values.

```json
// BAD: secret inline in MCP config
{
  "mcpServers": {
    "myserver": {
      "env": {
        "API_KEY": "sk_live_abc123..."
      }
    }
  }
}

// GOOD: reference an environment variable
{
  "mcpServers": {
    "myserver": {
      "env": {
        "API_KEY": "${MY_API_KEY}"
      }
    }
  }
}
```

## .gitignore

Ensure `.env`, `.env.local`, `.env.*.local`, and any file containing secrets is in `.gitignore` **before the first commit**. Check that `.env.example` or `.env.sample` files contain only placeholder values, not real keys.

Also add MCP config files containing credentials:
```
.env
.env.local
.env.*.local
.mcp.json
.cursor/mcp.json
```

If you have a shared `.mcp.json` that needs committing (for tool definitions), move secrets to `.env` and reference them as environment variables.

## Detection Tips

When auditing, search for:
- Files named `.env` that are tracked by git: `git ls-files | grep -E '\.env'`
- Strings matching common key patterns: `sk_live_`, `sk_test_`, `AKIA`, `ghp_`, `glpat-`, `xoxb-`, `Bearer `
- `process.env.NEXT_PUBLIC_` or `import.meta.env.VITE_` referencing anything with "secret", "private", "service", "key", or "token" in the name
- Hardcoded URLs containing credentials (e.g., `postgresql://user:password@host`)
- High-entropy strings in MCP config files (run `detect-secrets scan`)

## Scale of the Problem

RedHunt Labs scanned ~130,000 vibe-coded sites in 2025 (Wave 15) and found secrets in 1 in 5. GitGuardian's 2026 report recorded 28.65 million new hardcoded secrets in public GitHub commits during 2025 — a 34% year-over-year increase, the largest single-year jump on record.
