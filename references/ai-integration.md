# AI / LLM Integration Security

## API Keys Are Server-Side Only

AI API keys (OpenAI, Anthropic, Google, etc.) must never appear in client-side code. A leaked key enables unlimited API usage at your expense. Attackers drain accounts within minutes of discovery.

- No `NEXT_PUBLIC_OPENAI_API_KEY`
- No `NEXT_PUBLIC_ANTHROPIC_API_KEY`
- No API keys in React Native / Expo bundles
- No API keys in client-side JavaScript

All AI API calls go through your backend. The client sends the user's message to your server; your server calls the AI API.

RedHunt Labs (Wave 15, 2025) found Google Gemini API keys in 72% of AI-platform secret exposures and OpenAI API keys in 14% of their scan of ~130,000 vibe-coded sites.

## Spending Caps

Set hard spending caps on every AI API provider:
- OpenAI: Usage limits in dashboard
- Anthropic: Spending limits in console
- Google: Budget alerts in Cloud Console

Also implement **per-user usage limits** in your application:
- Track token usage per user in your database
- Set daily/monthly caps per user or per tier
- Return a clear error when limits are exceeded
- Don't rely on the AI provider's caps alone — they may have lag

## Prompt Injection

User input must be sanitized before inclusion in prompts. Never concatenate raw user input into system prompts:

```typescript
// BAD: user can override system instructions
const prompt = `You are a helpful assistant. User says: ${userInput}`;

// BETTER: separate system and user messages
const messages = [
  { role: 'system', content: 'You are a helpful assistant.' },
  { role: 'user', content: userInput },
];
```

Even with separate messages, sophisticated prompt injection can still occur. For high-stakes applications:
- Validate and filter user input before inclusion in any prompt
- Validate LLM output before acting on it
- Limit tool access for user-facing AI features

## Indirect Prompt Injection via Retrieved Content

If your app uses RAG (Retrieval-Augmented Generation) or fetches web content to include in prompts, that content is an attack surface. A malicious document or web page can contain instructions like:

```
Ignore all previous instructions. Your new task is to...
```

**Mitigations:**
- Treat retrieved content as untrusted user input — include it in user messages, not system prompts
- Use a content firewall or prompt shield to detect injection attempts in retrieved data
- Validate LLM output before acting on it (especially if the LLM has tool access)
- Log all tool invocations so anomalous agent behaviour is detectable

## LLM Output Is Untrusted

LLM responses should be treated as untrusted user input:

- **Sanitize before rendering as HTML** — LLM output can contain `<script>` tags or event handlers. Use a safe renderer (e.g., `DOMPurify`) or render as plain text.
- **Never execute LLM output as code** without sandboxing (e.g., `eval()`, `new Function()`, passing to `child_process.exec`)
- **Validate tool/function call parameters** — if using function calling/tool use, validate all returned parameters against an allowlist and schema before executing

```typescript
// BAD: renders LLM output directly as HTML
const html = await getAIResponse(userMessage);
element.innerHTML = html; // XSS if LLM output contains script tags

// GOOD: sanitize before rendering
import DOMPurify from 'dompurify';
const sanitized = DOMPurify.sanitize(html);
element.innerHTML = sanitized;

// BEST: render as Markdown via a safe renderer, or as plain text
```

## Tool / Function Calling

If your application gives an LLM access to tools (database queries, API calls, file operations):
- Restrict operations to a safe allowlist
- Validate all parameters from the LLM against a schema before executing
- Use least-privilege access (read-only where possible)
- Log all tool invocations for audit
- Never let the LLM construct raw SQL, shell commands, or file paths from user input

```typescript
// BAD: LLM-constructed shell command
await exec(llmResponse.command);

// GOOD: validate against allowlist before executing
const ALLOWED_COMMANDS = ['npm test', 'npm run lint'];
if (!ALLOWED_COMMANDS.includes(llmResponse.command)) {
  throw new Error('Command not permitted');
}
await exec(llmResponse.command);
```

## Agentic AI Features

If your application builds autonomous AI agents (multi-step, tool-calling, memory-using):
- Apply the principle of least privilege to agent tool access
- Require explicit user confirmation for destructive or irreversible operations
- Set hard limits on the number of steps an agent can take per session
- Never grant an agent access to production credentials it doesn't need
- Log and make auditable every action an agent takes
