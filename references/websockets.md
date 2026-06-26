# WebSocket Security

AI assistants consistently wire authentication to REST endpoints then skip it entirely on WebSocket connections. Help Net Security's study of Claude Code, Codex, and Gemini found all three made this mistake across every tested codebase. CVE-2025-52882 was an unauthenticated WebSocket in Claude Code's own VS Code extension.

## Failure 1: No Auth on the WebSocket Upgrade

HTTP middleware applied to `/api/*` does not automatically apply to WebSocket upgrade requests. The upgrade is a separate HTTP handshake — it does not go through Express middleware, Next.js route handlers, or any other standard middleware chain.

```javascript
// BAD: auth middleware on REST, but not on WebSocket upgrade
app.use('/api', verifyToken);

const wss = new WebSocketServer({ server });
wss.on('connection', (ws, req) => {
  // req.user is undefined — no middleware ran here
  // Any client can connect
  ws.on('message', handleMessage);
});

// GOOD: verify auth during the upgrade handshake
wss.on('connection', async (ws, req) => {
  try {
    const token = new URL(req.url, 'http://localhost').searchParams.get('token');
    const user = await verifyToken(token);
    ws.user = user; // attach to socket for use in message handlers
  } catch {
    ws.close(4001, 'Unauthorized');
    return;
  }

  ws.on('message', (msg) => handleMessage(ws.user, msg));
});
```

## Failure 2: Cross-Site WebSocket Hijacking (CSWSH)

Browsers automatically attach cookies to WebSocket handshakes — there is no same-origin restriction. A malicious page on `attacker.com` can open a WebSocket to `wss://yourapp.com/ws`, and the browser includes the victim's session cookies. This enabled a full account takeover at Gitpod (2023).

The `ws` Node.js library does **not** validate the `Origin` header by default.

```javascript
// BAD: no origin validation (ws library default)
const wss = new WebSocket.Server({ port: 8080 });

// GOOD: validate origin on every upgrade
const ALLOWED_ORIGINS = ['https://yourapp.com', 'https://app.yourapp.com'];

const server = http.createServer(app);
server.on('upgrade', (req, socket, head) => {
  const origin = req.headers.origin;
  if (!ALLOWED_ORIGINS.includes(origin)) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});
```

For development: also allowlist `http://localhost:3000` etc.

## Failure 3: Authentication ≠ Authorization Per Message

Verifying the user at connection time doesn't mean every message they send is authorized. A viewer-role user who authenticated can still send admin-action messages if the message handler doesn't check roles.

```javascript
// BAD: only checks connection-time auth
ws.on('message', (msg) => {
  const { action, payload } = JSON.parse(msg);
  if (action === 'delete-all-users') {
    deleteAllUsers(payload); // ws.user is a viewer
  }
});

// GOOD: check authorization per action
ws.on('message', (msg) => {
  const { action, payload } = JSON.parse(msg);

  if (action === 'delete-all-users') {
    if (ws.user.role !== 'admin') {
      ws.send(JSON.stringify({ error: 'Forbidden' }));
      return;
    }
    deleteAllUsers(payload);
  }
});
```

## Failure 4: Sessions Not Invalidated on Logout

WebSocket connections are persistent — they survive until explicitly closed. A user who logs out still has their WebSocket connection open. If you revoke a session (on logout, password change, or suspicious activity), you must also close all associated WebSocket connections.

```javascript
// On logout:
async function handleLogout(userId: string) {
  await revokeSession(userId);

  // Close all active WebSocket connections for this user
  for (const [client] of wss.clients) {
    if (client.userId === userId) {
      client.close(4002, 'Session revoked');
    }
  }
}
```

For distributed setups: publish the revocation event to Redis pub/sub so all server instances close the connection.

## Failure 5: No Connection Limits

Each persistent WebSocket connection consumes server memory and file descriptors. Without a per-user connection limit, an attacker can exhaust server resources.

```javascript
const userConnectionCounts = new Map<string, number>();
const MAX_CONNECTIONS_PER_USER = 5;

wss.on('connection', (ws, req) => {
  const userId = ws.user.id;
  const count = userConnectionCounts.get(userId) ?? 0;

  if (count >= MAX_CONNECTIONS_PER_USER) {
    ws.close(4003, 'Too many connections');
    return;
  }

  userConnectionCounts.set(userId, count + 1);
  ws.on('close', () => {
    const current = userConnectionCounts.get(userId) ?? 1;
    userConnectionCounts.set(userId, current - 1);
  });
});
```

## Failure 6: Input Validation on Messages

WebSocket messages arrive as raw strings or binary. Validate every message against a schema before processing — the same way you'd validate an API request body.

```javascript
import { z } from 'zod';

const MessageSchema = z.discriminatedUnion('action', [
  z.object({ action: z.literal('send-message'), text: z.string().max(1000) }),
  z.object({ action: z.literal('join-room'), roomId: z.string().cuid() }),
]);

ws.on('message', (raw) => {
  let parsed;
  try {
    parsed = MessageSchema.parse(JSON.parse(raw.toString()));
  } catch {
    ws.send(JSON.stringify({ error: 'Invalid message' }));
    return;
  }
  handleMessage(ws.user, parsed);
});
```

## Next.js / Vercel Limitation

Vercel's serverless functions do not support persistent WebSocket connections — each function invocation has a maximum execution time and cannot maintain state between requests. If your Next.js app needs WebSockets, use:
- A dedicated WebSocket server (separate Node.js process or service)
- Vercel's realtime service (Ably, Pusher, Liveblocks) via SSE or WebSocket proxying
- `@vercel/experimental-edge` with a stateful backend

AI assistants sometimes generate WebSocket handlers in Next.js API routes that will silently fail or behave incorrectly on Vercel.
