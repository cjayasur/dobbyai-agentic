// OAuth 2.1 Server with Authorization Code + PKCE
//
// This demonstrates the BROWSER-BASED login flow:
//   1. Client opens browser → user sees login page
//   2. User types username + password → auth server validates
//   3. Auth server redirects browser to client's callback URL with auth_code
//   4. Client exchanges auth_code + code_verifier → gets JWT token
//
// The auth_code travels through the browser redirect (in the URL).
// PKCE ensures a stolen auth_code is USELESS without the code_verifier.
//
// Run: bun oauth:pkce-server
// Port: 3300
//
// Compare with oauth-server-demo.ts (client_credentials — no browser, no redirect)

import { createServer, type IncomingMessage, type ServerResponse } from "http";
import { createHmac, randomBytes } from "crypto";

const PORT = 3300;
const JWT_SECRET = "dobbyai-oauth-demo-secret-change-in-production";

// ─── Registered users (who can log in via browser) ─────────────

const USERS: Record<string, { password: string; name: string }> = {
  cj: { password: "dobby2026", name: "CJ Jayasuriya" },
  mike: { password: "research1", name: "Mike Jayasuriya" },
};

// ─── Registered clients (apps that can request tokens) ─────────

const CLIENTS: Record<string, { redirectUri: string; allowedScopes: string[]; name: string }> = {
  "dobbyai-web": {
    redirectUri: "http://localhost:3500/callback",
    allowedScopes: ["mcp:tools:read", "mcp:tools:write"],
    name: "DobbyAI Web Client",
  },
  "dobbyai-admin": {
    redirectUri: "http://localhost:3500/callback",
    allowedScopes: ["mcp:tools:read", "mcp:tools:write", "mcp:tools:admin"],
    name: "DobbyAI Admin Client",
  },
};

// ─── Pending authorization codes (short-lived, one-time use) ───

type PendingCode = {
  code: string;
  clientId: string;
  userId: string;
  scopes: string[];
  codeChallenge: string;
  codeChallengeMethod: string;
  redirectUri: string;
  createdAt: number;
};

const pendingCodes = new Map<string, PendingCode>();

// ─── JWT helpers (same as oauth-server-demo.ts) ────────────────

function base64url(str: string): string {
  return Buffer.from(str).toString("base64url");
}

function createJWT(payload: Record<string, any>): string {
  const header = { alg: "HS256", typ: "JWT" };
  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(payload));
  const signature = createHmac("sha256", JWT_SECRET)
    .update(`${headerB64}.${payloadB64}`)
    .digest("base64url");
  return `${headerB64}.${payloadB64}.${signature}`;
}

// ─── PKCE verification ─────────────────────────────────────────

function verifyPKCE(codeVerifier: string, codeChallenge: string, method: string): boolean {
  if (method === "S256") {
    const hash = createHmac("sha256", "")
      .update("")
      .digest();
    // S256: BASE64URL(SHA256(code_verifier)) === code_challenge
    const computed = require("crypto")
      .createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");
    return computed === codeChallenge;
  }
  // "plain" method (not recommended, but spec allows it)
  return codeVerifier === codeChallenge;
}

// ─── Request body parser ────────────────────────────────────────

async function parseBody(req: IncomingMessage): Promise<Record<string, string>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const body = Buffer.concat(chunks).toString();
  const params = new URLSearchParams(body);
  const obj: Record<string, string> = {};
  for (const [k, v] of params) obj[k] = v;
  return obj;
}

// ─── HTML login page ────────────────────────────────────────────

function loginPage(clientId: string, scope: string, state: string,
  codeChallenge: string, codeChallengeMethod: string, redirectUri: string,
  error?: string): string {
  const clientName = CLIENTS[clientId]?.name ?? clientId;
  return `<!DOCTYPE html>
<html>
<head>
  <title>DobbyAI OAuth Login</title>
  <style>
    body { font-family: Helvetica, Arial, sans-serif; background: #1a1a2e; color: #eee;
           display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
    .card { background: #16213e; padding: 40px; border-radius: 12px; width: 360px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
    h2 { margin-top: 0; color: #e94560; }
    .app { color: #0f3460; background: #e94560; padding: 4px 10px; border-radius: 4px;
           font-size: 13px; display: inline-block; margin-bottom: 16px; }
    label { display: block; margin-top: 12px; font-size: 14px; color: #aaa; }
    input { width: 100%; padding: 10px; margin-top: 4px; border: 1px solid #333;
            border-radius: 6px; background: #0f3460; color: #eee; font-size: 14px;
            box-sizing: border-box; }
    button { width: 100%; padding: 12px; margin-top: 20px; background: #e94560; color: #fff;
             border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
    button:hover { background: #c73650; }
    .error { color: #ff6b6b; font-size: 13px; margin-top: 8px; }
    .scopes { font-size: 12px; color: #888; margin-top: 8px; }
    .info { font-size: 11px; color: #555; margin-top: 16px; text-align: center; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Sign In</h2>
    <div class="app">${clientName} wants access</div>
    <div class="scopes">Scopes requested: ${scope}</div>
    ${error ? `<div class="error">${error}</div>` : ""}
    <form method="POST" action="/authorize">
      <input type="hidden" name="client_id" value="${clientId}">
      <input type="hidden" name="scope" value="${scope}">
      <input type="hidden" name="state" value="${state}">
      <input type="hidden" name="code_challenge" value="${codeChallenge}">
      <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}">
      <input type="hidden" name="redirect_uri" value="${redirectUri}">
      <label>Username</label>
      <input type="text" name="username" placeholder="cj" autofocus>
      <label>Password</label>
      <input type="password" name="password" placeholder="password">
      <button type="submit">Authorize</button>
    </form>
    <div class="info">This is a teaching demo — not a production auth server</div>
  </div>
</body>
</html>`;
}

// ─── HTTP server ────────────────────────────────────────────────

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url!, `http://localhost:${PORT}`);

  // OAuth metadata discovery (RFC 8414)
  if (url.pathname === "/.well-known/oauth-authorization-server" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      issuer: `http://localhost:${PORT}`,
      authorization_endpoint: `http://localhost:${PORT}/authorize`,
      token_endpoint: `http://localhost:${PORT}/token`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["mcp:tools:read", "mcp:tools:write", "mcp:tools:admin"],
      token_endpoint_auth_methods_supported: ["none"],
    }));
    return;
  }

  // ── GET /authorize → show login page ──
  if (url.pathname === "/authorize" && req.method === "GET") {
    const clientId = url.searchParams.get("client_id") ?? "";
    const scope = url.searchParams.get("scope") ?? "";
    const state = url.searchParams.get("state") ?? "";
    const codeChallenge = url.searchParams.get("code_challenge") ?? "";
    const codeChallengeMethod = url.searchParams.get("code_challenge_method") ?? "S256";
    const redirectUri = url.searchParams.get("redirect_uri") ?? "";

    if (!CLIENTS[clientId]) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end(`Unknown client: ${clientId}`);
      return;
    }

    console.log(`  🌐 Login page shown for: ${clientId} (scopes: ${scope})`);
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(loginPage(clientId, scope, state, codeChallenge, codeChallengeMethod, redirectUri));
    return;
  }

  // ── POST /authorize → validate login, issue auth_code, redirect ──
  if (url.pathname === "/authorize" && req.method === "POST") {
    const body = await parseBody(req);
    const { username, password, client_id, scope, state,
            code_challenge, code_challenge_method, redirect_uri } = body;

    // Validate user credentials
    const user = USERS[username];
    if (!user || user.password !== password) {
      console.log(`  🚫 Login failed: ${username}`);
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(loginPage(client_id, scope, state, code_challenge,
        code_challenge_method, redirect_uri, "Invalid username or password"));
      return;
    }

    // Validate client
    const client = CLIENTS[client_id];
    if (!client) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end(`Unknown client: ${client_id}`);
      return;
    }

    // Validate redirect_uri matches registered one
    if (redirect_uri !== client.redirectUri) {
      console.log(`  🚫 Redirect URI mismatch: ${redirect_uri} !== ${client.redirectUri}`);
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end(`Invalid redirect_uri`);
      return;
    }

    // Generate auth_code
    const code = randomBytes(32).toString("hex");
    const requestedScopes = (scope ?? "").split(" ").filter(Boolean);
    const grantedScopes = requestedScopes.filter(s => client.allowedScopes.includes(s));

    // Store pending code with PKCE challenge
    pendingCodes.set(code, {
      code,
      clientId: client_id,
      userId: username,
      scopes: grantedScopes.length > 0 ? grantedScopes : client.allowedScopes,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method ?? "S256",
      redirectUri: redirect_uri,
      createdAt: Date.now(),
    });

    // Auto-expire after 60 seconds
    setTimeout(() => pendingCodes.delete(code), 60000);

    console.log(`  ✅ Login OK: ${username} (${user.name})`);
    console.log(`  🔑 Auth code issued: ${code.slice(0, 16)}...`);
    console.log(`  ↩️  Redirecting to: ${redirect_uri}`);

    // THE REDIRECT — this is where the auth_code travels via URL
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set("code", code);
    if (state) redirectUrl.searchParams.set("state", state);

    res.writeHead(302, { Location: redirectUrl.toString() });
    res.end();
    return;
  }

  // ── POST /token → exchange auth_code + code_verifier for JWT ──
  if (url.pathname === "/token" && req.method === "POST") {
    const body = await parseBody(req);
    const { grant_type, code, code_verifier, redirect_uri, client_id } = body;

    if (grant_type !== "authorization_code") {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "unsupported_grant_type",
        error_description: "This server only supports authorization_code (use oauth-server-demo.ts for client_credentials)" }));
      return;
    }

    // Look up the pending auth code
    const pending = pendingCodes.get(code);
    if (!pending) {
      console.log(`  🚫 Invalid or expired auth code`);
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant", error_description: "Auth code invalid or expired" }));
      return;
    }

    // Verify redirect_uri matches
    if (redirect_uri !== pending.redirectUri) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant", error_description: "redirect_uri mismatch" }));
      return;
    }

    // ── PKCE VERIFICATION — the key security check ──
    if (!code_verifier) {
      console.log(`  🚫 Missing code_verifier (PKCE required)`);
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_request", error_description: "code_verifier required (PKCE)" }));
      return;
    }

    if (!verifyPKCE(code_verifier, pending.codeChallenge, pending.codeChallengeMethod)) {
      console.log(`  🚫 PKCE verification FAILED — code_verifier doesn't match code_challenge`);
      console.log(`     This means someone stole the auth_code but doesn't have the verifier!`);
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant",
        error_description: "PKCE verification failed — code_verifier doesn't match" }));
      return;
    }

    console.log(`  ✅ PKCE verified: code_verifier matches code_challenge`);

    // Delete the code (one-time use)
    pendingCodes.delete(code);

    // Issue JWT
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = 3600;

    const token = createJWT({
      iss: `http://localhost:${PORT}`,
      sub: pending.userId,
      aud: "http://localhost:3400",
      scope: pending.scopes.join(" "),
      iat: now,
      exp: now + expiresIn,
      jti: randomBytes(16).toString("hex"),
      client_id: pending.clientId,
      user_name: USERS[pending.userId]?.name,
    });

    console.log(`  🎫 JWT issued for: ${pending.userId} via ${pending.clientId}`);

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      access_token: token,
      token_type: "Bearer",
      expires_in: expiresIn,
      scope: pending.scopes.join(" "),
    }));
    return;
  }

  // Health check
  if (url.pathname === "/" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      name: "DobbyAI OAuth Server (PKCE + Auth Code)",
      status: "running",
      flow: "authorization_code with PKCE",
      users: Object.keys(USERS),
      clients: Object.keys(CLIENTS),
    }));
    return;
  }

  res.writeHead(404);
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log(`\n🔐 OAuth 2.1 Server (Authorization Code + PKCE)`);
  console.log(`   http://localhost:${PORT}`);
  console.log(`   Login:    GET  http://localhost:${PORT}/authorize?client_id=dobbyai-web&...`);
  console.log(`   Token:    POST http://localhost:${PORT}/token`);
  console.log(`   Metadata: http://localhost:${PORT}/.well-known/oauth-authorization-server`);
  console.log(`\n   Users: cj (dobby2026), mike (research1)`);
  console.log(`   Clients: dobbyai-web, dobbyai-admin`);
  console.log(`\n   Flow: Browser login → redirect with auth_code → exchange with PKCE → JWT`);
  console.log(`   This is the BROWSER flow. For autonomous agents, use oauth-server-demo.ts\n`);
});
