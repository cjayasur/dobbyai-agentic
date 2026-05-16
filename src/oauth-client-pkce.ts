// OAuth 2.1 Client with Authorization Code + PKCE
//
// Demonstrates the BROWSER-BASED login flow from the CLIENT side:
//   1. Generate code_verifier (random secret) and code_challenge (hash of it)
//   2. Open browser → auth server login page (sends code_challenge)
//   3. User logs in → auth server redirects to our callback with auth_code
//   4. Exchange auth_code + code_verifier → get JWT token
//   5. Use token to call secure MCP server
//
// The code_verifier NEVER leaves this process.
// The code_challenge goes to the auth server (it's a hash — can't reverse it).
// Even if someone steals the auth_code from the redirect URL → useless without verifier.
//
// Run: bun oauth:pkce-client
// Port: 3500 (callback listener)
// Requires:
//   bun oauth:pkce-server     (port 3300)
//   bun mcp:secure-server     (port 3400)

import { createServer, type IncomingMessage, type ServerResponse } from "http";
import { randomBytes, createHash } from "crypto";
import { exec } from "child_process";

const CALLBACK_PORT = 3500;
const AUTH_SERVER = "http://localhost:3300";
const MCP_SERVER = "http://localhost:3400/mcp";
const CLIENT_ID = "dobbyai-web";
const REQUESTED_SCOPES = "mcp:tools:read mcp:tools:write";

// ─── PKCE: Generate code_verifier and code_challenge ────────────
//
// code_verifier:  random 43-128 character string (kept SECRET by client)
// code_challenge: SHA-256 hash of verifier, base64url encoded (sent to auth server)
//
// The auth server stores the challenge.
// When we exchange the code, we send the VERIFIER.
// Auth server hashes our verifier and compares to the stored challenge.
// If they match → we're the same client that started the flow.

function generatePKCE(): { codeVerifier: string; codeChallenge: string } {
  // 32 random bytes → 43 base64url characters
  const codeVerifier = randomBytes(32).toString("base64url");

  // SHA-256 hash → base64url encode
  const codeChallenge = createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");

  return { codeVerifier, codeChallenge };
}

// ─── State parameter (CSRF protection) ─────────────────────────
// Random value we send to auth server, they send back in the redirect.
// If it doesn't match → someone is trying to inject a forged redirect.

const state = randomBytes(16).toString("hex");

// ─── Generate PKCE pair ─────────────────────────────────────────

const { codeVerifier, codeChallenge } = generatePKCE();

// ─── MCP request helper ─────────────────────────────────────────

let sessionId: string | null = null;
let requestId = 1;

async function mcpRequest(method: string, params?: any, token?: string, isNotification = false): Promise<any> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (sessionId) headers["mcp-session-id"] = sessionId;

  const body: any = { jsonrpc: "2.0", method, params: params ?? {} };
  if (!isNotification) body.id = requestId++;

  const res = await fetch(MCP_SERVER, { method: "POST", headers, body: JSON.stringify(body) });

  const newSessionId = res.headers.get("mcp-session-id");
  if (newSessionId) sessionId = newSessionId;

  const contentType = res.headers.get("content-type") ?? "";
  let data: any = null;
  if (contentType.includes("text/event-stream")) {
    const text = await res.text();
    const dataLines = text.split("\n").filter(l => l.startsWith("data: "));
    for (const line of dataLines) {
      try { data = JSON.parse(line.slice(6)); } catch {}
    }
  } else {
    data = await res.json().catch(() => null);
  }
  return { status: res.status, data };
}

// ─── Main flow ──────────────────────────────────────────────────

async function main() {
  console.log("🔐 OAuth 2.1 Client — Authorization Code + PKCE\n");
  console.log("═══════════════════════════════════════════════════════\n");

  // ── Step 1: Generate PKCE pair ──
  console.log("  1️⃣  Generated PKCE pair:");
  console.log(`     code_verifier:  ${codeVerifier.slice(0, 20)}... (${codeVerifier.length} chars, KEPT SECRET)`);
  console.log(`     code_challenge: ${codeChallenge.slice(0, 20)}... (SHA-256 hash, sent to server)`);
  console.log(`     state:          ${state.slice(0, 16)}... (CSRF protection)`);

  // ── Step 2: Start callback server to catch the redirect ──
  console.log("\n  2️⃣  Starting callback listener on port 3500...");

  const authCodePromise = new Promise<string>((resolve, reject) => {
    const callbackServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url!, `http://localhost:${CALLBACK_PORT}`);

      if (url.pathname === "/callback") {
        const code = url.searchParams.get("code");
        const returnedState = url.searchParams.get("state");

        console.log(`\n  4️⃣  Callback received!`);
        console.log(`     auth_code: ${code?.slice(0, 16)}... (from redirect URL)`);
        console.log(`     state:     ${returnedState?.slice(0, 16)}...`);

        // Verify state (CSRF check)
        if (returnedState !== state) {
          console.log(`     🚫 STATE MISMATCH — possible CSRF attack!`);
          res.writeHead(400, { "Content-Type": "text/html" });
          res.end("<h1>Error: State mismatch (possible CSRF attack)</h1>");
          reject(new Error("State mismatch"));
          return;
        }
        console.log(`     ✅ State matches — not a CSRF attack`);

        if (!code) {
          res.writeHead(400, { "Content-Type": "text/html" });
          res.end("<h1>Error: No auth code received</h1>");
          reject(new Error("No auth code"));
          return;
        }

        // Show success page in browser
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(`<!DOCTYPE html><html><head><title>Authorized</title>
          <style>body{font-family:Helvetica,Arial,sans-serif;background:#1a1a2e;color:#eee;
          display:flex;justify-content:center;align-items:center;height:100vh;margin:0;text-align:center;}
          h1{color:#4ecdc4;} p{color:#888;}</style></head>
          <body><div><h1>Authorized!</h1>
          <p>Auth code received. You can close this tab.</p>
          <p style="font-size:12px;color:#555;">code: ${code.slice(0, 16)}...</p></div></body></html>`);

        // Close the callback server
        callbackServer.close();
        resolve(code);
      }
    });

    callbackServer.listen(CALLBACK_PORT, () => {
      console.log(`     Listening on http://localhost:${CALLBACK_PORT}/callback`);
    });

    // Timeout after 2 minutes
    setTimeout(() => {
      callbackServer.close();
      reject(new Error("Timeout waiting for callback"));
    }, 120000);
  });

  // ── Step 3: Open browser to auth server login page ──
  const authUrl = new URL(`${AUTH_SERVER}/authorize`);
  authUrl.searchParams.set("client_id", CLIENT_ID);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", REQUESTED_SCOPES);
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("redirect_uri", `http://localhost:${CALLBACK_PORT}/callback`);

  console.log(`\n  3️⃣  Opening browser for login...`);
  console.log(`     URL: ${authUrl.toString().slice(0, 80)}...`);
  console.log(`\n     ⏳ Waiting for you to log in (username: cj, password: dobby2026)...\n`);

  // Open the browser (macOS)
  exec(`open "${authUrl.toString()}"`);

  // ── Step 4: Wait for the callback with auth_code ──
  let authCode: string;
  try {
    authCode = await authCodePromise;
  } catch (err: any) {
    console.log(`\n  ❌ ${err.message}`);
    process.exit(1);
  }

  // ── Step 5: Exchange auth_code + code_verifier for token ──
  console.log(`\n  5️⃣  Exchanging auth_code for token (with PKCE)...`);
  console.log(`     POST ${AUTH_SERVER}/token`);
  console.log(`     grant_type:    authorization_code`);
  console.log(`     code:          ${authCode.slice(0, 16)}... (from redirect)`);
  console.log(`     code_verifier: ${codeVerifier.slice(0, 20)}... (our SECRET — proves we started the flow)`);
  console.log(`     redirect_uri:  http://localhost:${CALLBACK_PORT}/callback`);

  const tokenRes = await fetch(`${AUTH_SERVER}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: authCode,
      code_verifier: codeVerifier,
      redirect_uri: `http://localhost:${CALLBACK_PORT}/callback`,
      client_id: CLIENT_ID,
    }).toString(),
  });

  if (!tokenRes.ok) {
    const err = await tokenRes.json();
    console.log(`     ❌ Token exchange failed: ${err.error} — ${err.error_description}`);
    process.exit(1);
  }

  const tokenData = await tokenRes.json();
  console.log(`\n     ✅ Token received!`);
  console.log(`     Type:    ${tokenData.token_type}`);
  console.log(`     Scopes:  ${tokenData.scope}`);
  console.log(`     Expires: ${tokenData.expires_in}s`);
  console.log(`     Token:   ${tokenData.access_token.slice(0, 50)}...`);

  // ── Step 6: Use token to call secure MCP server ──
  console.log(`\n  6️⃣  Calling secure MCP server with token...`);

  // Initialize
  const initRes = await mcpRequest("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "dobbyai-pkce-client", version: "1.0.0" },
  }, tokenData.access_token);

  if (initRes.status === 200) {
    console.log(`     ✅ Connected to MCP server (session: ${sessionId?.slice(0, 8)}...)`);
    await mcpRequest("notifications/initialized", {}, tokenData.access_token, true);

    // List tools
    const toolsRes = await mcpRequest("tools/list", {}, tokenData.access_token);
    const tools = toolsRes.data?.result?.tools ?? [];
    for (const t of tools) {
      console.log(`     🔧 ${t.name}: ${t.description}`);
    }

    // Call add
    console.log(`\n     ── add(10, 32) ──`);
    const addRes = await mcpRequest("tools/call", { name: "add", arguments: { a: 10, b: 32 } }, tokenData.access_token);
    console.log(`     Result: ${addRes.data?.result?.content?.[0]?.text}`);

    // Call multiply
    console.log(`\n     ── multiply(7, 6) ──`);
    const mulRes = await mcpRequest("tools/call", { name: "multiply", arguments: { a: 7, b: 6 } }, tokenData.access_token);
    console.log(`     Result: ${mulRes.data?.result?.content?.[0]?.text}`);
  } else {
    console.log(`     ❌ MCP connection failed: ${initRes.status}`);
  }

  // ── Summary ──
  console.log("\n\n  ═══════════════════════════════════════════════════════");
  console.log("  AUTHORIZATION CODE + PKCE FLOW SUMMARY:");
  console.log("  ═══════════════════════════════════════════════════════");
  console.log("");
  console.log("  1. Generated PKCE pair (verifier=secret, challenge=hash)");
  console.log("  2. Opened browser → auth server login page");
  console.log("  3. User logged in → auth server redirected with auth_code");
  console.log("  4. Caught callback → verified state (CSRF check)");
  console.log("  5. Exchanged auth_code + code_verifier → got JWT token");
  console.log("  6. Used token to call secure MCP server → tools worked!");
  console.log("");
  console.log("  WHY PKCE MATTERS:");
  console.log("  The auth_code was in the redirect URL (visible to browser,");
  console.log("  extensions, history, logs). But WITHOUT the code_verifier,");
  console.log("  that stolen code is USELESS — the token exchange would fail.");
  console.log("");
  console.log("  COMPARE WITH client_credentials (bun mcp:secure-client):");
  console.log("  No browser, no redirect, no PKCE needed.");
  console.log("  Agent authenticates directly with client_id + client_secret.");
  console.log("  Use client_credentials for autonomous agents.");
  console.log("  Use auth_code + PKCE when a HUMAN needs to log in.");
  console.log("  ═══════════════════════════════════════════════════════\n");

  process.exit(0);
}

main().catch(err => {
  console.error("Error:", err);
  process.exit(1);
});
