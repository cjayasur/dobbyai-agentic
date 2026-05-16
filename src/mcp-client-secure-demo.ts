// Secure MCP Client Demo — handles OAuth 2.1 authentication
//
// Connects to a secure MCP server that requires Bearer tokens.
// Demonstrates the full flow:
//   1. Try to connect → get 401
//   2. Discover OAuth metadata from server
//   3. Discover auth server metadata
//   4. Get token via client_credentials grant
//   5. Retry with Bearer token → success
//   6. Call tools with token
//   7. Handle token expiration (re-auth)
//
// Run: bun mcp:secure-client
// Requires:
//   bun oauth:server        (port 3300)
//   bun mcp:secure-server   (port 3400)

const SECURE_MCP_URL = "http://localhost:3400/mcp";
const CLIENT_ID = "dobbyai-agent-001";
const CLIENT_SECRET = "agent001-secret-key";
const REQUESTED_SCOPES = "mcp:tools:read mcp:tools:write";

// ─── OAuth helper ───────────────────────────────────────────────

type TokenInfo = {
  accessToken: string;
  expiresAt: number;
  scope: string;
};

let cachedToken: TokenInfo | null = null;

async function discoverResourceMetadata(metadataUrl: string): Promise<any> {
  console.log(`\n  2️⃣  Discovering resource metadata...`);
  console.log(`     GET ${metadataUrl}`);
  const res = await fetch(metadataUrl);
  const data = await res.json();
  console.log(`     Resource: ${data.resource}`);
  console.log(`     Auth servers: ${data.authorization_servers?.join(", ")}`);
  console.log(`     Scopes: ${data.scopes_supported?.join(", ")}`);
  return data;
}

async function discoverAuthServerMetadata(authServerUrl: string): Promise<any> {
  console.log(`\n  3️⃣  Discovering auth server metadata...`);
  const metadataUrl = `${authServerUrl}/.well-known/oauth-authorization-server`;
  console.log(`     GET ${metadataUrl}`);
  const res = await fetch(metadataUrl);
  const data = await res.json();
  console.log(`     Issuer: ${data.issuer}`);
  console.log(`     Token endpoint: ${data.token_endpoint}`);
  console.log(`     Grant types: ${data.grant_types_supported?.join(", ")}`);
  return data;
}

async function getToken(tokenEndpoint: string, resource: string): Promise<TokenInfo> {
  // Check cache first
  if (cachedToken && Date.now() < cachedToken.expiresAt - 60000) {
    console.log(`\n  4️⃣  Using cached token (expires in ${Math.round((cachedToken.expiresAt - Date.now()) / 1000)}s)`);
    return cachedToken;
  }

  console.log(`\n  4️⃣  Requesting token (client_credentials)...`);
  console.log(`     POST ${tokenEndpoint}`);
  console.log(`     client_id: ${CLIENT_ID}`);
  console.log(`     scopes: ${REQUESTED_SCOPES}`);
  console.log(`     resource: ${resource} (Resource Indicator — RFC 8707)`);

  const res = await fetch(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      scope: REQUESTED_SCOPES,
      resource: resource,
    }).toString(),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(`Token request failed: ${err.error} — ${err.error_description}`);
  }

  const data = await res.json();
  cachedToken = {
    accessToken: data.access_token,
    expiresAt: Date.now() + data.expires_in * 1000,
    scope: data.scope,
  };

  console.log(`     ✅ Token received!`);
  console.log(`     Type: ${data.token_type}`);
  console.log(`     Scopes: ${data.scope}`);
  console.log(`     Expires in: ${data.expires_in}s`);
  console.log(`     Token (first 50 chars): ${data.access_token.slice(0, 50)}...`);

  return cachedToken;
}

// ─── MCP client with auth ───────────────────────────────────────

let sessionId: string | null = null;
let requestId = 1;

async function mcpRequest(method: string, params?: any, token?: string, isNotification = false): Promise<any> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (sessionId) headers["mcp-session-id"] = sessionId;

  const body: any = {
    jsonrpc: "2.0",
    method,
    params: params ?? {},
  };
  if (!isNotification) body.id = requestId++;

  const res = await fetch(SECURE_MCP_URL, { method: "POST", headers, body: JSON.stringify(body) });

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

  return { status: res.status, headers: res.headers, data, raw: res };
}

// ─── Main demo ──────────────────────────────────────────────────

async function main() {
  console.log("🔒 Secure MCP Client Demo — OAuth 2.1 Authentication\n");
  console.log("═══════════════════════════════════════════════════════\n");

  // ── Step 1: Try to connect WITHOUT a token ──
  console.log("  1️⃣  Connecting WITHOUT token (expect 401)...");
  console.log(`     POST ${SECURE_MCP_URL}`);

  const noAuthResponse = await mcpRequest("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "dobbyai-secure-client", version: "1.0.0" },
  });

  console.log(`     Response: ${noAuthResponse.status}`);

  if (noAuthResponse.status === 401) {
    const wwwAuth = noAuthResponse.raw.headers.get("www-authenticate");
    console.log(`     WWW-Authenticate: ${wwwAuth}`);
    console.log(`     ✅ Got 401 — server requires authentication (expected!)`);

    // Extract resource metadata URL from WWW-Authenticate header
    const metadataMatch = wwwAuth?.match(/resource_metadata="([^"]+)"/);
    if (!metadataMatch) throw new Error("No resource_metadata in WWW-Authenticate header");
    const resourceMetadataUrl = metadataMatch[1];

    // ── Step 2: Discover resource metadata ──
    const resourceMeta = await discoverResourceMetadata(resourceMetadataUrl);

    // ── Step 3: Discover auth server metadata ──
    const authServerUrl = resourceMeta.authorization_servers[0];
    const authMeta = await discoverAuthServerMetadata(authServerUrl);

    // ── Step 4: Get a token ──
    const tokenInfo = await getToken(authMeta.token_endpoint, resourceMeta.resource);

    // ── Step 5: Retry with token ──
    console.log(`\n  5️⃣  Retrying with Bearer token...`);
    console.log(`     POST ${SECURE_MCP_URL}`);
    console.log(`     Authorization: Bearer ${tokenInfo.accessToken.slice(0, 30)}...`);

    const authResponse = await mcpRequest("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "dobbyai-secure-client", version: "1.0.0" },
    }, tokenInfo.accessToken);

    console.log(`     Response: ${authResponse.status}`);

    if (authResponse.status === 200) {
      console.log(`     ✅ AUTHENTICATED! Connected to secure MCP server.`);
      const serverInfo = authResponse.data?.result?.serverInfo;
      if (serverInfo) console.log(`     Server: ${serverInfo.name} v${serverInfo.version}`);
      if (sessionId) console.log(`     Session: ${sessionId.slice(0, 8)}...`);

      // Send initialized notification (required by MCP protocol)
      console.log(`\n     Sending initialized notification...`);
      await mcpRequest("notifications/initialized", {}, tokenInfo.accessToken, true);
      console.log(`     ✅ Server knows we're ready.`);
    } else {
      console.log(`     ❌ Still failed: ${JSON.stringify(authResponse.data)}`);
      return;
    }

    // ── Step 6: Call tools with token ──
    console.log(`\n  6️⃣  Calling tools (authenticated)...\n`);

    // tools/list
    console.log("     ── tools/list ──");
    const toolsRes = await mcpRequest("tools/list", {}, tokenInfo.accessToken);
    const tools = toolsRes.data?.result?.tools ?? [];
    for (const t of tools) {
      console.log(`     📧 ${t.name}: ${t.description}`);
    }

    // tools/call — add
    console.log("\n     ── tools/call: add(10, 32) ──");
    const addRes = await mcpRequest("tools/call", {
      name: "add", arguments: { a: 10, b: 32 },
    }, tokenInfo.accessToken);
    console.log(`     Result: ${addRes.data?.result?.content?.[0]?.text ?? JSON.stringify(addRes.data)}`);

    // tools/call — multiply
    console.log("\n     ── tools/call: multiply(7, 6) ──");
    const mulRes = await mcpRequest("tools/call", {
      name: "multiply", arguments: { a: 7, b: 6 },
    }, tokenInfo.accessToken);
    console.log(`     Result: ${mulRes.data?.result?.content?.[0]?.text ?? JSON.stringify(mulRes.data)}`);

    // tools/call — get_secret_data (requires admin scope — we don't have it!)
    console.log("\n     ── tools/call: get_secret_data (might be denied by scope) ──");
    const secretRes = await mcpRequest("tools/call", {
      name: "get_secret_data", arguments: {},
    }, tokenInfo.accessToken);
    console.log(`     Result: ${secretRes.data?.result?.content?.[0]?.text ?? JSON.stringify(secretRes.data)}`);

    // ── Step 7: Summary ──
    console.log("\n\n  ═══════════════════════════════════════════════════════");
    console.log("  SECURE MCP FLOW SUMMARY:");
    console.log("  ═══════════════════════════════════════════════════════");
    console.log("");
    console.log("  1. Connected without token     → 401 Unauthorized");
    console.log("  2. Discovered resource metadata → found auth server");
    console.log("  3. Discovered auth server       → found token endpoint");
    console.log("  4. Got token (client_credentials) → JWT with scopes");
    console.log("  5. Retried with Bearer token   → 200 OK, connected!");
    console.log("  6. Called tools with token      → results returned");
    console.log("");
    console.log("  Token is scoped to THIS server (Resource Indicator).");
    console.log("  Token expires in 1 hour (short-lived).");
    console.log("  If stolen, damage is limited + scoped.");
    console.log("  Server can revoke at any time.");
    console.log("");
    console.log("  THIS is what MCP spec 2025-11-25 prescribes.");
    console.log("  Same flow works with Keycloak, Auth0, or any OAuth 2.1 server.");
    console.log("  ═══════════════════════════════════════════════════════\n");

  } else if (noAuthResponse.status === 200) {
    console.log("     ⚠️  Server didn't require auth — connected without token");
    console.log("     This server has no authentication. See mcp-server-secure-demo.ts for secured version.");
  } else {
    console.log(`     ❌ Unexpected response: ${noAuthResponse.status}`);
    console.log(`     ${JSON.stringify(noAuthResponse.data)}`);
  }
}

main().catch(err => {
  console.error("Error:", err);
  process.exit(1);
});
