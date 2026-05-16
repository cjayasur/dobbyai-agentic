// Secure MCP Server Demo — requires OAuth Bearer token
//
// Same as mcp-server-http.ts (math server) but with authentication.
// Rejects connections without a valid JWT token.
// Validates: token signature, expiration, audience, scopes.
//
// Run: bun mcp:secure-server
// Port: 3400
// Requires: bun oauth:server running on port 3300
//
// This demonstrates the MCP spec's authorization flow:
//   1. Client connects → server returns 401
//   2. Client discovers OAuth metadata
//   3. Client gets token from auth server
//   4. Client retries with Bearer token → 200 OK

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { createServer, type IncomingMessage, type ServerResponse } from "http";
import { createHmac } from "crypto";

const PORT = 3400;
const OAUTH_SERVER = "http://localhost:3300";
const JWT_SECRET = "dobbyai-oauth-demo-secret-change-in-production";

// ─── JWT validation ─────────────────────────────────────────────

function verifyJWT(token: string): Record<string, any> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, signature] = parts;
  const expected = createHmac("sha256", JWT_SECRET)
    .update(`${headerB64}.${payloadB64}`)
    .digest("base64url");
  if (signature !== expected) return null;
  try {
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    if (payload.aud && payload.aud !== `http://localhost:${PORT}`) return null;
    return payload;
  } catch {
    return null;
  }
}

function hasScope(payload: Record<string, any>, required: string): boolean {
  const scopes = (payload.scope ?? "").split(" ");
  return scopes.includes(required);
}

// ─── MCP Server ─────────────────────────────────────────────────

const TOOL_SCOPES: Record<string, string> = {
  add: "mcp:tools:read",
  multiply: "mcp:tools:read",
  get_secret_data: "mcp:tools:admin",
};

function createMCPServer(authPayload: Record<string, any>): Server {
  const server = new Server(
    { name: "secure-math-server", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "add",
        description: "Add two numbers (requires mcp:tools:read scope)",
        inputSchema: {
          type: "object",
          properties: {
            a: { type: "number" }, b: { type: "number" },
          },
          required: ["a", "b"],
        },
      },
      {
        name: "multiply",
        description: "Multiply two numbers (requires mcp:tools:read scope)",
        inputSchema: {
          type: "object",
          properties: {
            a: { type: "number" }, b: { type: "number" },
          },
          required: ["a", "b"],
        },
      },
      {
        name: "get_secret_data",
        description: "Returns sensitive data (requires mcp:tools:admin scope)",
        inputSchema: { type: "object", properties: {} },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    const requiredScope = TOOL_SCOPES[name];
    if (requiredScope && !hasScope(authPayload, requiredScope)) {
      console.log(`  🚫 Scope denied: ${name} requires ${requiredScope}, agent has: ${authPayload.scope}`);
      return {
        content: [{ type: "text", text: `Access denied: tool "${name}" requires scope "${requiredScope}". Your token has: ${authPayload.scope}` }],
        isError: true,
      };
    }

    switch (name) {
      case "add":
        return { content: [{ type: "text", text: String(args!.a + args!.b) }] };
      case "multiply":
        return { content: [{ type: "text", text: String(args!.a * args!.b) }] };
      case "get_secret_data":
        return { content: [{ type: "text", text: "SECRET: The vault code is 42-17-93. This required admin scope to access." }] };
      default:
        return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
    }
  });

  return server;
}

// ─── Per-session auth context ───────────────────────────────────

const sessionAuth = new Map<string, Record<string, any>>();

// ─── HTTP server with auth ──────────────────────────────────────

const transports = new Map<string, { transport: StreamableHTTPServerTransport; server: Server }>();

const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url!, `http://localhost:${PORT}`);

  // OAuth resource metadata (RFC 9728)
  if (url.pathname === "/.well-known/oauth-protected-resource" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      resource: `http://localhost:${PORT}`,
      authorization_servers: [OAUTH_SERVER],
      scopes_supported: ["mcp:tools:read", "mcp:tools:write", "mcp:tools:admin"],
      bearer_methods_supported: ["header"],
    }));
    return;
  }

  if (url.pathname === "/mcp") {
    // ── AUTHENTICATION CHECK ──
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      console.log(`  🚫 401 — No Bearer token`);
      res.writeHead(401, {
        "Content-Type": "application/json",
        "WWW-Authenticate": `Bearer resource_metadata="http://localhost:${PORT}/.well-known/oauth-protected-resource"`,
      });
      res.end(JSON.stringify({ error: "unauthorized", message: "Bearer token required" }));
      return;
    }

    const token = authHeader.slice(7);
    const payload = verifyJWT(token);
    if (!payload) {
      console.log(`  🚫 401 — Invalid or expired token`);
      res.writeHead(401, {
        "Content-Type": "application/json",
        "WWW-Authenticate": `Bearer error="invalid_token" error_description="Token invalid or expired"`,
      });
      res.end(JSON.stringify({ error: "invalid_token", message: "Token invalid or expired" }));
      return;
    }

    console.log(`  ✅ Authenticated: ${payload.sub} (scopes: ${payload.scope})`);

    // ── MCP HANDLING (same as mcp-server-http.ts) ──
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    if (req.method === "POST") {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const body = JSON.parse(Buffer.concat(chunks).toString());

      if (!sessionId) {
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => crypto.randomUUID(),
          onsessioninitialized: (id) => {
            transports.set(id, { transport, server: mcpServer });
            console.log(`  📡 Session: ${id.slice(0, 8)}... (agent: ${payload.sub})`);
          },
        });
        const mcpServer = createMCPServer(payload);
        transport.onclose = () => {
          if (transport.sessionId) transports.delete(transport.sessionId);
        };
        await mcpServer.connect(transport);
        await transport.handleRequest(req, res, body);
      } else {
        const entry = transports.get(sessionId);
        if (entry) {
          await entry.transport.handleRequest(req, res, body);
        } else {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Unknown session" }));
        }
      }
    } else if (req.method === "GET") {
      const entry = sessionId ? transports.get(sessionId) : undefined;
      if (entry) await entry.transport.handleRequest(req, res);
      else { res.writeHead(400); res.end("Unknown session"); }
    } else if (req.method === "DELETE") {
      const entry = sessionId ? transports.get(sessionId) : undefined;
      if (entry) await entry.transport.handleRequest(req, res);
      else { res.writeHead(200); res.end(); }
    } else {
      res.writeHead(405); res.end("Method not allowed");
    }
    return;
  }

  if (url.pathname === "/" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      name: "Secure MCP Math Server",
      auth: "OAuth 2.1 Bearer token required",
      metadata: `http://localhost:${PORT}/.well-known/oauth-protected-resource`,
    }));
    return;
  }

  res.writeHead(404); res.end("Not found");
});

httpServer.listen(PORT, () => {
  console.log(`\n🔒 Secure MCP Math Server (OAuth 2.1 Required)`);
  console.log(`   http://localhost:${PORT}/mcp`);
  console.log(`   Auth metadata: http://localhost:${PORT}/.well-known/oauth-protected-resource`);
  console.log(`   OAuth server:  ${OAUTH_SERVER}`);
  console.log(`\n   Tools: add, multiply, get_secret_data`);
  console.log(`   Scopes: mcp:tools:read (math), mcp:tools:admin (secrets)`);
  console.log(`\n   Try without token → 401 Unauthorized`);
  console.log(`   Try with token → tools work\n`);
});
