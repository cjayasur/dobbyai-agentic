# DobbyAI — Agentic Loop, MCP, and Agent Identity from Protocol Level

A from-scratch autonomous AI agent built **without** LangChain, LangGraph, or
any agent framework — the agentic loop, MCP transport, OAuth 2.1 authorization,
and a three-tier agent identity model implemented directly against the
protocols.

> Built to understand the trust and authorization layer that lets AI agents
> authenticate, get scoped authority, and act autonomously with an audit
> trail — not to wrap an SDK.

---

## Why this repo exists

Most "AI agents" are a prompt and a `while` loop around someone else's
framework. This is the opposite: every layer is implemented against the wire
protocol so the trust boundaries are explicit and auditable.

It demonstrates four things that matter for agent infrastructure:

1. **A real agentic loop** — `tool_use → execute → tool_result → repeat to
   end_turn`, with SSE streaming, JSON-RPC tool dispatch, context compaction,
   and persistent memory. TypeScript/Bun, zero framework dependencies.
2. **MCP from both sides** — custom MCP servers *and* an MCP client with
   transport handling (stdio + Streamable HTTP), capability discovery, and
   tool routing.
3. **OAuth 2.1 for agents** — both `client_credentials` (autonomous) and
   `authorization_code + PKCE` (human-delegated) flows, JWT (HMAC-SHA256),
   Resource Indicators (RFC 8707), scope-based per-tool authorization.
4. **A three-tier agent identity model** — delegated authority with ephemeral
   execution contexts: shared secret → signed JWT assertion → hardware-bound
   key (Apple Secure Enclave). Documented end-to-end in
   [`docs/security-curriculum.md`](docs/security-curriculum.md).

---

## Map to regulated / security-critical deployments

If you work where AI agents must authenticate, hold only scoped authority,
and leave an audit trail — finance, healthcare, government, any on-prem
regulated environment — the relevant pieces are:

| Concern | Where it lives | What it shows |
|---|---|---|
| **Delegated, ephemeral agent identity** | `docs/security-curriculum.md` (three-tier model) | root authority → delegated agent credential → ephemeral session — least-privilege by construction, so a compromised session never escalates to root |
| **Programmable governance / scoped authority** | `src/mcp-server-secure-demo.ts` | per-tool scope enforcement at the protocol level — an agent only gets the tools and parameters its grant allows |
| **Human-delegated vs autonomous auth** | `src/oauth-server-pkce.ts`, `src/oauth-server-demo.ts` | PKCE for human-delegated agents, `client_credentials` for autonomous ones — side by side |
| **Auditability** | `src/step10-full-agent.ts` | every tool call is logged before execution; the loop is designed so each action is traceable |
| **Tool-agnostic orchestration** | `src/step10-full-agent.ts` + MCP servers | the agent loop never changes when tools are added/removed — servers are swappable behind the MCP host |

---

## Repository tour

```
src/
  step10-full-agent.ts        The complete agentic loop. SSE streaming parser,
                              async JSON-RPC tool dispatch, context compaction,
                              persistent memory, permission tiers, multi-server
                              MCP orchestration. ~1,100 lines, zero frameworks.

  mcp-server-secure-demo.ts   MCP server behind OAuth 2.1 Bearer auth with
                              per-tool scope enforcement. "Programmable
                              governance" at the protocol level.
  mcp-client-secure-demo.ts   MCP client that performs the auth handshake,
                              caches/refreshes tokens, calls scoped tools.
  mcp-server-memory.ts        Persistent-memory MCP server (the agent's
                              institutional knowledge across sessions).

  oauth-server-pkce.ts        OAuth 2.1 authorization_code + PKCE server
                              (human-delegated agent authorization).
  oauth-client-pkce.ts        The browser/PKCE client flow end to end.
  oauth-server-demo.ts        OAuth 2.1 client_credentials server
                              (autonomous agent authorization).

docs/
  security-curriculum.md      ~3,000-line teaching curriculum: crypto
                              foundations → SSH → OAuth flows → MCP wire
                              protocol → rogue-server attacks & defenses →
                              the three-tier agent identity model.
```

Start with **`src/step10-full-agent.ts`** for the loop, then
**`docs/security-curriculum.md`** for the identity/authorization architecture.

---

## The agentic loop (the core idea)

```
user / task
   │
   ▼
LLM emits tool_use ──► agent executes via MCP ──► tool_result ──┐
   ▲                                                            │
   └────────────────────  repeat until end_turn  ◄──────────────┘
```

The LLM is the brain; the loop is the behavior; the MCP host is the
connection layer; MCP servers are the capabilities. These are **orthogonal
roles** — the loop is tool-agnostic, so servers can be added, removed, or
swapped (local Qwen, Llama, or a hosted model) without touching the agent.

---

## Running it

```bash
bun install
cp .env.example .env          # then set AGENT_API_URL + AGENT_API_KEY (see below)
bun run src/step10-full-agent.ts
```

The backend is pluggable — **any Anthropic-Messages-compatible endpoint**.
Two env vars select it; credentials are read from the environment, never
hardcoded:

| Var | Meaning |
|---|---|
| `AGENT_API_URL` | the `/v1/messages` endpoint (default: `https://api.anthropic.com/v1/messages`) |
| `AGENT_API_KEY` | the credential for that endpoint |

The in-code model name (`claude-sonnet-4-…`) is sent as-is; a translation
proxy remaps it to whatever local model it fronts, so the agent code never
changes between these modes.

### Three ways to run

**1. Hosted Claude (simplest).** Real Anthropic, your account is billed:

```bash
AGENT_API_URL=https://api.anthropic.com/v1/messages
AGENT_API_KEY=sk-ant-api03-…
```

**2. Local model via a translation proxy (zero external egress).** Point at a
self-hosted Anthropic↔OpenAI proxy in front of Qwen / Llama:

```bash
AGENT_API_URL=http://localhost:8082/v1/messages
AGENT_API_KEY=dk_…
```

**3. The full on-prem stack.** Pair with companion repo
[`dobbyai-proxy-extensions`](https://github.com/cjayasur/dobbyai-proxy-extensions)
— local `dk_*` token auth + vision routing on top of the open-source
`1rgs/claude-code-proxy`. End to end:

```
this agent (MCP tools, OAuth) ─► dobbyai-proxy-extensions  ─► your local
  AGENT_API_URL=…proxy/v1/messages   (dk_ auth, Anthropic↔OpenAI    Qwen/Llama
  AGENT_API_KEY=dk_…                  + tool-call translation)        (vLLM/llama.cpp)
```

Bring the proxy up per its README (mint a `dk_` with its `create_key.py`),
point `AGENT_API_URL` at it, and the entire loop — agent, MCP tools, auth,
inference — runs with **nothing leaving the perimeter**. The serving topology
(vLLM tensor-parallel on consumer GPUs; llama.cpp on a Blackwell
unified-memory box) is in
[`docs/on-prem-deployment.md`](docs/on-prem-deployment.md). Relevant for
regulated / sovereign deployments (finance, healthcare, government).

> ⚠️ This agent has filesystem tools and follows instructions literally — it
> will read and print a file you ask it to, `.env` included. Keep secrets out
> of files in its workspace; supply credentials via the environment.

---

## Design choices worth noting

- **No agent framework.** Building from primitives makes the trust boundaries
  explicit. You can see exactly where a token is checked, where a scope is
  enforced, where an action is logged — none of it is hidden in a dependency.
- **Auth is not bolted on.** The secure MCP server rejects calls without a
  valid Bearer token *and* checks scope per tool. An agent with a token for
  tool A cannot call tool B.
- **Identity is layered, not flat.** The three-tier model separates *who
  authorized this* (root) from *which agent is acting* (delegated) from *this
  specific run* (ephemeral) — so a compromised session never escalates to root
  authority.
- **The loop is auditable by construction.** Every tool invocation is recorded
  before it executes, with enough context to reconstruct why the agent did
  what it did.

---

## Status

This is a working reference implementation and an active teaching project, not
a productized SDK. It runs; it is single-tenant by design; the architecture is
built to scale out behind a proper supervisor and a hardened auth broker.

## License

MIT — see [LICENSE](LICENSE).
