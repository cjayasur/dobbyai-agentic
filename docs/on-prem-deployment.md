# On-Prem Deployment — Closing the Loop

This document shows how the agent runs **fully on-premises with zero external
API egress** — the serving layer that makes "no Anthropic, no OpenAI, no
cloud" a documented topology rather than a claim.

It completes the circle:

```
┌──────────────┐   Anthropic     ┌──────────────────┐   OpenAI      ┌────────────────────┐
│  DobbyAI     │   Messages API  │  Translation     │   /v1/chat    │  Local LLM serving │
│  agent loop  │ ───────────────►│  proxy           │ ─────────────►│  (vLLM or          │
│  (this repo) │                 │  (Anthropic↔     │               │   llama.cpp)       │
│              │ ◄───────────────│   OpenAI)        │ ◄─────────────│                    │
└──────────────┘   SSE stream    └──────────────────┘   SSE stream  └────────────────────┘
                                  proxy-extensions repo              this document
   nothing in this loop leaves the network perimeter — ever
```

- **Agent loop** → `cjayasur/dobbyai-agentic` (this repo)
- **Translation proxy** → `cjayasur/dobbyai-proxy-extensions` (auth + vision routing on top of the open-source `1rgs/claude-code-proxy`)
- **Serving layer** → documented below

The agent speaks the Anthropic Messages API. The proxy translates to/from the
OpenAI chat-completions shape. Behind the proxy is a local open-weight model.
**Switching backends is one environment variable** — the agent never changes.

---

## Two serving paths, same model, same API

The same model (`Qwen3.6-27B`) is served two ways depending on the hardware in
the rack. Both expose an OpenAI-compatible endpoint the proxy can target.

### Path A — vLLM on 2× consumer GPUs (tensor-parallel)

For a workstation with two 24 GB consumer GPUs (e.g. RTX 3090-class), vLLM
splits the model across both cards with tensor parallelism:

```bash
vllm serve <org>/Qwen3.6-27B-AWQ-INT4 \
  --enable-auto-tool-choice \
  --tool-call-parser qwen3_coder \
  --reasoning-parser qwen3 \
  --port 8013 \
  --max-model-len 131072 \
  --tensor-parallel-size 2 \
  --gpu-memory-utilization 0.92 \
  --enforce-eager
```

Why these flags:

| Flag | Why |
|---|---|
| `AWQ-INT4` weights | 4-bit activation-aware quantization — fits a 27B dense model into 2×24 GB with room for a 131K KV cache |
| `--tensor-parallel-size 2` | Splits every layer across both GPUs; ~doubles effective memory bandwidth (the real bottleneck for token generation) |
| `--tool-call-parser qwen3_coder` | Parses the model's native tool-call format so the agent's JSON-RPC dispatch works without glue |
| `--reasoning-parser qwen3` | Separates chain-of-thought from the final answer (preserve-thinking for agentic tasks) |
| `--max-model-len 131072` | 131K context — long agent transcripts + multi-file tool results |
| `--enforce-eager` | Disables CUDA-graph capture; slower but avoids capture-time instability on mixed consumer GPUs |

Observed single-stream throughput: **~8 tok/s** on a 27B dense model at INT4
across 2× RTX 3090. Bandwidth-bound, not compute-bound — that number is a
direct function of aggregate GPU memory bandwidth.

### Path B — llama.cpp on a single Blackwell unified-memory box

For a single NVIDIA GB10 Blackwell unit (128 GB LPDDR5x **unified** memory),
the model runs whole on one device — no tensor-parallel split, no inter-GPU
communication tax:

```bash
# Build once, with CUDA:
cmake -B build -DGGML_CUDA=ON -DLLAMA_BUILD_WEBUI=OFF
cmake --build build --config Release -j "$(nproc)"

# Serve (OpenAI-compatible, tool calling via jinja template):
./build/bin/llama-server \
  -m models/Qwen3.6-27B-Q4_K_M.gguf \
  --host 0.0.0.0 --port 8080 \
  --ctx-size 131072 \
  --n-gpu-layers 99 \
  --jinja \
  --metrics \
  --alias Qwen3.6-27B
```

Why this path matters:

- **Unified memory changes the calculus.** Two 24 GB cards give 48 GB total
  but split, with a communication tax and a hard ceiling. One 128 GB unified
  device fits models a dual-24 GB box physically cannot (70B+), with no split.
- **GGUF Q4_K_M** is the speed/quality sweet spot — ~2–3 % benchmark delta vs
  Q8, unmeasurable for tool-calling, ~40 % less data moved per token.
- Observed throughput: **~7.5 tok/s at Q8**, **~11 tok/s at Q4_K_M** on the
  GB10 — single device matching the dual-3090 workstation at a fraction of the
  power draw and physical footprint, with headroom for far larger models.

---

## The switch is one variable

The agent (`src/step10-full-agent.ts`) reads its backend from the environment:

```bash
# Point at the proxy; the proxy points at whichever serving path is live.
AGENT_API_URL=https://your-proxy-host/v1/messages
AGENT_API_KEY=dk_xxx        # validated locally by the proxy's auth middleware
```

The proxy's upstream (the local model) is itself a single env var
(`OPENAI_BASE_URL` → `http://your-gpu-host:8013/v1` or
`http://your-blackwell-box:8080/v1`). **Nothing in the agent code changes when
the serving hardware changes.** That tool-agnostic, backend-agnostic
separation is the whole point — the trust boundary stays fixed while the
infrastructure underneath is swappable.

---

## Why this topology, for regulated deployment

Each layer exists for a reason that matters where data cannot leave a
perimeter (finance, healthcare, government):

| Layer | Trust property it provides |
|---|---|
| Local serving (vLLM / llama.cpp) | Inference never touches a third-party API — no data exfiltration surface |
| Translation proxy + `dk_*` auth | Identity/authorization enforced **inside** the perimeter, against a local key store, no external IdP callout |
| Agent loop with audit logging | Every tool call recorded before execution — reconstructable decision trail |
| Three-tier identity (see `docs/security-curriculum.md`) | Compromised session ≠ escalated authority |

The result is an agentic stack where the **only** thing that ever needs to
cross the network boundary is nothing. The model, the auth, the orchestration,
and the audit trail all live on hardware the operator controls.

---

## Reproducing it

1. Stand up a serving path (A or B above) — any OpenAI-compatible endpoint.
2. Run the translation proxy (`cjayasur/dobbyai-proxy-extensions` on top of
   `1rgs/claude-code-proxy`), pointed at that endpoint.
3. Point this agent at the proxy via `AGENT_API_URL` / `AGENT_API_KEY`.
4. `bun run src/step10-full-agent.ts` — the loop now runs entirely on local
   hardware.

Hostnames above (`your-gpu-host`, `your-blackwell-box`, `your-proxy-host`) are
placeholders — substitute your own. No internal addressing is encoded
anywhere in this stack.
