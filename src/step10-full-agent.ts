// Step 10: The Full Agent — Everything Combined (1100+ lines)
//
// This is the complete claude-code-simple agent combining every lesson.
//
// Run:  bun step10:agent
//
// WHAT'S IN THIS FILE (12 lessons stacked):
//   L1-2:  API client (fetch + JSON)
//   L3:    Multi-turn conversation (messages array)
//   L4:    SSE streaming parser (content_block_start/delta/stop)
//   L6b:   Resilient XML fallback (vLLM qwen3_coder bug workaround)
//   L7:    MCP integration (SDK, stdio + HTTP transports)
//   L8:    System prompt (dynamic workspace injection) + context compaction
//   L9:    Memory MCP server + auto-detect memories from user input
//   L10:   Permissions (read=auto, write=ask, admin=warn)
//   L11:   Custom MCP servers (code-analyzer, job-applier)
//   L12:   Vision (/image → non-streaming fallback for Qwen3.6 native vision)
//
// COMMANDS: /system /messages /memories /mcp /tools /dump /image /exit
//
// MCP SERVERS (from mcp.config.json):
//   filesystem(14) + fetch(1) + math(3) + memory(5) + code-analyzer(4) + jobs(6) + built-in(3) = 36 tools

import { readFileSync, readdirSync, statSync, existsSync } from "fs";
import { resolve, join } from "path";
import { execSync } from "child_process";
import { homedir } from "os";
import { createInterface } from "readline";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

// Backend is pluggable. Point at any Anthropic-Messages-compatible endpoint:
//   - Your own Anthropic<->OpenAI translation proxy (self-hosted Qwen/Llama)
//   - api.anthropic.com directly
// Credentials are read from the environment — never hardcoded.
const API_URL = process.env.AGENT_API_URL ?? "https://api.anthropic.com/v1/messages";
const API_KEY = process.env.AGENT_API_KEY ?? "";

if (!API_KEY) {
  console.error("Set AGENT_API_KEY (and optionally AGENT_API_URL). See .env.example.");
  process.exit(1);
}

// Context management settings
const MAX_CONTEXT_MESSAGES = 40;
const COMPACTION_TARGET = 10;


// ─── Types ──────────────────────────────────────────────────────

type TextBlock = { type: "text"; text: string };
type ToolUseBlock = { type: "tool_use"; id: string; name: string; input: any };
type ToolResultBlock = { type: "tool_result"; tool_use_id: string; content: string };
type ContentBlock = TextBlock | ToolUseBlock | ToolResultBlock;

type Message = {
  role: "user" | "assistant" | "system";
  content: string | ContentBlock[];
};

type StreamResult = { blocks: ContentBlock[]; stopReason: string };

type ToolSchema = {
  name: string;
  description: string;
  input_schema: any;
};


// ─── System Prompt Builder ──────────────────────────────────────
//
// The system prompt is injected into every API call. It tells the LLM:
//   - Who it is (a coding assistant)
//   - What rules to follow (no hallucination, no fabrication)
//   - What workspace it's in (file tree, git status)
//   - What tools it has available
//
// Claude Code does this dynamically — the prompt changes based on
// the current directory, git state, and configured tools.

const MEMORY_DIR = join(homedir(), ".claude-code-simple");
const MEMORY_FILE = join(MEMORY_DIR, "memories.json");

function loadMemoriesForPrompt(): string {
  if (!existsSync(MEMORY_FILE)) return "";
  try {
    const store = JSON.parse(readFileSync(MEMORY_FILE, "utf-8"));
    const entries = Object.values(store) as Array<{ key: string; value: string }>;
    if (entries.length === 0) return "";
    return entries.map(e => `  ${e.key}: ${e.value}`).join("\n");
  } catch {
    return "";
  }
}

function buildSystemPrompt(toolNames: string[]): string {
  const cwd = process.cwd();

  // Get workspace context
  let fileTree = "";
  try {
    const entries = readdirSync(cwd);
    fileTree = entries
      .filter(e => !e.startsWith(".") && e !== "node_modules")
      .map(e => {
        const stat = statSync(join(cwd, e));
        return stat.isDirectory() ? `  ${e}/` : `  ${e}`;
      })
      .join("\n");
  } catch {
    fileTree = "  (could not read directory)";
  }

  // Get git status if in a git repo
  let gitInfo = "";
  try {
    const branch = execSync("git branch --show-current", { cwd, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] }).trim();
    const status = execSync("git status --short", { cwd, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] }).trim();
    gitInfo = `\nGit branch: ${branch}`;
    if (status) gitInfo += `\nGit status:\n${status}`;
  } catch {
    gitInfo = "\nNot a git repository.";
  }

  // Load saved memories from previous sessions
  const memories = loadMemoriesForPrompt();
  const memorySection = memories
    ? `\n## Memories from Previous Sessions\n\nYou remember these facts from earlier conversations:\n${memories}\n\nUse this knowledge to personalize your responses. If the user corrects a memory, update it using the save_memory tool.`
    : "\n## Memories\n\nNo memories saved yet. When you learn important facts about the user, their project, or their preferences, save them using the save_memory tool so you remember next time.";

  return `You are a coding assistant running in the terminal. You help the user with software engineering tasks: reading code, writing code, debugging, explaining, and file management.

## Rules

- Be concise. Short answers unless the user asks for detail.
- When a tool call fails or returns an error, report the error honestly. NEVER fabricate data or make up file contents.
- If you don't know something, say so. Do not guess or hallucinate.
- Only use data that came from tool results. Never invent file contents, API responses, or command output.
- When fetching a URL and saving to a file, use the EXACT content from the fetch result. Do not rewrite or summarize it.
- IMPORTANT: When the user tells you ANYTHING about themselves, their project, or their preferences, you MUST call save_memory IMMEDIATELY in the same response. Do not wait. Do not ask. Just save it. Examples of things to save:
  - Their name, role, experience level
  - What project they're working on
  - Programming languages they use or are learning
  - Preferences (concise answers, no emojis, etc.)
  - Hardware they're using (laptop specs, server specs)
  - Goals or deadlines they mention
${memorySection}

## Workspace

Current directory: ${cwd}
${gitInfo}

Files:
${fileTree}

## Available Tools

You have ${toolNames.length} tools: ${toolNames.join(", ")}

Use the appropriate tool when the user asks to read files, list directories, fetch URLs, or perform math. Do not guess what a file contains — read it.
Use the memory tools (save_memory, recall_memory, search_memories, list_memories, forget_memory) to persist important information across sessions.`;
}


// ─── Context Compaction ─────────────────────────────────────────
//
// When the messages array grows beyond MAX_CONTEXT_MESSAGES, we ask
// the LLM to summarize the older conversation, then replace those
// messages with a single summary message.
//
// This is how Claude Code maintains long sessions — it periodically
// compresses the history so you never hit the context window limit.
//
// BEFORE compaction (40 messages):
//   [msg1, msg2, msg3, ..., msg35, msg36, msg37, msg38, msg39, msg40]
//
// AFTER compaction (~10 messages):
//   [summary_of_msg1_to_msg30, msg31, msg32, ..., msg40]

async function compactContext(messages: Message[]): Promise<void> {
  if (messages.length <= MAX_CONTEXT_MESSAGES) return;

  const keepCount = COMPACTION_TARGET;
  const oldMessages = messages.slice(0, messages.length - keepCount);
  const recentMessages = messages.slice(messages.length - keepCount);

  // Build a summary request
  const summaryContent = oldMessages.map((m, i) => {
    const text = typeof m.content === "string"
      ? m.content
      : m.content.map(b => {
          if (b.type === "text") return b.text;
          if (b.type === "tool_use") return `[Called tool: ${b.name}]`;
          if (b.type === "tool_result") return `[Tool result: ${b.content.slice(0, 100)}...]`;
          return "[unknown block]";
        }).join(" ");
    return `${m.role}: ${text}`;
  }).join("\n");

  // Ask the LLM to summarize (non-streaming, simple call)
  console.log("\n  📦 Compacting context (summarizing older messages)...");

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 1024,
        messages: [{
          role: "user",
          content: `Summarize this conversation history in 2-3 paragraphs. Capture: what was discussed, what files were read or modified, what tools were used, and any decisions made. Be factual — do not add information that wasn't in the conversation.\n\n${summaryContent}`,
        }],
      }),
    });

    if (!response.ok) {
      console.log("  ⚠️  Compaction failed (HTTP error), keeping full history");
      return;
    }

    const data = await response.json() as any;
    const summaryText = data.content?.[0]?.text ?? "Summary unavailable.";

    // Replace messages array: summary + recent messages
    messages.length = 0;
    messages.push({
      role: "user",
      content: `[CONTEXT SUMMARY — the following is a summary of our earlier conversation]\n\n${summaryText}\n\n[END SUMMARY — conversation continues below]`,
    });
    messages.push({
      role: "assistant",
      content: "Understood. I have the context from our earlier conversation. Let's continue.",
    });
    for (const msg of recentMessages) {
      messages.push(msg);
    }

    console.log(`  📦 Compacted: ${oldMessages.length + recentMessages.length} messages → ${messages.length} messages\n`);
  } catch (err) {
    console.log(`  ⚠️  Compaction failed: ${err}`);
  }
}


// ─── Config types + MCP Client ──────────────────────────────────

type StdioServerConfig = {
  command: string;
  args: string[];
  env?: Record<string, string>;
};
type HttpServerConfig = {
  transport: "http";
  url: string;
};
type MCPServerConfig = StdioServerConfig | HttpServerConfig;
type MCPConfig = { mcpServers: Record<string, MCPServerConfig> };

class MCPClientSDK {
  readonly name: string;
  readonly transportType: "stdio" | "http";
  private readonly command?: string;
  private readonly args?: string[];
  private readonly env: Record<string, string>;
  private readonly url?: string;
  private client: Client | null = null;

  public tools: Array<{ name: string; description: string; inputSchema: any }> = [];

  constructor(name: string, cfg: StdioServerConfig | HttpServerConfig) {
    this.name = name;
    if ("transport" in cfg && cfg.transport === "http") {
      this.transportType = "http";
      this.url = cfg.url;
      this.env = {};
    } else {
      this.transportType = "stdio";
      this.command = cfg.command;
      this.args = cfg.args;
      this.env = cfg.env ?? {};
    }
  }

  async connect(): Promise<void> {
    let transport;
    if (this.transportType === "http") {
      transport = new StreamableHTTPClientTransport(new URL(this.url!));
    } else {
      transport = new StdioClientTransport({
        command: this.command!,
        args: this.args!,
        env: { ...process.env, ...this.env } as Record<string, string>,
      });
    }

    this.client = new Client(
      { name: "claude-code-simple", version: "0.1.0" },
      { capabilities: {} }
    );

    await this.client.connect(transport);
    const res = await this.client.listTools();
    this.tools = res.tools as any;
  }

  async callTool(toolName: string, args: any): Promise<string> {
    if (!this.client) throw new Error(`MCP client ${this.name} not connected`);
    const result: any = await this.client.callTool({
      name: toolName,
      arguments: args,
    });

    if (result?.isError) {
      return `ERROR (from MCP tool ${toolName}): ${this.extractText(result.content)}`;
    }
    return this.extractText(result?.content ?? []);
  }

  async shutdown(): Promise<void> {
    if (!this.client) return;
    try { await this.client.close(); } catch {}
    this.client = null;
  }

  private extractText(content: any): string {
    if (!content) return "";
    if (typeof content === "string") return content;
    if (!Array.isArray(content)) return JSON.stringify(content);
    const parts: string[] = [];
    for (const block of content) {
      if (block?.type === "text" && typeof block.text === "string") {
        parts.push(block.text);
      } else {
        parts.push(JSON.stringify(block));
      }
    }
    return parts.join("\n");
  }
}


// ─── Config loading ─────────────────────────────────────────────

function loadMCPConfig(): MCPConfig {
  const configPath = resolve("mcp.config.json");
  if (!existsSync(configPath)) {
    console.log("  (no mcp.config.json — MCP disabled)\n");
    return { mcpServers: {} };
  }
  try {
    return JSON.parse(readFileSync(configPath, "utf-8")) as MCPConfig;
  } catch (err) {
    console.error(`  ⚠️  Failed to parse mcp.config.json: ${err}`);
    return { mcpServers: {} };
  }
}

async function startMCPServers(config: MCPConfig): Promise<MCPClientSDK[]> {
  const clients: MCPClientSDK[] = [];
  for (const [name, cfg] of Object.entries(config.mcpServers)) {
    const client = new MCPClientSDK(name, cfg);
    try {
      const icon = client.transportType === "http" ? "🌐" : "🔌";
      process.stdout.write(`  ${icon} Connecting to MCP server: ${name} (${client.transportType}) ...`);
      await client.connect();
      console.log(` ok (${client.tools.length} tools)`);
      clients.push(client);
    } catch (err) {
      console.log(` ❌ ${err}`);
    }
  }
  return clients;
}


// ─── Built-in tools ─────────────────────────────────────────────

function handleGetCurrentTime(): string {
  return new Date().toISOString();
}

function handleRead(input: any): string {
  const filePath = input?.file_path;
  if (!filePath) return "ERROR: missing file_path";
  const resolved = resolve(filePath);
  if (!existsSync(resolved)) return `ERROR: file not found: ${resolved}`;
  try {
    const stat = statSync(resolved);
    if (stat.size > 100_000) return `ERROR: file too large (${stat.size} bytes, max 100KB)`;
    return readFileSync(resolved, "utf-8");
  } catch (err) {
    return `ERROR reading file: ${err}`;
  }
}

function handleListDir(input: any): string {
  const dirPath = input?.dir_path ?? ".";
  const resolved = resolve(dirPath);
  if (!existsSync(resolved)) return `ERROR: directory not found: ${resolved}`;
  try {
    const entries = readdirSync(resolved);
    return entries
      .map(name => {
        const stat = statSync(join(resolved, name));
        return stat.isDirectory() ? `[DIR]  ${name}` : `[FILE] ${name}`;
      })
      .join("\n");
  } catch (err) {
    return `ERROR listing directory: ${err}`;
  }
}

const builtInSchemas: ToolSchema[] = [
  {
    name: "GetCurrentTime",
    description: "Returns current system time as ISO-8601.",
    input_schema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "Read",
    description: "Read a file from disk.",
    input_schema: {
      type: "object",
      properties: { file_path: { type: "string" } },
      required: ["file_path"],
    },
  },
  {
    name: "ListDir",
    description: "List files and subdirectories in a directory.",
    input_schema: {
      type: "object",
      properties: { dir_path: { type: "string" } },
      required: ["dir_path"],
    },
  },
];

const builtInHandlers: Record<string, (input: any) => string> = {
  GetCurrentTime: handleGetCurrentTime,
  Read: handleRead,
  ListDir: handleListDir,
};


// ─── Tool registry + dispatch ───────────────────────────────────

function buildToolSchemas(mcpClients: MCPClientSDK[]): ToolSchema[] {
  const schemas: ToolSchema[] = [...builtInSchemas];
  for (const client of mcpClients) {
    for (const tool of client.tools) {
      schemas.push({
        name: `mcp_${client.name}_${tool.name}`,
        description: `[${client.name}] ${tool.description}`,
        input_schema: tool.inputSchema,
      });
    }
  }
  return schemas;
}

// ─── Permission system ──────────────────────────────────────────
//
// Each tool is classified by risk level:
//   "read"  → auto-approved (safe, doesn't change anything)
//   "write" → asks user before executing (modifies files/state)
//   "admin" → asks user with warning (destructive or irreversible)
//
// The classification is based on the tool name. Unknown tools default to "write".

type PermissionLevel = "read" | "write" | "admin";

const TOOL_PERMISSIONS: Record<string, PermissionLevel> = {
  // Built-in tools
  GetCurrentTime: "read",
  Read: "read",
  ListDir: "read",

  // Filesystem MCP — read operations
  mcp_filesystem_read_file: "read",
  mcp_filesystem_read_text_file: "read",
  mcp_filesystem_read_media_file: "read",
  mcp_filesystem_read_multiple_files: "read",
  mcp_filesystem_list_directory: "read",
  mcp_filesystem_list_directory_with_sizes: "read",
  mcp_filesystem_directory_tree: "read",
  mcp_filesystem_get_file_info: "read",
  mcp_filesystem_list_allowed_directories: "read",
  mcp_filesystem_search_files: "read",

  // Filesystem MCP — write operations
  mcp_filesystem_write_file: "write",
  mcp_filesystem_edit_file: "write",
  mcp_filesystem_create_directory: "write",
  mcp_filesystem_move_file: "admin",

  // Fetch MCP
  mcp_fetch_fetch: "read",

  // Math MCP
  mcp_math_add: "read",
  mcp_math_multiply: "read",
  mcp_math_get_server_info: "read",

  // Memory MCP
  mcp_memory_save_memory: "write",
  mcp_memory_recall_memory: "read",
  mcp_memory_search_memories: "read",
  mcp_memory_list_memories: "read",
  mcp_memory_forget_memory: "admin",

  // Job Applier MCP
  "mcp_jobs_search_jobs": "read",
  "mcp_jobs_read_job_posting": "read",
  "mcp_jobs_score_fit": "read",
  "mcp_jobs_login": "write",
  "mcp_jobs_get_captcha": "read",
  "mcp_jobs_apply_to_job": "admin",

  // Browser/Playwright MCP — most auto-approved for smooth browsing
  "mcp_browser_browser_navigate": "read",
  "mcp_browser_browser_navigate_back": "read",
  "mcp_browser_browser_take_screenshot": "read",
  "mcp_browser_browser_snapshot": "read",
  "mcp_browser_browser_click": "read",
  "mcp_browser_browser_hover": "read",
  "mcp_browser_browser_type": "read",
  "mcp_browser_browser_fill_form": "read",
  "mcp_browser_browser_select_option": "read",
  "mcp_browser_browser_press_key": "read",
  "mcp_browser_browser_tabs": "read",
  "mcp_browser_browser_wait_for": "read",
  "mcp_browser_browser_console_messages": "read",
  "mcp_browser_browser_network_requests": "read",
  "mcp_browser_browser_network_request": "read",
  "mcp_browser_browser_close": "read",
  "mcp_browser_browser_resize": "read",
  "mcp_browser_browser_handle_dialog": "read",
  "mcp_browser_browser_drag": "write",
  "mcp_browser_browser_drop": "write",
  "mcp_browser_browser_file_upload": "write",
  "mcp_browser_browser_evaluate": "admin",
  "mcp_browser_browser_run_code_unsafe": "admin",
};

function getPermissionLevel(toolName: string): PermissionLevel {
  return TOOL_PERMISSIONS[toolName] ?? "write";
}

// Global reference to readline — set in main(), used by askPermission()
let globalRl: ReturnType<typeof createInterface> | null = null;

function askPermission(toolName: string, input: any, level: PermissionLevel): Promise<boolean> {
  return new Promise((resolve) => {
    if (!globalRl) { resolve(true); return; }

    const inputPreview = JSON.stringify(input).slice(0, 100);
    const prefix = level === "admin" ? "  ⚠️  ADMIN" : "  🔒";
    console.log(`\n${prefix} Tool "${toolName}" requires permission.`);
    console.log(`     Args: ${inputPreview}`);

    globalRl.question("     Allow? (y/n): ", (answer: string) => {
      const allowed = answer.trim().toLowerCase().startsWith("y");
      if (!allowed) console.log("     ❌ Denied by user.");
      resolve(allowed);
    });
  });
}

async function executeTool(
  name: string,
  input: any,
  mcpClients: MCPClientSDK[]
): Promise<string> {
  // Check permission before executing
  const level = getPermissionLevel(name);
  if (level !== "read") {
    const allowed = await askPermission(name, input, level);
    if (!allowed) return `Tool "${name}" was denied by the user.`;
  }

  const handler = builtInHandlers[name];
  if (handler) {
    try { return handler(input); }
    catch (err) { return `ERROR: built-in tool "${name}" threw: ${err}`; }
  }

  if (name.startsWith("mcp_")) {
    for (const client of mcpClients) {
      const prefix = `mcp_${client.name}_`;
      if (name.startsWith(prefix)) {
        const toolName = name.slice(prefix.length);
        try { return await client.callTool(toolName, input); }
        catch (err) { return `ERROR: MCP tool "${name}" failed: ${err}`; }
      }
    }
    return `ERROR: No MCP server found for tool "${name}"`;
  }

  return `ERROR: Unknown tool "${name}"`;
}


// ─── Auto-detect memory-worthy statements ───────────────────────

const MEMORY_PATTERNS: Array<{ pattern: RegExp; keyFn: (m: RegExpMatchArray, i?: number) => string; valueFn: (m: RegExpMatchArray) => string }> = [
  { pattern: /my name is (\w+)/i, keyFn: () => "user_name", valueFn: (m) => m[1] },
  { pattern: /i(?:'m| am) (?:a |an )?(.+?(?:developer|engineer|scientist|architect|student|manager|consultant|designer|founder))/i, keyFn: () => "user_role", valueFn: (m) => m[1] },
  { pattern: /i(?:'m| am) (?:building|working on|developing|creating) (.+?)(?:\.|$)/i, keyFn: () => "user_project", valueFn: (m) => m[1].trim() },
  { pattern: /i (?:prefer|like|want) (.+?)(?:\.|$)/i, keyFn: () => "user_preference", valueFn: (m) => m[1].trim() },
  { pattern: /i(?:'ve| have) (?:been |)(?:using|programming|coding|working)(?: (?:in|with))? (.+?) for (\d+)/i, keyFn: (m) => `experience_${m[1].trim().toLowerCase().replace(/\s+/g, "_")}`, valueFn: (m) => `${m[1].trim()} for ${m[2]} years` },
  { pattern: /(?:remember|don't forget|save|note) that (.+)/i, keyFn: (_m, i) => `user_note_${i}`, valueFn: (m) => m[1].trim() },
];

async function autoDetectMemories(userMessage: string, mcpClients: MCPClientSDK[]): Promise<void> {
  const memoryClient = mcpClients.find(c => c.name === "memory");
  if (!memoryClient) return;
  const timestamp = Date.now();
  for (const { pattern, keyFn, valueFn } of MEMORY_PATTERNS) {
    const match = userMessage.match(pattern);
    if (match) {
      const key = keyFn(match, timestamp);
      const value = valueFn(match);
      try {
        await memoryClient.callTool("save_memory", { key, value });
        console.log(`  💾 Auto-saved memory: ${key} = "${value}"`);
      } catch {}
    }
  }
}


// ─── Streaming SSE parser with resilience ───────────────────────

function parseQwenFunctionXml(xml: string): { name: string; input: any } | null {
  const nameMatch = xml.match(/<function=([A-Za-z_][A-Za-z0-9_]*)>/);
  if (!nameMatch) return null;
  const name = nameMatch[1];
  const paramRegex = /<parameter=([A-Za-z_][A-Za-z0-9_]*)>\s*([\s\S]*?)\s*<\/parameter>/g;
  const input: any = {};
  let match: RegExpExecArray | null;
  while ((match = paramRegex.exec(xml)) !== null) {
    const key = match[1];
    let value = match[2].trim();
    try { input[key] = JSON.parse(value); }
    catch { input[key] = value; }
  }
  return { name, input };
}

async function sendMessageNonStreaming(
  messages: Message[],
  toolSchemas: ToolSchema[],
  systemPrompt: string
): Promise<StreamResult> {
  console.log("  👁️ Vision mode (non-streaming)...");
  const response = await fetch(API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 4096,
      system: systemPrompt,
      messages,
      tools: toolSchemas,
    }),
  });

  if (!response.ok) throw new Error(`HTTP ${response.status}: ${await response.text()}`);
  const data = await response.json() as any;

  const blocks: ContentBlock[] = [];
  const stopReason = data.stop_reason ?? "end_turn";

  for (const block of data.content ?? []) {
    if (block.type === "text") {
      // Strip thinking tags from response
      const cleaned = block.text
        .replace(/<\/?think>/g, "")
        .replace(/^[\s\S]*?<\/think>\s*/g, "")
        .trim();
      if (cleaned) {
        process.stdout.write(cleaned);
        blocks.push({ type: "text", text: cleaned });
      }
    } else if (block.type === "tool_use") {
      console.log(`\n  🔧 Calling ${block.name}(${JSON.stringify(block.input)})`);
      blocks.push({ type: "tool_use", id: block.id, name: block.name, input: block.input });
    }
  }

  return { blocks, stopReason };
}

async function sendMessageStreaming(
  messages: Message[],
  toolSchemas: ToolSchema[],
  systemPrompt: string
): Promise<StreamResult> {
  // Detect if any message contains an image — use non-streaming for vision
  const hasImage = messages.some(m =>
    Array.isArray(m.content) && m.content.some((b: any) => b.type === "image")
  );

  if (hasImage) {
    return sendMessageNonStreaming(messages, toolSchemas, systemPrompt);
  }

  const response = await fetch(API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 4096,
      stream: true,
      system: systemPrompt,
      messages,
      tools: toolSchemas,
    }),
  });

  if (!response.ok) throw new Error(`HTTP ${response.status}: ${await response.text()}`);
  if (!response.body) throw new Error("Response has no body");

  const reader = response.body.getReader();
  const decoder = new TextDecoder();

  type StreamingTextBlock = {
    type: "text"; index: number; text: string;
    mode: "normal" | "buffering_xml";
    xmlBuffer: string; extractedToolCalls: ToolUseBlock[];
    isThinking: boolean; thinkingDone: boolean;
  };
  type StreamingToolUseBlock = {
    type: "tool_use"; index: number;
    id: string; name: string; partialJson: string; input?: any;
  };
  type StreamingBlock = StreamingTextBlock | StreamingToolUseBlock;

  const blocks: StreamingBlock[] = [];
  let stopReason = "";
  let buffer = "";

  function handleTextDelta(block: StreamingTextBlock, deltaText: string) {
    block.text += deltaText;
    if (block.mode === "normal") {
      const xmlStart = block.text.indexOf("<function=");
      if (xmlStart === -1) { process.stdout.write(deltaText); return; }
      block.mode = "buffering_xml";
      block.xmlBuffer = block.text.slice(xmlStart);
      const before = deltaText.slice(0, deltaText.length - (block.text.length - xmlStart));
      if (before) process.stdout.write(before);
      return;
    }
    block.xmlBuffer += deltaText;
    const endTag = "</function>";
    let searchStart = 0;
    while (true) {
      const endIdx = block.xmlBuffer.indexOf(endTag, searchStart);
      if (endIdx === -1) break;
      const fullXml = block.xmlBuffer.slice(0, endIdx + endTag.length);
      const parsed = parseQwenFunctionXml(fullXml);
      if (parsed) {
        const syntheticId = `xmltool_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
        block.extractedToolCalls.push({
          type: "tool_use", id: syntheticId, name: parsed.name, input: parsed.input,
        });
        console.log(`\n  🔧 Calling ${parsed.name}(${JSON.stringify(parsed.input)}) [recovered from raw XML]`);
      }
      block.xmlBuffer = block.xmlBuffer.slice(endIdx + endTag.length);
      searchStart = 0;
      if (block.xmlBuffer.indexOf("<function=") === -1) {
        block.mode = "normal";
        if (block.xmlBuffer) process.stdout.write(block.xmlBuffer);
        block.xmlBuffer = "";
        break;
      }
    }
  }

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";

    for (const line of lines) {
      if (!line.startsWith("data: ")) continue;
      const payload = line.slice(6).trim();
      if (payload === "[DONE]") continue;
      let event: any;
      try { event = JSON.parse(payload); } catch { continue; }

      switch (event.type) {
        case "content_block_start": {
          const cb = event.content_block;
          if (cb.type === "text") {
            blocks[event.index] = {
              type: "text", index: event.index, text: "",
              mode: "normal", xmlBuffer: "", extractedToolCalls: [],
              isThinking: true, thinkingDone: false,
            };
          } else if (cb.type === "tool_use") {
            blocks[event.index] = {
              type: "tool_use", index: event.index,
              id: cb.id, name: cb.name, partialJson: "",
            };
            console.log(`\n  🔧 Calling ${cb.name}(...)`);
          }
          break;
        }
        case "content_block_delta": {
          const block = blocks[event.index];
          if (!block) break;
          if (event.delta.type === "thinking_delta") {
            // Reasoning/thinking from proxy — print dimmed but don't store
            // Only arrives when SUPPRESS_REASONING=false on proxy
            process.stdout.write(`\x1b[2m${event.delta.text}\x1b[0m`);
            break;
          } else if (event.delta.type === "text_delta" && block.type === "text") {
            handleTextDelta(block, event.delta.text);
          } else if (event.delta.type === "input_json_delta" && block.type === "tool_use") {
            block.partialJson += event.delta.partial_json;
          }
          break;
        }
        case "content_block_stop": {
          const block = blocks[event.index];
          if (block?.type === "tool_use") {
            try { block.input = JSON.parse(block.partialJson); }
            catch { block.input = {}; }
            console.log(`\n  🔧 Calling ${block.name}(${JSON.stringify(block.input)})`);
          }
          break;
        }
        case "message_delta": {
          if (event.delta?.stop_reason) stopReason = event.delta.stop_reason;
          break;
        }
      }
    }
  }

  const finalBlocks: ContentBlock[] = [];
  let foundSynthetic = false;
  for (const b of blocks) {
    if (b.type === "text") {
      const cleanedText = b.text
        .replace(/<function=[\s\S]*?<\/function>/g, "")
        .replace(/<\/?think>/g, "")
        .replace(/^[\s\S]*?<\/think>\s*/g, "")
        .trim();
      if (cleanedText) finalBlocks.push({ type: "text", text: cleanedText });
      if (b.extractedToolCalls.length > 0) {
        foundSynthetic = true;
        for (const tc of b.extractedToolCalls) finalBlocks.push(tc);
      }
    } else {
      finalBlocks.push({ type: "tool_use", id: b.id, name: b.name, input: b.input });
    }
  }
  if (foundSynthetic && stopReason !== "tool_use") stopReason = "tool_use";
  return { blocks: finalBlocks, stopReason };
}


// ─── Agentic loop ───────────────────────────────────────────────

async function runAgenticTurn(
  messages: Message[],
  mcpClients: MCPClientSDK[],
  systemPrompt: string
): Promise<void> {
  const toolSchemas = buildToolSchemas(mcpClients);
  const MAX_ITERATIONS = 15;

  for (let i = 0; i < MAX_ITERATIONS; i++) {
    const { blocks, stopReason } = await sendMessageStreaming(messages, toolSchemas, systemPrompt);
    messages.push({ role: "assistant", content: blocks });

    if (stopReason !== "tool_use") { console.log("\n"); return; }

    const toolResults: ToolResultBlock[] = [];
    for (const block of blocks) {
      if (block.type !== "tool_use") continue;
      const output = await executeTool(block.name, block.input, mcpClients);
      const preview = output.length > 200 ? output.slice(0, 200) + "..." : output;
      console.log(`  ← ${preview.replaceAll("\n", "\n     ")}`);
      toolResults.push({ type: "tool_result", tool_use_id: block.id, content: output });
    }
    messages.push({ role: "user", content: toolResults });
  }
  console.error(`\n⚠️  Hit MAX_ITERATIONS (15)`);
}


// ─── Main ───────────────────────────────────────────────────────

async function main() {
  console.log("🤖 Claude Code Simple + Permissions + Memory + System Prompts\n");

  const config = loadMCPConfig();
  const mcpClients = await startMCPServers(config);

  // Build tool list for system prompt
  const toolSchemas = buildToolSchemas(mcpClients);
  const toolNames = toolSchemas.map(t => t.name);

  // Build system prompt with workspace context
  const systemPrompt = buildSystemPrompt(toolNames);

  const totalTools = toolNames.length;
  console.log(`\n🧰 Total tools: ${totalTools}`);
  console.log(`   ${builtInSchemas.length} built-in`);
  for (const client of mcpClients) {
    console.log(`   ${client.tools.length} from MCP "${client.name}"`);
  }
  console.log(`\n📋 System prompt: ${systemPrompt.length} chars`);
  console.log(`📦 Context compaction: after ${MAX_CONTEXT_MESSAGES} messages → ${COMPACTION_TARGET} kept`);
  console.log(`\nType /exit to quit. Commands: /system /messages /memories /mcp /tools /dump\n`);

  const messages: Message[] = [];

  const shutdown = async () => {
    console.log("\n🔌 Shutting down MCP servers...");
    for (const client of mcpClients) await client.shutdown();
    rl.close();
    console.log("👋 bye");
    process.exit(0);
  };
  process.on("SIGINT", shutdown);

  // readline gives us up/down arrow history + permission prompts
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
    history: [] as string[],
    historySize: 100,
    prompt: "❯ ",
  });
  globalRl = rl;

  function askQuestion(): void {
    rl.question("❯ ", async (userInput: string) => {
      if (userInput === null) { await shutdown(); return; }
      const trimmed = userInput.trim();
      if (trimmed === "/exit" || trimmed === "/quit") { await shutdown(); return; }
      if (trimmed === "") { askQuestion(); return; }

      // Debug commands
      if (trimmed === "/system") {
        console.log("\n--- SYSTEM PROMPT ---");
        console.log(systemPrompt);
        console.log("--- END ---\n");
        askQuestion(); return;
      }
      if (trimmed === "/messages") {
        console.log(`\n--- MESSAGE HISTORY (${messages.length} messages) ---`);
        for (let i = 0; i < messages.length; i++) {
          const m = messages[i];
          console.log(`\n  [${i}] ${m.role}:`);
          if (typeof m.content === "string") {
            console.log(`       "${m.content.slice(0, 120)}${m.content.length > 120 ? "..." : ""}"`);
          } else {
            for (const block of m.content) {
              if (block.type === "text") {
                const preview = block.text.slice(0, 100);
                console.log(`       text: "${preview}${block.text.length > 100 ? "..." : ""}"`);
              } else if (block.type === "tool_use") {
                console.log(`       tool_use: ${block.name}(${JSON.stringify(block.input).slice(0, 80)})`);
              } else if (block.type === "tool_result") {
                const preview = block.content.slice(0, 80);
                console.log(`       tool_result [${block.tool_use_id.slice(0, 12)}]: "${preview}${block.content.length > 80 ? "..." : ""}"`);
              }
            }
          }
        }
        console.log("\n--- END ---\n");
        askQuestion(); return;
      }
      if (trimmed.startsWith("/image ")) {
        const imagePath = resolve(trimmed.slice(7).trim());
        if (!existsSync(imagePath)) {
          console.log(`  File not found: ${imagePath}\n`);
          askQuestion(); return;
        }
        const imageData = readFileSync(imagePath);
        const base64 = imageData.toString("base64");
        const ext = imagePath.split(".").pop()?.toLowerCase() ?? "jpeg";
        const mediaType = ext === "png" ? "image/png" : ext === "gif" ? "image/gif" : ext === "webp" ? "image/webp" : "image/jpeg";
        console.log(`  📷 Sending image (${(imageData.length / 1024).toFixed(0)}KB, ${mediaType})`);

        // Ask what to do with the image
        const prompt = trimmed.includes("—") ? trimmed.split("—").slice(1).join("—").trim() : "Describe this image in detail.";

        messages.push({
          role: "user",
          content: [
            { type: "image", source: { type: "base64", media_type: mediaType, data: base64 } },
            { type: "text", text: prompt },
          ] as any,
        });
        console.log("");
        try {
          await runAgenticTurn(messages, mcpClients, systemPrompt);
          await compactContext(messages);
        } catch (err) {
          console.error("\nError:", err);
          messages.pop();
        }
        askQuestion(); return;
      }
      if (trimmed === "/tools") {
        const toolSchemas = buildToolSchemas(mcpClients);
        const readTools: string[] = [];
        const writeTools: string[] = [];
        const adminTools: string[] = [];
        for (const t of toolSchemas) {
          const level = getPermissionLevel(t.name);
          if (level === "read") readTools.push(t.name);
          else if (level === "write") writeTools.push(t.name);
          else adminTools.push(t.name);
        }
        console.log(`\n--- TOOLS (${toolSchemas.length}) by permission level ---\n`);
        console.log(`  ✅ READ (auto-approve): ${readTools.length}`);
        for (const t of readTools) console.log(`     ${t}`);
        console.log(`\n  🔒 WRITE (ask first): ${writeTools.length}`);
        for (const t of writeTools) console.log(`     ${t}`);
        console.log(`\n  ⚠️  ADMIN (ask + warn): ${adminTools.length}`);
        for (const t of adminTools) console.log(`     ${t}`);
        console.log("\n--- END ---\n");
        askQuestion(); return;
      }
      if (trimmed === "/mcp") {
        const configPath = resolve("mcp.config.json");
        const rawConfig = existsSync(configPath) ? JSON.parse(readFileSync(configPath, "utf-8")) : { mcpServers: {} };

        console.log(`\n--- MCP SERVERS (${mcpClients.length} connected) ---\n`);
        for (const client of mcpClients) {
          const cfg = rawConfig.mcpServers?.[client.name];
          const icon = client.transportType === "http" ? "🌐" : "🔌";
          const toolNames = client.tools.map((t: any) => t.name).join(", ");

          // Derive language and origin from config
          let lang = "?";
          let origin = "";
          if (client.transportType === "http") {
            lang = "any";
            origin = cfg?.url ?? "unknown";
          } else if (cfg?.command) {
            const cmd = cfg.command as string;
            const args = (cfg.args as string[]) ?? [];
            if (cmd.includes("npx")) {
              lang = "Node.js";
              const pkg = args.find((a: string) => a.startsWith("@") || (!a.startsWith("-") && a.includes("/"))) ?? args[args.length - 1];
              origin = `npm: ${pkg}`;
            } else if (cmd.includes("python")) {
              const ver = cmd.match(/python(\d+\.\d+)/)?.[1] ?? "3.x";
              lang = `Python ${ver}`;
              const mod = args.find((a: string) => a !== "-m") ?? "unknown";
              origin = `pip: ${mod}`;
            } else if (cmd.includes("bun")) {
              lang = "TypeScript/Bun";
              const file = args.find((a: string) => a.endsWith(".ts")) ?? "unknown";
              origin = `local: ${file}`;
            } else {
              lang = cmd.split("/").pop() ?? cmd;
              origin = args.join(" ");
            }
          }

          console.log(`  ${icon} ${client.name}`);
          console.log(`     transport: ${client.transportType} │ lang: ${lang}`);
          console.log(`     origin:    ${origin}`);
          console.log(`     tools(${client.tools.length}): ${toolNames}\n`);
        }
        console.log(`  ⚡ built-in (${builtInSchemas.length}): GetCurrentTime, Read, ListDir`);
        console.log(`  ── total: ${builtInSchemas.length + mcpClients.reduce((s, c) => s + c.tools.length, 0)} tools\n`);
        console.log("--- END ---\n");
        askQuestion(); return;
      }
      if (trimmed === "/dump") {
      const toolSchemas = buildToolSchemas(mcpClients);
      const fullRequest = {
        model: "claude-sonnet-4-20250514",
        max_tokens: 2048,
        stream: true,
        system: systemPrompt,
        messages,
        tools: toolSchemas,
      };
      const json = JSON.stringify(fullRequest, null, 2);
      const approxTokens = Math.round(json.length / 4);
      console.log(`\n--- FULL API REQUEST (${json.length} chars, ~${approxTokens} tokens) ---`);
      console.log(json);
      console.log("--- END ---\n");
      askQuestion(); return;
    }
    if (trimmed === "/memories") {
        console.log(`\n--- MEMORY FILE (${MEMORY_FILE}) ---`);
        if (existsSync(MEMORY_FILE)) {
          console.log(readFileSync(MEMORY_FILE, "utf-8"));
        } else {
          console.log("  (no memories saved yet)");
        }
        console.log("--- END ---\n");
        askQuestion(); return;
      }

      await autoDetectMemories(trimmed, mcpClients);

      messages.push({ role: "user", content: trimmed });
      console.log("");

      try {
        await runAgenticTurn(messages, mcpClients, systemPrompt);
        await compactContext(messages);
      } catch (err) {
        console.error("\nError:", err);
        messages.pop();
      }

      askQuestion();
    });
  }

  askQuestion();
}

main().catch(async (err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
