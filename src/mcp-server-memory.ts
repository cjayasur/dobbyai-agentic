// MCP Memory Server — persists knowledge across sessions
//
// A simple key-value memory server that saves facts to a JSON file.
// The agent can save, recall, list, and forget memories.
// Memories survive between sessions because they're written to disk.
//
// Transport: stdio (spawned as child process by the agent)
// Storage: ~/.claude-code-simple/memories.json
//
// This is a simplified version of what Claude Code uses for persistent memory.
// Claude Code's @modelcontextprotocol/server-memory uses a knowledge graph;
// ours uses a flat key-value store for simplicity.
//
// Run standalone:  bun run src/mcp-server-memory.ts
// (reads JSON-RPC from stdin, writes to stdout — same as any MCP server)

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";

// ─── Storage ────────────────────────────────────────────────────

const MEMORY_DIR = join(homedir(), ".claude-code-simple");
const MEMORY_FILE = join(MEMORY_DIR, "memories.json");

type MemoryEntry = {
  key: string;
  value: string;
  created: string;
  updated: string;
};

type MemoryStore = Record<string, MemoryEntry>;

function loadMemories(): MemoryStore {
  if (!existsSync(MEMORY_FILE)) return {};
  try {
    return JSON.parse(readFileSync(MEMORY_FILE, "utf-8"));
  } catch {
    return {};
  }
}

function saveMemories(store: MemoryStore): void {
  if (!existsSync(MEMORY_DIR)) {
    mkdirSync(MEMORY_DIR, { recursive: true });
  }
  writeFileSync(MEMORY_FILE, JSON.stringify(store, null, 2));
}

// ─── MCP Server ─────────────────────────────────────────────────

const server = new Server(
  { name: "memory-server", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "save_memory",
      description: "Save a fact or piece of information for later recall. Use this when the user says 'remember this' or when you learn something important about the user, project, or preferences.",
      inputSchema: {
        type: "object",
        properties: {
          key: {
            type: "string",
            description: "A short label for this memory (e.g. 'user_name', 'project_language', 'preferred_style')",
          },
          value: {
            type: "string",
            description: "The fact or information to remember",
          },
        },
        required: ["key", "value"],
      },
    },
    {
      name: "recall_memory",
      description: "Recall a previously saved memory by its key. Use this when you need to look up something that was saved earlier.",
      inputSchema: {
        type: "object",
        properties: {
          key: {
            type: "string",
            description: "The key of the memory to recall",
          },
        },
        required: ["key"],
      },
    },
    {
      name: "search_memories",
      description: "Search all memories for a keyword. Returns all memories whose key or value contains the search term.",
      inputSchema: {
        type: "object",
        properties: {
          query: {
            type: "string",
            description: "The search term to look for in memory keys and values",
          },
        },
        required: ["query"],
      },
    },
    {
      name: "list_memories",
      description: "List all saved memories. Returns keys and values of everything currently remembered.",
      inputSchema: {
        type: "object",
        properties: {},
      },
    },
    {
      name: "forget_memory",
      description: "Delete a previously saved memory by its key. Use when the user asks you to forget something.",
      inputSchema: {
        type: "object",
        properties: {
          key: {
            type: "string",
            description: "The key of the memory to forget",
          },
        },
        required: ["key"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const store = loadMemories();

  switch (name) {
    case "save_memory": {
      const key = args!.key as string;
      const value = args!.value as string;
      const now = new Date().toISOString();
      const existing = store[key];

      // If the value is the same, don't update — tell the LLM it's already saved.
      // This prevents the agentic loop from saving the same thing repeatedly.
      if (existing && existing.value === value) {
        return {
          content: [{
            type: "text",
            text: `Memory "${key}" already contains this exact value. No update needed.`,
          }],
        };
      }

      store[key] = {
        key,
        value,
        created: existing?.created ?? now,
        updated: now,
      };
      saveMemories(store);
      return {
        content: [{
          type: "text",
          text: existing
            ? `Updated memory "${key}" (previously: "${existing.value}")`
            : `Saved memory "${key}": "${value}"`,
        }],
      };
    }

    case "recall_memory": {
      const key = args!.key as string;
      const entry = store[key];
      if (!entry) {
        return {
          content: [{ type: "text", text: `No memory found for key "${key}"` }],
        };
      }
      return {
        content: [{
          type: "text",
          text: `${entry.key}: ${entry.value}\n(saved: ${entry.created}, updated: ${entry.updated})`,
        }],
      };
    }

    case "search_memories": {
      const query = (args!.query as string).toLowerCase();
      const matches = Object.values(store).filter(
        e => e.key.toLowerCase().includes(query) || e.value.toLowerCase().includes(query)
      );
      if (matches.length === 0) {
        return {
          content: [{ type: "text", text: `No memories matching "${args!.query}"` }],
        };
      }
      const lines = matches.map(e => `  ${e.key}: ${e.value}`);
      return {
        content: [{ type: "text", text: `Found ${matches.length} memories:\n${lines.join("\n")}` }],
      };
    }

    case "list_memories": {
      const entries = Object.values(store);
      if (entries.length === 0) {
        return {
          content: [{ type: "text", text: "No memories saved yet." }],
        };
      }
      const lines = entries.map(e => `  ${e.key}: ${e.value}`);
      return {
        content: [{
          type: "text",
          text: `${entries.length} memories:\n${lines.join("\n")}`,
        }],
      };
    }

    case "forget_memory": {
      const key = args!.key as string;
      if (!store[key]) {
        return {
          content: [{ type: "text", text: `No memory found for key "${key}"` }],
        };
      }
      const old = store[key].value;
      delete store[key];
      saveMemories(store);
      return {
        content: [{ type: "text", text: `Forgot memory "${key}" (was: "${old}")` }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
});

// ─── Start ──────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Server is now running — reads JSON-RPC from stdin, writes to stdout.
  // stderr is free for logging:
  console.error("Memory MCP server running on stdio");
  console.error(`Storage: ${MEMORY_FILE}`);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
