# MCP Production Kit 🚀

> **The enterprise-ready, type-safe TypeScript starter kit for building Model Context Protocol (MCP) servers.**  
> Designed for Claude Desktop, Cursor, Antigravity, and autonomous AI agent architectures.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-blue.svg)](https://www.typescriptlang.org/)
[![MCP Spec](https://img.shields.io/badge/MCP%20Spec-2024--11--05-green.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![A7mdMe/mcp-production-kit MCP server](https://glama.ai/mcp/servers/A7mdMe/mcp-production-kit/badges/score.svg)](https://glama.ai/mcp/servers/A7mdMe/mcp-production-kit)

---

## ⚡ Why MCP Production Kit?

Most open-source MCP examples are toys: they demonstrate a simple `add(a, b)` function over local `stdio`, but fail when deployed to production. 

**MCP Production Kit** solves the core engineering hurdles out of the box:
* **Dual Transport Architecture:** Run locally on `stdio` (for Claude Desktop / Cursor) OR remotely over `HTTP / Server-Sent Events (SSE)` using a single codebase.
* **Zero-Leak Logging:** In `stdio` mode, `stdout` is strictly reserved for JSON-RPC message framing. Our structured logger routes all diagnostics to `stderr` with automated secret redacting to prevent pipe corruption.
* **Hardened Security & SSRF Defense:** The built-in HTTP fetch tool blocks loopback, private IPv4/IPv6 ranges, and cloud metadata endpoints (`169.254.169.254`).
* **In-Memory Agent Persistence:** Includes an isolated, namespaced key-value state store with configurable TTL for multi-step agent reasoning.
* **Production Observability:** Built-in OS telemetry, memory metrics, and `/health` monitoring.

---

## 🏗️ Architecture

```
                 ┌──────────────────────────────────────────────┐
                 │          AI Agent (Claude / Cursor)          │
                 └──────────────────────┬───────────────────────┘
                                        │
                         JSON-RPC 2.0 / MCP Protocol
                                        │
                ┌───────────────────────┴───────────────────────┐
                │               Transport Layer                 │
                │   ┌───────────────────┐   ┌───────────────┐   │
                │   │  stdio (Desktop)  │   │  HTTP / SSE   │   │
                │   └───────────────────┘   └───────────────┘   │
                └───────────────────────┬───────────────────────┘
                                        │
                ┌───────────────────────┴───────────────────────┐
                │             MCP Production Server             │
                │   ┌───────────────┐   ┌───────────────────┐   │
                │   │ Zod Validator │   │ Safe Stderr Logger│   │
                │   └───────────────┘   └───────────────────┘   │
                ├───────────────────────────────────────────────┤
                │                Built-in Tools                 │
                │  • get_system_metrics                         │
                │  • secure_http_fetch (SSRF Guard)             │
                │  • agent_memory_store (Namespaced KV + TTL)   │
                └───────────────────────────────────────────────┘
```

---

## 🚀 Quickstart

### 1. Installation
```bash
git clone https://github.com/your-username/mcp-production-kit.git
cd mcp-production-kit
npm install
npm run build
```

### 2. Run Tests
```bash
npm test
```

### 3. Connect to Claude Desktop
Add this to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "production-kit": {
      "command": "node",
      "args": [
        "/absolute/path/to/mcp-production-kit/dist/index.js",
        "--transport=stdio"
      ]
    }
  }
}
```

### 4. Run as Remote HTTP/SSE Server
```bash
npm run start:sse
# Listening on http://localhost:3000
# Healthcheck: http://localhost:3000/health
# SSE Stream: http://localhost:3000/sse
```

---

## 🛠️ Built-in Tools

| Tool Name | Description | Security Controls |
|---|---|---|
| `get_system_metrics` | Real-time OS, CPU load, and heap memory breakdown. | Read-only introspection. |
| `secure_http_fetch` | Safe web scraping and API interaction. | Blocks private IPs, AWS metadata, caps payload at 512 KB, 10s timeout. |
| `agent_memory_store` | Multi-turn state management (`set`, `get`, `list`, `delete`). | Isolated namespaces and automatic TTL expiration. |

---

## 📦 Pro Pack Upgrade ($19 One-Time)

For production cloud deployments and enterprise teams, the **Pro Pack** provides ready-to-deploy extensions:
* **Cloudflare Workers Serverless Template:** Deploy directly to Cloudflare's edge network with Bearer Token authentication and native streaming.
* **PostgreSQL / Supabase Connector:** Read-only schema introspection and parameterized SQL queries with mutation defenses.
* **Production Dockerfile & Compose:** Multi-stage distroless container with non-root security and healthcheck polling.

👉 **[Get Pro Pack ($19.00 USD) — Instant Checkout on Whop](https://whop.com/checkout/plan_eiKHeRpooY3yc)**  
*(Also viewable at [Whop Storefront](https://whop.com/github-67b8/mcp-production-kit-pro-pack))*

---

## 📄 License
MIT © 2026 Antigravity Autonomous Lab
