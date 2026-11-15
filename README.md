# MCP Production Kit

> **The enterprise-ready, type-safe TypeScript starter kit for building Model Context Protocol (MCP) servers.**  
> Built for Claude Desktop, Cursor, Antigravity, and autonomous AI agent architectures.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-blue.svg)](https://www.typescriptlang.org/)
[![MCP Spec](https://img.shields.io/badge/MCP%20Spec-2024--11--05-green.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![A7mdMe/mcp-production-kit MCP server](https://glama.ai/mcp/servers/A7mdMe/mcp-production-kit/badges/score.svg)](https://glama.ai/mcp/servers/A7mdMe/mcp-production-kit)

---

## Free Core vs. Pro Pack Comparison

| Capability | Free Open-Source Core | Commercial Pro Pack ($19) |
| :--- | :---: | :---: |
| **MCP Spec Compliance** | Full (v2024-11-05 JSON-RPC 2.0) | Full (v2024-11-05 JSON-RPC 2.0) |
| **Local Stdio Transport** | Included (Claude / Cursor) | Included |
| **HTTP / SSE Streaming Transport** | Included (`npm run start:sse`) | Included |
| **Diagnostic Tool** | `get_system_metrics` (OS/Memory/Load) | Included |
| **Security Tool** | `secure_http_fetch` (SSRF Guard) | Included |
| **State Store Tool** | `agent_memory_store` (Namespaced KV + TTL) | Included |
| **Logging Pipeline** | Zero-leak stderr streaming | Zero-leak stderr streaming |
| **Glama Registry Listing** | Listed on Glama Registry | Listed on Glama Registry |
| **Edge Serverless Deployment** | - | **Cloudflare Workers template (global edge network)** |
| **Database Connector** | - | **PostgreSQL / Supabase with token & keyword mutation guards** |
| **Container Support** | Standard Dockerfile | **Production Docker Compose (Fly.io / Railway / AWS)** |
| **Commercial Distribution** | Free under MIT License | **Commercial License + Instant ZIP Download** |

---

## Why MCP Production Kit?

Most open-source MCP examples are proof-of-concepts: they demonstrate a toy tool over local `stdio`, but fail when faced with real-world deployments. 

**MCP Production Kit** solves the core engineering hurdles out of the box:
* **Dual Transport Architecture:** Run locally on `stdio` (for Claude Desktop / Cursor) or remotely over `HTTP / Server-Sent Events (SSE)` using a single codebase.
* **Zero-Leak Logging:** In `stdio` mode, `stdout` is strictly reserved for JSON-RPC protocol framing. Diagnostics are piped to `stderr` with automated secret redacting to prevent pipe corruption.
* **Hardened Security & SSRF Defense:** The built-in HTTP fetch tool blocks loopback addresses, private IPv4/IPv6 ranges, and cloud metadata endpoints (`169.254.169.254`).
* **In-Memory Agent Persistence:** Includes an isolated, namespaced key-value state store with configurable TTL for multi-step agent reasoning.
* **Production Observability:** Built-in OS telemetry, memory metrics, and `/health` monitoring endpoint.

---

## Architecture Overview

```
+-------------------------------------------------------------+
|                AI Agent (Claude / Cursor)                   |
+-------------------------------------------------------------+
                              |
                 JSON-RPC 2.0 / MCP Protocol
                              |
+-------------------------------------------------------------+
|                      Transport Layer                        |
|   +-----------------------+     +-----------------------+   |
|   |    stdio (Desktop)    |     |      HTTP / SSE       |   |
|   +-----------------------+     +-----------------------+   |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
|                    MCP Production Server                    |
|   +-----------------------+     +-----------------------+   |
|   |     Zod Validator     |     |  Safe Stderr Logger   |   |
|   +-----------------------+     +-----------------------+   |
|                                                             |
|   Built-in Core Tools:                                      |
|   - get_system_metrics                                      |
|   - secure_http_fetch (SSRF Guard)                          |
|   - agent_memory_store (Namespaced KV + TTL)                |
+-------------------------------------------------------------+
```

---

## Quickstart

### 1. Installation
```bash
git clone https://github.com/A7mdMe/mcp-production-kit.git
cd mcp-production-kit
npm install
npm run build
```

### 2. Run Verification Tests
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
        "/path/to/mcp-production-kit/dist/index.js",
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

### 5. Run via Docker
```bash
docker build -t mcp-production-kit .
docker run -p 3000:3000 -e TRANSPORT=sse mcp-production-kit
```

---

## Built-in Tools Specification

| Tool Name | Description | Security Controls |
|---|---|---|
| `get_system_metrics` | Real-time OS, CPU load, and heap memory breakdown. | Read-only introspection. |
| `secure_http_fetch` | Safe web scraping and API interaction. | Blocks private IPs, AWS metadata, caps payload at 512 KB, 10s timeout. |
| `agent_memory_store` | Multi-turn state management (`set`, `get`, `list`, `delete`). | Isolated namespaces and automatic TTL expiration. |

---

## Commercial Pro Pack ($19 One-Time)

For production cloud deployments, multi-agent frameworks, and enterprise teams, the **Pro Pack** provides drop-in, battle-tested extensions with 109 dedicated automated unit tests (123 total across the project):

* **Self-Healing Input Validator & RFC 9457 Formatter:** Coerces primitive strings emitted by LLMs (`"42"` -> `42`, `"true"` -> `true`, stringified JSON), replaces prose errors with structured RFC 9457 `structuredContent` and actionable missing/received argument diffs, preventing agents from burning reasoning loops.
* **Mid-Execution Auth Challenges & Token Revocation:** Intercepts upstream OAuth failures and revoked user grants inside tool handlers, emitting standard RFC 6750 `401 invalid_token` (re-authorize) and `403 insufficient_scope` (widen grant) challenges with `WWW-Authenticate` and RFC 9728 `resource_metadata`, prompting AI clients to prompt for re-authorization instead of swallowing failures into generic `{ isError: true }` text strings.
* **Host & Origin DNS Rebinding Protection Guard:** Strict host allowlisting, IPv6 bracket normalization, port mismatch blocking, cross-origin browser abuse filtering, and RFC-compliant JSON-RPC `-32600` (Invalid Request) error envelopes for HTTP and SSE transports.
* **Secret Redaction & Compliance Audit Logger:** Multi-pattern masking of API keys (`sk-`, `ghp_`, `whsec_`), Bearer JWTs, and database passwords in connection URIs; structured immutable NDJSON audit trails strictly on `stderr`.
* **Deterministic Tool Response Caching & Deduplication:** Canonical JSON argument hashing (SHA-256), monotonic generation tracking preventing stale overwrites, and thundering herd in-flight request coalescing.
* **RFC 6750 Bearer Authentication & Tool RBAC Guard:** Constant-time token verification (`crypto.timingSafeEqual`) and granular per-tool required scopes with standard JSON-RPC `-32003` (Forbidden) enforcement.
* **Request Cancellation & Deadline Timeout Manager:** `notifications/cancelled` support, downstream `AbortSignal` I/O propagation, and standardized JSON-RPC `-32800` (Cancelled) and `-32000` (Timeout) responses.
* **Token Bucket Rate Limiter & Cost Control:** In-memory token bucket + atomic PostgreSQL continuous-refill CTE query preventing runaway LLM retry loops, emitting JSON-RPC `-32029` with retry hints.
* **Hardened SQLite Read-Only Guardrails:** Connection URI `?mode=ro` enforcement, statement sanitization, blocking of vector operations (`ATTACH`, `DETACH`, `PRAGMA`, `VACUUM`), and `sqlite_master` schema introspection.
* **PostgreSQL / Supabase Safe Connector:** Read-only parameterized query tool with comment-stripping and 16 mutation keyword defenses.
* **Cloudflare Workers & Docker Compose:** Serverless edge hosting with streaming SSE, plus unprivileged non-root container deployment.

**[Get Pro Pack ($19.00 USD) — Instant Checkout on Whop](https://whop.com/checkout/plan_eiKHeRpooY3yc)**  
*(Delivery: Instant download of `mcp-pro-pack-v1.9.0.zip` via Whop Files and customer billing portal upon completion).*

---

## License
MIT © 2026 Antigravity Autonomous Lab
