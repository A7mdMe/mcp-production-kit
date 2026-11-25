# MCP Production Kit

> **The enterprise-ready, type-safe TypeScript starter kit for building Model Context Protocol (MCP) servers.**  
> Built for Claude Desktop, Cursor, Antigravity, and autonomous AI agent architectures.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-blue.svg)](https://www.typescriptlang.org/)
[![MCP Spec](https://img.shields.io/badge/MCP%20Spec-2024--11--05-green.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![A7mdMe/mcp-production-kit MCP server](https://glama.ai/mcp/servers/A7mdMe/mcp-production-kit/badges/score.svg)](https://glama.ai/mcp/servers/A7mdMe/mcp-production-kit)
[![MCP Production Hardened](https://img.shields.io/badge/MCP-Production_Hardened-2ea44f?logo=github)](https://github.com/A7mdMe/mcp-production-kit)

---


> 🛡️ **Looking for production security best practices?**  
> Check out the **[Production MCP Server Hardening & Security Checklist](MCP_PRODUCTION_HARDENING_CHECKLIST.md)** covering 33 architectural vulnerabilities, protocol edge cases, and reliability failure modes discovered in production MCP deployments.

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
| **JSON-RPC Dispatching** | Standard Dispatcher | **O(1) Fast-Path Classifier bypassing union walks** |
| **64-Bit Integer Codec** | IEEE 754 Number | **Lossless BigInt & Raw JSON Token Reviver** |
| **HTTP Stream & Slowloris Guard** | - | **Arrival deadlines (408), byte limits (413), instant SSE teardown** |
| **Filesystem & Traversal Guard** | - | **Boundary containment, prefix-bypass defense, atomic writes** |
| **SSE Reconnect & Teardown Guard** | - | **Immediate close on handshake failure, bounds retry backoff** |
| **Stdio Lifecycle & Epoch Fence** | - | **Monotonic epoch fence, eliminates Connection closed races & reaps orphans** |
| **Client Session Invariants** | - | **Fail-closed discovery on closed client, prevents hallucinated empty tools** |
| **Subscription Router Guard** | - | **Zero-slot graceful completion for unadvertised filters, prevents DoS** |
| **Resilient Subprocess Execution Guard** | - | **Progress-aware heartbeat timeouts, load scaling & graceful fallback extractors (#5658)** |
| **Metadata Integrity Pinning Guard** | - | **Trust-On-First-Use (TOFU) cryptographic fingerprinting & prompt-injection defense (#3907)** |
| **Graph Memory & Idempotency Guard** | - | **Explicit skipped relation feedback (#5654), observation deduplication parity (#5653), idempotent deletes (#5655)** |
| **Monorepo Workspace Reconciler** | - | **Bi-directional manifest sync & v1/v2 skew auditing (#3230)** |
| **Stdio Lifecycle Sentinel** | - | **Trapped onclose descriptor & delayed-exit isolation on retries (#3194)** |
| **Resilient Stdio Framing** | - | **Lone surrogate sanitization & fail-safe -32700 ID recovery (#3894)** |
| **Non-Finite Float & Schema Guard** | - | **NaN/+Inf/-Inf sanitization & outputSchema nullable union adaptation (#3897)** |
| **Hardened Environment & Limits** | - | **Fail-closed parsing, unit multipliers (KB/MB/ms/s), NaN defense (#5642)** |
| **Unicode Normalization & Identity** | - | **NFC/NFD twin reconciliation, NUL-byte sanitization & ZWJ preservation (#5643)** |
| **Memory Invariant & Graph Guard** | - | **Exact/trimmed relation deletes, case collision auto-heal, count sync (#5645)** |
| **RFC 6570 URI Template Guard** | - | **Tolerates empty expressions without crashes (#3221); RFC 6570 §3.2.1 encoding (#3219)** |
| **Persistent Symlink Guard** | - | **Preserves PV symlinks during atomic renames (#5644); redacts DB credentials (#5646)** |
| **SSE Stream Priming Guard** | - | **Immediate t=0 event ID priming & gapless Last-Event-ID replay for GET streams (#3211)** |
| **OAuth Token Revocation Guard** | - | **RFC 7009 revocation, RFC 7662 introspection & OIDC metadata preservation (#3213)** |
| **Intermediate Elicitation Guard** | - | **Bypasses outputSchema crash on input_required (#3216); sanitizes CLI refs (#5641)** |
| **Polymorphic Argument Guard** | - | **Preserves string "null" & JSON-in-string for union schemas (#3055, #5176)** |
| **Memory Quarantine Guard** | - | **Corrupted record isolation, auto-repair & quarantine ledger (#5609)** |
| **Container Lifecycle Guard** | - | **Universal PID 1 signals, drain hooks & probes (#5611)** |
| **File Lock & Memory Guard** | - | **Atomic ABA race-free stale lock clearing & PID liveness (#5624)** |
| **Stream Resumption Guard** | - | **Fail-fast on premature close (#3210); -32022/-32021 checks (#3179, #3202)** |
| **OAuth Issuer Guard** | - | **Template-aware Entra ID matching, WHATWG percent-decoding & IdP security** |
| **HTTP Body Normalizer** | - | **Bypasses JSON parsing on bodyless requests, fixes 400 Invalid JSON** |
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


### 4. Connect to Cursor
Add this to your `.cursor/mcp.json` or Workspace MCP Settings:
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

### 5. Run as Remote HTTP/SSE Server
```bash
npm run start:sse
# Listening on http://localhost:3000
# Healthcheck: http://localhost:3000/health
# SSE Stream: http://localhost:3000/sse
```

### 6. Run via Docker
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

For production cloud deployments, multi-agent frameworks, and enterprise teams, the **Pro Pack** provides drop-in, battle-tested extensions with 354 dedicated automated unit tests (362 total across the project):

* **Monorepo Workspace Manifest Reconciler & Migration Guard:** Eliminates broken builds and half-migrated split-brain configurations during MCP v1-to-v2 migrations in monorepos (pnpm, npm/yarn workspaces, Lerna) (resolving typescript-sdk #3230). Automatically discovers all workspace member packages, bi-directionally maps rewritten TypeScript source files to their enclosing `package.json`, performs atomic dependency swaps (`@modelcontextprotocol/sdk` to `@modelcontextprotocol/client` and `@modelcontextprotocol/server`), preserves formatting and indentation, and audits trees for version skew.
* **Stdio Connection Lifecycle Sentinel & Transport Isolation Guard:** Eliminates `Connection closed` race conditions when retrying `client.connect()` on the same Client instance after failed handshakes or with stubborn child processes (resolving typescript-sdk #3194, #3198). Uses `Object.defineProperty` property descriptor traps to prevent the SDK from overwriting lifecycle guards, actively disarms event listeners on dying subprocesses to neutralize late SIGTERM/SIGKILL exit signals, and enforces monotonic generation barriers.
* **Resilient Stdio Line Framing & Lone Surrogate Guard:** Eliminates 30s-60s client timeout freezes caused by unparseable JSON lines or lone UTF-16 surrogate escapes (`\ud83d`) dropped by standard stdio readers (resolving python-sdk #3894). Pre-sanitizes isolated surrogates to `\uFFFD` without corrupting valid emoji pairs, extracts the client request ID from malformed payloads via regex fast-scan, and immediately emits a standard JSON-RPC `-32700 Parse error` response carrying the client ID to unblock callers in 0ms.
* **Non-Finite Float Sanitizer & Schema-Safe Coercion Guard:** Eliminates client-side crashes and schema validation exceptions caused by mathematical, ML, and statistical tools returning non-finite floats (NaN, +Infinity, -Infinity) (resolving python-sdk #3897, #3341). Features deep object and array traversal, configurable sanitization (null substitution, token preservation, boundary clamping, and structured tool-error envelopes), and automated outputSchema patching to allow nullable number unions without breaking client runners.
* **Hardened Environment Variable Parser & Resource Limit Guard:** Eliminates silent security limit bypass caused by NaN relational comparisons in MCP servers (servers #5642). Safely parses environment limits with intuitive unit multipliers (KB, MB, GB, ms, s, m, h), enforces strict fail-closed boundary clamping, audits configuration on startup, and monitors streaming data against byte ceilings.
* **Unicode Normalization, NUL-Byte Sanitization & Byte-Identity Guard:** Eliminates cross-platform memory corruption, Unicode normalization twins (NFC vs NFD), and NUL-byte truncation in MCP memory servers (servers #5643). Automatically canonicalizes entity names across macOS and Linux/Windows environments, merges split-brain normalization variants, and preserves multi-codepoint Zero-Width Joiner (ZWJ) emoji sequences byte-for-byte.
* **Knowledge Graph Memory Invariant, Case Normalizer & Exact-Match Sanitization Guard:** Resolves memory graph corruption and zombie relations in MCP memory servers (servers #5645). Provides configurable exact-match vs whitespace-trimmed relation deletions, audits and auto-heals case collisions across entity names, and ensures observationCount metadata is atomically synchronized across overview queries.
* **RFC 6570 URI Template Normalizer & Resource Routing Guard:** Eliminates unhandled TypeError crashes on empty expressions during MCP resource routing and template resolution (typescript-sdk #3221). Implements strict RFC 6570 §3.2.1 percent-encoding for non-reserved operators, coalesces adjacent literal slices, and provides safe, structured pattern matching without crashing server sessions or leaking JSON-RPC -32603 internal errors (typescript-sdk #3219).
* **Persistent Symlink Resolution, Atomic Staging & Error Sanitization Guard:** Eliminates broken symlinks and silent persistent volume desync incidents during atomic renames (servers #5644). Automatically resolves physical target paths to write through symlinks without unlinking them, handles EXDEV cross-device container volume errors, and performs deep error credential sanitization to prevent leaking database passwords or Bearer tokens in failure outputs (servers #5646).
* **Standalone SSE Stream Priming, Resumption & Gapless Replay Guard:** Eliminates silent notification loss on standalone GET SSE streams during proxy timeouts and connection rotations (typescript-sdk #3211). Automatically writes an initial spec-compliant priming frame (id: <streamId>_1, retry: <interval>) at t=0 so clients always retain a resumption ID, filters priming frames from application data, and performs gapless event replay upon reconnection with Last-Event-ID.
* **OIDC / OAuth Token Revocation, Introspection & Discovery Metadata Guard:** Eliminates zombie token persistence and authorization leaks by preserving RFC 7009 revocation_endpoint and RFC 7662 introspection_endpoint during OpenID Connect discovery (typescript-sdk #3213). Includes automated token lifecycle management with client_secret_basic and client_secret_post support to ensure tokens are actively revoked on IdPs (Cognito, Okta, Keycloak) when clients log out.
* **Intermediate Elicitation & Clean Ref Output Guard:** Resolves premature outputSchema validation crashes when tools return intermediate human-in-the-loop elicitation requests (resultType: input_required, typescript-sdk #3216). Manages cryptographic requestState nonces and TTL deadlines, and provides deterministic ref sanitization that strips CLI markers (* main, + feature), ANSI escapes, and quotes to prevent downstream tool chaining failures (servers #5641).
* **Polymorphic Argument & Nullable String Preservation Guard:** Prevents silent argument corruption and premature JSON parsing across MCP tool arguments (python-sdk #3055, servers #5176). Features union-aware schema traversal (anyOf, oneOf, type arrays) that automatically preserves stringified JSON and literal "null" parameters for nullable string annotations, enables safe fallback deserialization for strictly collection schemas, and preserves underlying error causes and stderr diagnostic tails for subprocess failures (servers #5636).
* **Knowledge Graph Quarantine & Memory Remediation Guard:** Eliminates unrecoverable memory file bloat and quota exhaustion caused by corrupted or malformed lines perpetually preserved on save (servers #5609). Features self-healing schema normalization (missing entityType, non-string observations), automatic segregation of unparseable lines into an isolated quarantine ledger (<memory>.quarantine.jsonl), and dedicated tools for autonomous inspection, repair, and purging.
* **Container & Process Lifecycle Guard:** Eliminates Docker container 10-second stop timeouts (exit 137) by installing universal PID 1 SIGTERM and SIGINT listeners across both stdio and HTTP/SSE transports (servers #5611). Coordinates graceful drain hooks with bounded deadlines, provides container orchestrator readiness probes (/readyz 503 during drain), and bundles a hardened non-root tini Alpine Dockerfile template.
* **Cross-Process Resilient File & Memory Lock Guard:** Eliminates critical ABA race conditions where concurrent stale-lock breakers inadvertently delete newly acquired live guards in shared agent memories and file-based state stores (servers #5624). Features atomic rename-aside staging, inode/device handle pinning, monotonic generation tokens, and cross-platform PID liveness detection to break deadlocks safely.
* **Stream Resumption, Truncation & Protocol Negotiation Guard:** Eliminates 30s-60s agent hangs by instantly aborting pending requests with `ConnectionClosed` when Streamable HTTP per-request SSE streams close prematurely (typescript-sdk #3210). Validates resumption token endpoints against terminal HTTP 405/404/410/403 rejections, intercepts unsupported protocol versions on pinned stdio connections with standard JSON-RPC -32022 errors (#3179, #3206), and enforces client capability preconditions with JSON-RPC -32021 errors (#3202).
* **Enterprise OAuth Issuer & Multi-Tenant Authority Guard:** Resolves Microsoft Entra ID `{tenantid}` template mismatch rejections on `/organizations/v2.0` and `/common/v2.0` endpoints without compromising security (typescript-sdk #3207). Features WHATWG URL percent-decoding normalization (`%7Btenantid%7D`), strict protocol/host/port pinning confined to approved authority domains, token issuer claim verification, and pluggable discovery hooks without disabling RFC 9207 mix-up attack protections.
* **HTTP Transport & Body Parsing Normalizer:** Resolves plain-text 400 Invalid JSON crashes on bodyless GET, DELETE, HEAD, and OPTIONS requests carrying default Content-Type headers (typescript-sdk #3201). Leaves empty bodies unparsed so downstream SSE streams, session terminators, and CORS preflights execute cleanly, and emits structured JSON-RPC -32700 Parse Error envelopes on malformed POST payloads.
* **Resilient Subscription Router & Capacity Guard:** Resolves subscription slot exhaustion and capacity Denial-of-Service (-32603) on stdio transports (typescript-sdk #3199). Immediately emits SubscriptionsListenResult (resultType: 'complete') for unadvertised filters in 0ms, releasing slots instantaneously and preventing client-side subscription.closed promise hangs.
* **Client Session & Fail-Closed Capability Invariants:** Resolves the silent empty array resolution bug on closed clients (typescript-sdk #3195). Enforces strict fail-closed connection checks before evaluating capabilities or response caches, preventing AI agents from hallucinating tool absence when servers disconnect, and provides auto-reconnection recovery sentinels.
* **Stdio Lifecycle & Monotonic Epoch Fence:** Resolves transport collision race conditions and "Connection closed" errors during handshake retries (typescript-sdk #3194). Enforces monotonic connection epochs, intercepts and suppresses delayed onclose/onerror events from previous child processes before they can corrupt active client state, guarantees transport.close() is awaited before rethrow, and cross-platform process tree reaping via taskkill (Windows) and process-group SIGKILL (POSIX).
* **Resilient SSE Reconnect & Handshake Teardown Guard:** Prevents client-side zombie connection leaks and background reconnect storms when connecting to MCP servers over SSE (typescript-sdk #3193). Guarantees immediate .close() execution on handshake rejection, bounds reconnection attempts with jittered exponential backoff, halts retries on terminal HTTP errors (401, 403, 404), and unrefs internal timers to guarantee clean process exit.
* **Filesystem Containment & Path Traversal Guard:** Strictly bounds LLM-generated file writes to designated workspace roots via strict `path.relative` containment, eliminates sibling directory prefix-bypass vulnerabilities (typescript-sdk #3191), blocks Windows DOS device names (`CON`/`NUL`/`AUX`) and null bytes, prevents symlink escapes, and performs atomic file writes via temporary files.
* **HTTP & SSE Stream Lifecycle Guard & Slowloris Defense:** Enforces streaming body arrival deadlines (408) and byte size ceilings (413) on incoming HTTP POST requests (typescript-sdk #3131), and instantly cancels idle stream reader locks on client socket disconnects, clearing session registrations in <2ms and eliminating 409 Conflict reconnect lockouts (typescript-sdk #3148).
* **Zero-Overhead JSON-RPC Message Classifier & Fast-Path Dispatcher:** Eliminates redundant Zod union schema walks and backtracking bottlenecks on high-throughput transports (typescript-sdk #3189 & #3190) via $O(1)$ envelope key discrimination, supporting single and batch RPC payloads with microsecond dispatching.
* **Lossless 64-Bit Integer & BigInt Codec:** Prevents precision corruption on 64-bit integers (PostgreSQL `BIGINT`, Discord/Twitter Snowflakes, nanosecond timestamps, micro-units) exceeding `Number.MAX_SAFE_INTEGER` (`9,007,199,254,740,991`), eliminates `TypeError: Do not know how to serialize a BigInt` in tool responses, and guarantees bit-for-bit round-trip fidelity.
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
*(Delivery: Instant download of `mcp-pro-pack-v3.16.0.zip` via Whop Files and customer billing portal upon completion).*

---

## License
MIT © 2026 Antigravity Autonomous Lab
