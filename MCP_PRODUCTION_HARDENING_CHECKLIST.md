# Production MCP Server Hardening & Security Checklist

> **A comprehensive reference checklist of 33 architectural vulnerabilities, protocol edge cases, and reliability failure modes discovered in production Model Context Protocol (MCP) servers—and how to fix them.**

Whether you are building MCP servers in TypeScript, Python, or Go for Claude Desktop, Cursor, Cline, or enterprise autonomous multi-agent pipelines, this checklist covers the critical vulnerabilities and edge cases you must guard against before going to production.

---

## Quick Navigation

1. [Transport & Protocol Isolation](#1-transport--protocol-isolation)
2. [Input Validation & Injection Defense](#2-input-validation--injection-defense)
3. [Filesystem & Volume Persistence](#3-filesystem--volume-persistence)
4. [Authentication & Authorization (OAuth / RBAC)](#4-authentication--authorization-oauth--rbac)
5. [State, Memory & Knowledge Graphs](#5-state-memory--knowledge-graphs)
6. [Streaming, Lifecycle & Process Stability](#6-streaming-lifecycle--process-stability)

---

## 1. Transport & Protocol Isolation

- [ ] **1. Stdio Framing & Stderr Stream Leakage**:
  - *Risk*: `console.log()` statements emit raw diagnostic text into `stdout`. The MCP client attempts to parse this text as JSON-RPC, corrupts the framing boundary, and drops the connection.
  - *Remedy*: Intercept all application logging and route stdout strictly to JSON-RPC serialization; redirect all operational logs, debug traces, and library outputs exclusively to `stderr`.

- [ ] **2. Fast-Path RPC Classification without Redundant Zod Walks**:
  - *Risk*: Inspecting each inbound JSON-RPC message through 4+ sequential schema unions consumes up to 7% of server CPU under concurrent load (typescript-sdk #3189).
  - *Remedy*: Classify messages in $O(1)$ by discriminating top-level key presence (`method` + `id` = Request; `method` without `id` = Notification; `result` / `error` = Response) before applying targeted schema validation.

- [ ] **3. Empty-Body HTTP / SSE Request Handling**:
  - *Risk*: Clients sending `Content-Type: application/json` on `GET`, `HEAD`, `DELETE`, or empty-payload POST requests cause JSON body parsers to throw raw HTTP 400 Bad Request errors (typescript-sdk #3201).
  - *Remedy*: Normalize incoming HTTP requests to bypass JSON decoding when content-length is 0 or HTTP method semantics do not require request bodies.

- [ ] **4. Stale Stdio Process Reaper & Orphan Prevention**:
  - *Risk*: When a host client disconnects or crashes without signaling EOF, lingering MCP server subprocesses continue consuming host memory and CPU (typescript-sdk #3194, #3195).
  - *Remedy*: Implement an idle timeout watchdog and parent-process liveness probes to gracefully terminate orphaned child processes.

---

- [ ] **5. Fail-Safe Stdio Request ID Recovery & Lone Surrogate Defense**:
  - *Risk*: A request line that fails JSON validation (e.g. lone UTF-16 surrogate escapes like `\ud83d`) is dropped by standard stdio readers without emitting any reply to stdout. The client hangs until its 30s-60s timeout expires (python-sdk #3894).
  - *Remedy*: Pre-sanitize isolated surrogates to `\uFFFD`, extract the client's request ID from malformed lines via regex fast-scan, and immediately emit a spec-compliant JSON-RPC `-32700 Parse error` envelope to unblock the client instantly.

- [ ] **6. Property-Trapped Transport Lifecycle Sentinel & Delayed Exit Isolation**:
  - *Risk*: A failed handshake leaves `client.transport` set; retrying on the same Client causes the first child's delayed exit to trigger `onclose` on the new connection, rejecting it with `Connection closed` (typescript-sdk #3194).
  - *Remedy*: Trap `transport.onclose` via `Object.defineProperty` so SDK reassignments cannot overwrite generation guards, disarm all listeners on dying subprocesses, and reset `client.transport` before retrying.

- [ ] **7. Monorepo Workspace Manifest Reconciliation & Half-Migration Defense**:
  - *Risk*: v1-to-v2 codemods rewrite workspace member source files to v2 imports without updating member `package.json` manifests, causing broken builds and split-brain dependency skew despite exiting with code 0 (typescript-sdk #3230).
  - *Remedy*: Atomically map rewritten files to member manifests, swap v1 SDK for v2 packages across all workspace packages, preserve formatting, and fail CI if any member manifest is left un-synchronized.

## 2. Input Validation & Injection Defense

- [ ] **5. Server-Side Request Forgery (SSRF) Blocklist**:
  - *Risk*: LLMs instructed to fetch arbitrary URLs can target cloud metadata endpoints (`169.254.169.254`), container interfaces, or loopback services (`localhost`, `127.0.0.1`).
  - *Remedy*: Resolve DNS synchronously before connection, validate IP ranges, and block private, link-local, loopback, and non-HTTP protocols.

- [ ] **6. DNS Rebinding Protection via Host Header Verification**:
  - *Risk*: Malicious websites visited by the user can make cross-origin requests to local HTTP/SSE MCP ports if the `Host` header is not strictly validated.
  - *Remedy*: Whitelist acceptable `Host` headers (`localhost`, `127.0.0.1`, explicit domain) and reject unknown hosts with HTTP 403 Forbidden.

- [ ] **7. SQL Mutation Guardrails for LLM Database Connectors**:
  - *Risk*: Read-only database tools can be exploited by prompt injection into running `DROP TABLE`, `DELETE`, or stacked queries with semicolons.
  - *Remedy*: Enforce connection-level read-only flags (e.g. `?mode=ro` in SQLite, read-only transactions in PostgreSQL) combined with query AST / token boundary validation to block comment evasions (`-- DROP TABLE`) and write operations.

- [ ] **8. 64-Bit Integer Lossless Codec**:
  - *Risk*: Database IDs, timestamps, and snow-flake IDs exceeding JavaScript's `Number.MAX_SAFE_INTEGER` ($2^{53} - 1$) silently truncate and corrupt in standard JSON serialization.
  - *Remedy*: Use a lossless JSON reviver and serializer that preserves 64-bit integers as `BigInt` or unquoted string tokens.

- [ ] **9. Polymorphic Argument & Nullable String Preservation**:
  - *Risk*: LLMs frequently pass literal string `"null"` or JSON-stringified payloads for union parameters (`str | null`), causing schema validators to reject valid inputs (servers #5176, python-sdk #3055).
  - *Remedy*: Implement schema-aware argument normalization that distinguishes between string `"null"` and `null`, preserving intended payloads.

---

- [ ] **10. Fail-Closed Environment Variable & Resource Limit Parsing**:
  - *Risk*: Naive `Number(process.env.VAR)` evaluates to `NaN` when operators configure limits with unit suffixes (`10MB`, `500KB`, `30s`) or non-numeric strings. Because relational comparisons against `NaN` (`size > NaN`) always evaluate to `false`, **THE RESOURCE LIMIT IS SILENTLY DISABLED**, allowing unbounded payload fetches that trigger OOM crashes (servers #5642).
  - *Remedy*: Parse byte sizes and durations safely with unit multiplier support (`KB`, `MB`, `GB`, `ms`, `s`, `m`), clamp values within safe minimum/maximum bounds, and strictly fail-closed back to secure defaults if parsing fails.

- [ ] **11. Non-Finite Float (NaN / Infinity) Schema Serialization & Client Crash Defense**:
  - *Risk*: Math, ML, and statistical tools returning `NaN` or `Infinity` (e.g. AUC on single-class splits, zero division) convert to `null` in JSON. Clients validating against `"type": "number"` throw unhandled runtime exceptions, losing the entire tool response (python-sdk #3897, #3341).
  - *Remedy*: Deeply sanitize non-finite floats into compliant nulls or string tokens (`"NaN"`, `"Infinity"`), provide structured tool errors on invalid calculations, and patch output schemas to permit nullable number unions.

## 3. Filesystem & Volume Persistence

- [ ] **10. Strict Path Containment & Device Traversal Guards**:
  - *Risk*: LLMs generating file paths with `../`, sibling prefixes (`/workspace-secret`), null bytes, or Windows reserved device names (`CON`, `PRN`, `AUX`) can escape the target root (typescript-sdk #3191).
  - *Remedy*: Canonicalize paths using `realpath`, verify strict boundary containment via `path.relative`, and sanitize DOS device names.

- [ ] **11. Atomic Rename Symlink & Persistent Volume Preservation**:
  - *Risk*: When atomic writes execute `fs.rename(temp, target)` onto a symlinked file (e.g., Docker mounts, Kubernetes PersistentVolumes), the symlink is severed and replaced with a local regular file. Backups and external storage silently freeze (servers #5644).
  - *Remedy*: Resolve the physical realpath target before staging, create the temporary file in the target's physical directory, and rename onto the canonical destination.

- [ ] **12. Error Output Secret Redaction**:
  - *Risk*: Upstream failure outputs and stack traces routinely leak database connection strings (`postgres://user:pass@host`), Bearer tokens, and API keys directly into LLM context (servers #5646).
  - *Remedy*: Sanitize all outgoing JSON-RPC error messages and tool responses with regex masks redacting credentials, authorization headers, and API keys.

---

## 4. Authentication & Authorization (OAuth / RBAC)

- [ ] **13. Strict Separation of 401 Invalid Token vs 403 Insufficient Scope**:
  - *Risk*: Emitting 403 when a token is revoked causes clients to repeatedly attempt to widen scopes instead of re-authenticating (typescript-sdk #3173).
  - *Remedy*: Return RFC 6750 HTTP 401 `invalid_token` (with no scopes) when a grant is revoked; return HTTP 403 `insufficient_scope` (with required scopes) only when incremental consent is needed.

- [ ] **14. OIDC Token Revocation & Introspection Endpoint Preservation**:
  - *Risk*: Zod schemas that strip undeclared fields discard `revocation_endpoint` and `introspection_endpoint` during OpenID discovery, leaving clients unable to revoke tokens on logout (typescript-sdk #3213).
  - *Remedy*: Preserve RFC 7009 revocation and RFC 7662 introspection endpoints in OIDC discovery metadata schemas.

- [ ] **15. Tool-Level Role-Based Access Control (RBAC)**:
  - *Risk*: All authenticated users gain equal access to dangerous tools (e.g., file writes, system commands, database drops).
  - *Remedy*: Require specific OAuth scopes or API key permission claims for individual tool execution, rejecting unauthorized calls with JSON-RPC `-32003` (Forbidden).

---

## 5. State, Memory & Knowledge Graphs

- [ ] **16. Whitespace Sensitivity in Relation Deletions**:
  - *Risk*: Exact-match deletion in memory servers fails when LLMs include accidental space padding (`"knows "` vs `"knows"`), leaving zombie relations that resist deletion (servers #5645).
  - *Remedy*: Offer a trimmed deletion mode that strips surrounding whitespace before comparing relation types, preventing leaked graph edges.

- [ ] **17. Entity Identity Case Asymmetry Mitigation**:
  - *Risk*: Entity creation is case-sensitive (`"User"` and `"user"` coexist), while search is case-insensitive, causing split-brain entity graphs across multi-turn sessions (servers #5645).
  - *Remedy*: Provide configurable entity case policies (case-sensitive, canonical lowercasing, or alias mapping) to prevent duplicate entity proliferation.

- [ ] **18. Atomic `observationCount` Synchronization**:
  - *Risk*: `observationCount` metadata calculated at read time can drift after deletions, misleading agents during pagination or overview discovery (`observationLimit: 0`) (servers #5645).
  - *Remedy*: Atomically synchronize `observationCount` across deletions and guarantee that overview queries return exact remaining totals.

- [ ] **20. Unicode NFC vs NFD Normalization Twins & NUL-Byte Sanitization**:
  - *Risk*: Cross-platform agent fleets (macOS sending decomposed NFD `Cafe\u0301` vs Linux storing precomposed NFC `Caf\u00e9`) generate disjoint duplicate entities for the same conceptual node. Furthermore, embedded NUL bytes (`\0`) cause silent string truncation in downstream C-based database drivers (servers #5643).
  - *Remedy*: Canonicalize entity names to Unicode NFC, detect and merge normalization twins into primary nodes, and sanitize embedded NUL bytes before database persistence.

- [ ] **19. Knowledge Graph Quarantine & Self-Healing**:
  - *Risk*: A single corrupt, malformed, or un-parseable JSON line in a persistent graph file crashes the entire memory server on startup (servers #5609).
  - *Remedy*: Separate malformed entries into a sidecar quarantine file (`memory.quarantine.jsonl`) while preserving healthy graph records, allowing automated self-healing.

---

## 6. Streaming, Lifecycle & Process Stability

- [ ] **20. Standalone SSE Stream Priming at $t=0$**:
  - *Risk*: Clients connecting to GET SSE streams miss events sent before the connection finishes handshaking, because the stream is never primed with an initial event ID (typescript-sdk #3211).
  - *Remedy*: Emit an immediate priming heartbeat event frame with a monotonic sequence ID at $t=0$, enabling gapless replay with `Last-Event-ID`.

- [ ] **21. Intermediate Elicitation State Handling**:
  - *Risk*: Calling a tool that requires intermediate user confirmation (`input_required`) crashes the server if the tool declared an `outputSchema`, because the intermediate state does not match the final schema (typescript-sdk #3216).
  - *Remedy*: Intercept `input_required` responses and bypass final schema validation until the user completes the elicitation loop.

- [ ] **22. RFC 6570 URI Template Empty Expression Tolerance**:
  - *Risk*: Registering resource templates with empty expressions like `/api/{}` crashes `UriTemplate.match()` with an unhandled `TypeError`, returning protocol error `-32603` (typescript-sdk #3221).
  - *Remedy*: Prune empty expressions during template compilation, coalesce adjacent literal fragments, and enforce RFC 6570 §3.2.1 percent-encoding.

- [ ] **23. Deterministic Tool Caching & Thundering Herd Coalescing**:
  - *Risk*: Multiple concurrent agent turns requesting the same expensive tool with identical arguments trigger duplicate backend calls and rate-limit exhaustion.
  - *Remedy*: Coalesce concurrent requests onto a single promise using deterministic SHA-256 argument hashes with TTL expiration and stale-generation rejection (typescript-sdk #3075).

- [ ] **24. Atomic ABA-Free Stale Lock Reclamation**:
  - *Risk*: Multi-process servers sharing SQLite or local databases crash when encountering stale lock files left by abruptly terminated processes (servers #5624).
  - *Remedy*: Reclaim stale locks atomically using process heartbeat verification and owner PID validation to prevent race conditions.

---

## Need Drop-In, Production-Ready Solutions?

Every single vulnerability, edge case, and architectural invariant listed in this checklist is implemented and verified with **362 automated unit tests** in the **[MCP Production Kit](https://github.com/A7mdMe/mcp-production-kit)**:

- **Free Open-Source Core**: Production-ready TypeScript starter kit with dual stdio/SSE transports, SSRF protection, clean stdio logging, and namespaced memory store.
- **Commercial Pro Pack**: 33 drop-in modular TypeScript guards covering PostgreSQL/SQLite security, rate limiters, OAuth revocation, atomic symlinks, stream priming, and knowledge graph invariants.

🔗 **Explore the open-source repository:** [github.com/A7mdMe/mcp-production-kit](https://github.com/A7mdMe/mcp-production-kit)  
🛒 **Get the Pro Pack ($19):** [whop.com/checkout/plan_eiKHeRpooY3yc](https://whop.com/checkout/plan_eiKHeRpooY3yc)

---
*Maintained by [A7mdMe](https://github.com/A7mdMe). Contributions and additions to this checklist are welcome via pull requests!*

- [x] **Item 10: Graph Memory Idempotency & Observation Parity (servers #5653, #5654, #5655)**
  - *Risk:* In agent memory servers, `create_relations` silently returns empty results on duplicate creation with no notice, while `create_entities` allows duplicate observations that break deletion arithmetic ("Deleted 2 of 1").
  - *Hardening:* Enforce invariant deduplication on entity ingestion, return structured `skipped` arrays with reasons (`ALREADY_EXISTS`, `ENTITY_NOT_FOUND`), and normalize repeated deletion payloads.
  - *Reference:* `graph_memory_integrity_guard.ts` (Pro Pack Module 40).
