import assert from 'assert';
import { validateReadOnlyQuery } from '../pro_pack/postgres_connector.ts';
import { handleJsonRpc } from '../pro_pack/cloudflare_worker.ts';
import {
  TokenBucketRateLimiter,
  createRateLimitJsonRpcError,
  POSTGRES_TOKEN_BUCKET_DDL,
  POSTGRES_ATOMIC_CONSUME_QUERY
} from '../pro_pack/rate_limiter.ts';
import {
  validateReadOnlySqliteQuery,
  enforceReadOnlyConnectionUri,
  SQLITE_SCHEMA_INTROSPECTION_QUERY
} from '../pro_pack/sqlite_connector.ts';
import {
  McpCancellationManager,
  createCancellationJsonRpcError,
  createTimeoutJsonRpcError,
  CancelNotificationSchema,
  MCP_ERROR_REQUEST_CANCELLED,
  MCP_ERROR_TIMEOUT
} from '../pro_pack/cancellation_manager.ts';
import {
  McpAuthGuard,
  timingSafeCompare,
  MCP_ERROR_UNAUTHORIZED,
  MCP_ERROR_FORBIDDEN
} from '../pro_pack/auth_middleware.ts';
import {
  McpToolCache,
  generateToolCacheKey,
  canonicalJsonStringify
} from '../pro_pack/tool_cache.ts';
import {
  McpAuditLogger,
  redactSensitiveString,
  redactSensitiveData
} from '../pro_pack/audit_logger.ts';
import {
  parseHostHeader,
  verifyHostAndOrigin,
  createHostGuardMiddleware,
  LOOPBACK_HOSTS,
  WILDCARD_HOSTS
} from '../pro_pack/host_guard.ts';
import {
  AuthChallengeError,
  formatWwwAuthenticateHeader,
  formatAuthChallengeJsonRpc,
  wrapToolHandlerWithAuthCheck
} from '../pro_pack/auth_challenge.ts';
import {
  normalizeToolArguments,
  buildProblemDetails,
  formatValidationSummary,
  createStructuredToolHandler
} from '../pro_pack/input_validator.ts';
import {
  parseExactJson,
  stringifyExactJson,
  detectPrecisionLoss,
  isUnsafeIntegerString,
  wrapToolResultWithExactNumbers
} from '../pro_pack/lossless_json.ts';
import {
  classifyJsonRpcMessage,
  classifyJsonRpcPayload,
  FastPathDispatcher
} from '../pro_pack/message_classifier.ts';
import {
  StreamLifecycleGuard,
  defaultStreamLifecycleGuard
} from '../pro_pack/stream_lifecycle_guard.ts';
import {
  resolveWithin,
  safeWriteFile,
  safeReadFile,
  sanitizeRelativePath,
  PathTraversalError
} from '../pro_pack/filesystem_guard.ts';
import {
  ResilientSseClientController,
  wrapTransportWithTeardownGuard,
  isNonRetryableError,
  calculateBackoffDelay,
  SseTeardownError
} from '../pro_pack/sse_reconnect_guard.ts';
import {
  TransportEpochFence,
  reapProcessTree,
  wrapClientWithLifecycleGuard
} from '../pro_pack/stdio_lifecycle_guard.ts';
import {
  ClientSessionGuard,
  ClientSessionError,
  wrapClientWithSessionGuard
} from '../pro_pack/client_session_guard.ts';
import {
  SubscriptionRouterGuard,
  computeHonoredSubset,
  hasActiveSubscriptionFilters,
  createGuardedSubscriptionRouter
} from '../pro_pack/subscription_router_guard.ts';
import {
  normalizeHttpRequestBody,
  formatJsonRpcParseError,
  handleNormalizedFetch,
  createMcpHonoNormalizerMiddleware
} from '../pro_pack/http_transport_normalizer.ts';
import {
  validateAuthorizationIssuer,
  validateTokenIssuerClaim,
  createTenantAwareIssuerValidator
} from '../pro_pack/oauth_issuer_guard.ts';
import {
  StreamTruncationGuard,
  validateResumptionAttempt,
  validateProtocolVersion,
  validateClientCapabilities,
  createTerminalStreamError,
  MCP_ERROR_MISSING_CAPABILITY,
  MCP_ERROR_UNSUPPORTED_PROTOCOL,
  MCP_ERROR_CONNECTION_CLOSED
} from '../pro_pack/stream_resumption_guard.ts';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { EventEmitter } from 'node:events';

let passed = 0;
let failed = 0;

async function test(name: string, fn: () => Promise<void> | void) {
  try {
    await fn();
    console.log(`  [PASS] ${name}`);
    passed++;
  } catch (err: unknown) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err instanceof Error ? err.message : String(err)}`);
    failed++;
  }
}

async function runProPackTestSuite() {
  console.log('\n======================================================');
  console.log('   Pro Pack Commercial Features - Automated Test Suite');
  console.log('======================================================\n');

  // 1. PostgreSQL Connector Tests
  console.log('[Module: PostgreSQL Safe Query Validator]');

  await test('Allows safe standard SELECT queries', () => {
    const res = validateReadOnlyQuery('SELECT id, email, created_at FROM users WHERE is_active = true');
    assert.strictEqual(res.safe, true);
  });

  await test('Allows SELECT queries with string literals containing mutation words', () => {
    // Crucial: 'DELETED' inside quotes must NOT trigger false positive
    const res = validateReadOnlyQuery("SELECT * FROM audit_logs WHERE action_status = 'DELETED' AND category = 'USER'");
    assert.strictEqual(res.safe, true);
  });

  await test('Allows safe read-only Common Table Expressions (WITH ... SELECT)', () => {
    const res = validateReadOnlyQuery('WITH active_users AS (SELECT * FROM users WHERE active = true) SELECT * FROM active_users');
    assert.strictEqual(res.safe, true);
  });

  await test('Blocks direct DELETE statements', () => {
    const res = validateReadOnlyQuery('DELETE FROM users WHERE id = 42');
    assert.strictEqual(res.safe, false);
    assert(res.reason?.includes("Query must start with 'SELECT' or 'WITH'") || res.reason?.includes('DELETE'));
  });

  await test('Blocks DROP TABLE statements', () => {
    const res = validateReadOnlyQuery('DROP TABLE production_orders');
    assert.strictEqual(res.safe, false);
    assert(res.reason?.includes("Query must start with 'SELECT' or 'WITH'") || res.reason?.includes('DROP'));
  });

  await test('Blocks stacked SQL injection attacks with semicolons', () => {
    const res = validateReadOnlyQuery('SELECT * FROM users; DROP TABLE accounts');
    assert.strictEqual(res.safe, false);
    assert(res.reason?.includes('Multiple SQL statements detected'));
  });

  await test('Blocks CTE mutation attacks (WITH d AS (DELETE ...) SELECT ...)', () => {
    const res = validateReadOnlyQuery('WITH d AS (DELETE FROM accounts WHERE balance < 0 RETURNING *) SELECT * FROM d');
    assert.strictEqual(res.safe, false);
    assert(res.reason?.includes("Prohibited keyword 'DELETE'"));
  });

  await test('Blocks comment-wrapped evasion attempts (-- comment \\n DROP TABLE)', () => {
    const res = validateReadOnlyQuery('-- bypass check \n DROP TABLE secrets');
    assert.strictEqual(res.safe, false);
  });

  // 2. Cloudflare Worker JSON-RPC Tests
  console.log('\n[Module: Cloudflare Worker JSON-RPC Edge Handler]');

  await test('Worker handles MCP initialize and returns spec 2024-11-05', () => {
    const res = handleJsonRpc({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2024-11-05' }
    }, { SERVER_NAME: 'test-edge', SERVER_VERSION: '1.2.3' });

    assert.strictEqual(res.jsonrpc, '2.0');
    assert.strictEqual(res.id, 1);
    const result = res.result as any;
    assert.strictEqual(result.protocolVersion, '2024-11-05');
    assert.strictEqual(result.serverInfo.name, 'test-edge');
  });

  await test('Worker handles tools/list and returns edge tools catalog', () => {
    const res = handleJsonRpc({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/list'
    }, {});

    const result = res.result as any;
    assert(Array.isArray(result.tools));
    assert(result.tools.some((t: any) => t.name === 'edge_health_check'));
    assert(result.tools.some((t: any) => t.name === 'edge_dns_resolve'));
  });

  await test('Worker handles tools/call for edge_health_check', () => {
    const res = handleJsonRpc({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'edge_health_check', arguments: { verbose: true } }
    }, {}, { colo: 'LHR', country: 'GB' } as any);

    const result = res.result as any;
    assert(result.content && result.content[0]);
    const parsed = JSON.parse(result.content[0].text);
    assert.strictEqual(parsed.status, 'healthy');
    assert.strictEqual(parsed.colo, 'LHR');
  });

  await test('Worker returns -32601 error for unknown tool call', () => {
    const res = handleJsonRpc({
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: { name: 'non_existent_tool', arguments: {} }
    }, {});

    assert(res.error);
    const err = res.error as any;
    assert.strictEqual(err.code, -32601);
  });

  // 3. MCP Rate Limiter & Token Bucket Tests
  console.log('\n[Module: Token Bucket Rate Limiter & Cost Control]');

  await test('Allows consumption within bucket burst capacity', () => {
    const limiter = new TokenBucketRateLimiter({ capacity: 5, refillRatePerSecond: 1 });
    const r1 = limiter.consume('search_tool', 'agent-alpha');
    const r2 = limiter.consume('search_tool', 'agent-alpha');
    assert.strictEqual(r1.allowed, true);
    assert.strictEqual(r1.remainingTokens, 4);
    assert.strictEqual(r2.allowed, true);
    assert.strictEqual(r2.remainingTokens, 3);
  });

  await test('Enforces rate limit when token quota is depleted', () => {
    const limiter = new TokenBucketRateLimiter({ capacity: 2, refillRatePerSecond: 0.1 });
    limiter.consume('search_tool', 'agent-beta'); // 1 left
    limiter.consume('search_tool', 'agent-beta'); // 0 left
    const blocked = limiter.consume('search_tool', 'agent-beta'); // should be blocked
    assert.strictEqual(blocked.allowed, false);
    assert.strictEqual(blocked.remainingTokens, 0);
    assert.strictEqual(blocked.auditRecord.status, 'RATE_LIMITED');
  });

  await test('Calculates accurate retryAfterSeconds on rate limit rejection', () => {
    // 1 token per 2 seconds (0.5 tokens/sec). If cost=1 and 0 tokens left, retryAfter = 2s
    const limiter = new TokenBucketRateLimiter({ capacity: 1, refillRatePerSecond: 0.5 });
    limiter.consume('heavy_query', 'agent-gamma');
    const blocked = limiter.consume('heavy_query', 'agent-gamma');
    assert.strictEqual(blocked.allowed, false);
    assert(blocked.retryAfterSeconds >= 2);
  });

  await test('Refills tokens over time according to refillRatePerSecond', async () => {
    const limiter = new TokenBucketRateLimiter({ capacity: 2, refillRatePerSecond: 10 }); // fast refill for test
    limiter.consume('fast_tool', 'agent-delta', 2); // drain bucket
    await new Promise(r => setTimeout(r, 150)); // wait 150ms -> +1.5 tokens
    const r = limiter.consume('fast_tool', 'agent-delta', 1);
    assert.strictEqual(r.allowed, true);
  });

  await test('Supports per-tool limit overrides independently', () => {
    const limiter = new TokenBucketRateLimiter({ capacity: 10, refillRatePerSecond: 1 });
    limiter.setToolLimit('expensive_mutation', { capacity: 1, refillRatePerSecond: 0.1 });

    const standard = limiter.consume('standard_tool', 'agent-epsilon');
    assert.strictEqual(standard.allowed, true);
    assert.strictEqual(standard.remainingTokens, 9);

    const exp1 = limiter.consume('expensive_mutation', 'agent-epsilon');
    assert.strictEqual(exp1.allowed, true);
    assert.strictEqual(exp1.remainingTokens, 0);

    const exp2 = limiter.consume('expensive_mutation', 'agent-epsilon');
    assert.strictEqual(exp2.allowed, false);
  });

  await test('Formats standard MCP JSON-RPC -32029 error structure with code and retry data', () => {
    const err = createRateLimitJsonRpcError(42, 'sql_runner', 5);
    assert.strictEqual(err.jsonrpc, '2.0');
    assert.strictEqual(err.id, 42);
    assert.strictEqual(err.error.code, -32029);
    assert(err.error.message.includes('Rate limit exceeded for tool \'sql_runner\''));
    assert.strictEqual(err.error.data.retryAfterSeconds, 5);
  });

  await test('Exports valid PostgreSQL atomic token bucket DDL and CTE query', () => {
    assert(POSTGRES_TOKEN_BUCKET_DDL.includes('CREATE TABLE IF NOT EXISTS mcp_rate_limits'));
    assert(POSTGRES_ATOMIC_CONSUME_QUERY.includes('WITH current_state AS'));
    assert(POSTGRES_ATOMIC_CONSUME_QUERY.includes('ON CONFLICT (agent_id, tool_name) DO UPDATE'));
  });

  // 4. SQLite Read-Only Guardrail & Schema Introspection Tests
  console.log('\n[Module: Hardened SQLite Read-Only Guardrails & Schema Introspection]');

  await test('Allows safe standard SQLite SELECT queries', () => {
    const res = validateReadOnlySqliteQuery('SELECT id, name, created_at FROM items WHERE active = 1');
    assert.strictEqual(res.safe, true);
  });

  await test('Allows SELECT queries with string literals containing prohibited words', () => {
    const res = validateReadOnlySqliteQuery("SELECT * FROM attachments WHERE filename = 'ATTACH_FILE.pdf' AND status = 'DETACHED'");
    assert.strictEqual(res.safe, true);
  });

  await test('Allows safe read-only Common Table Expressions (WITH ... SELECT)', () => {
    const res = validateReadOnlySqliteQuery('WITH active_items AS (SELECT id, name FROM items WHERE active = 1) SELECT * FROM active_items');
    assert.strictEqual(res.safe, true);
  });

  await test('Blocks direct SQLite DELETE statements', () => {
    const res = validateReadOnlySqliteQuery('DELETE FROM items WHERE id = 10');
    assert.strictEqual(res.safe, false);
    assert(res.reason?.includes("Query must start with 'SELECT' or 'WITH'") || res.reason?.includes('DELETE'));
  });

  await test('Blocks direct SQLite DROP TABLE statements', () => {
    const res = validateReadOnlySqliteQuery('DROP TABLE items');
    assert.strictEqual(res.safe, false);
    assert(res.reason?.includes("Query must start with 'SELECT' or 'WITH'") || res.reason?.includes('DROP'));
  });

  await test('Blocks stacked SQL injection attacks with semicolons in SQLite', () => {
    const res = validateReadOnlySqliteQuery('SELECT * FROM items; DROP TABLE items');
    assert.strictEqual(res.safe, false);
    assert(res.reason?.includes('Multiple SQL statements detected'));
  });

  await test('Blocks SQLite ATTACH DATABASE vectors', () => {
    const res = validateReadOnlySqliteQuery("SELECT * FROM items; ATTACH DATABASE 'malicious.db' AS evil");
    assert.strictEqual(res.safe, false);
  });

  await test('Blocks SQLite PRAGMA execution vectors', () => {
    const res = validateReadOnlySqliteQuery('PRAGMA writable_schema = ON');
    assert.strictEqual(res.safe, false);
    assert(res.reason?.includes("Query must start with 'SELECT' or 'WITH'") || res.reason?.includes('PRAGMA'));
  });

  await test('Blocks SQLite comment-wrapped evasion attempts (-- bypass \\n DROP TABLE)', () => {
    const res = validateReadOnlySqliteQuery('-- bypass check \n DROP TABLE secrets');
    assert.strictEqual(res.safe, false);
  });

  await test('Enforces ?mode=ro read-only mode on SQLite connection URIs', () => {
    const uri1 = enforceReadOnlyConnectionUri('local.db');
    assert.strictEqual(uri1, 'file:local.db?mode=ro');

    const uri2 = enforceReadOnlyConnectionUri('file:data.sqlite');
    assert.strictEqual(uri2, 'file:data.sqlite?mode=ro');

    const uri3 = enforceReadOnlyConnectionUri('file:data.sqlite?mode=rwc');
    assert.strictEqual(uri3, 'file:data.sqlite?mode=ro');

    const uri4 = enforceReadOnlyConnectionUri('file:data.sqlite?cache=shared');
    assert.strictEqual(uri4, 'file:data.sqlite?cache=shared&mode=ro');
  });

  await test('Exports valid sqlite_master schema introspection query', () => {
    assert(SQLITE_SCHEMA_INTROSPECTION_QUERY.includes('FROM sqlite_master'));
    assert(SQLITE_SCHEMA_INTROSPECTION_QUERY.includes("name NOT LIKE 'sqlite_%'"));
  });

  // 5. Request Cancellation & Execution Timeout Tests
  console.log('\n[Module: Request Cancellation & Deadline Timeout Manager]');

  await test('Registers in-flight request and returns un-aborted AbortSignal', () => {
    const manager = new McpCancellationManager();
    const signal = manager.registerRequest('req-1', 5000);
    assert.strictEqual(signal.aborted, false);
    assert.strictEqual(manager.isInFlight('req-1'), true);
    assert.strictEqual(manager.getInFlightCount(), 1);
    manager.cleanup('req-1');
    assert.strictEqual(manager.isInFlight('req-1'), false);
    assert.strictEqual(manager.getInFlightCount(), 0);
  });

  await test('handleCancelNotification aborts active signal and cleans up mapping', () => {
    const manager = new McpCancellationManager();
    const signal = manager.registerRequest('req-2', 10000);
    const handled = manager.handleCancelNotification({ requestId: 'req-2', reason: 'User clicked Stop' });
    assert.strictEqual(handled, true);
    assert.strictEqual(signal.aborted, true);
    assert.strictEqual(signal.reason?.message, 'User clicked Stop');
    assert.strictEqual(manager.isInFlight('req-2'), false);
  });

  await test('handleCancelNotification returns false for unknown or completed request', () => {
    const manager = new McpCancellationManager();
    const handled = manager.handleCancelNotification({ requestId: 'non-existent' });
    assert.strictEqual(handled, false);
  });

  await test('executeWithGuards completes normally when tool finishes before deadline', async () => {
    const manager = new McpCancellationManager();
    const res = await manager.executeWithGuards('req-3', 2000, async (signal) => {
      assert.strictEqual(signal.aborted, false);
      return { status: 'completed', records: 42 };
    });
    assert.strictEqual(res.success, true);
    if (res.success) {
      assert.strictEqual(res.data.records, 42);
    }
    assert.strictEqual(manager.getInFlightCount(), 0);
  });

  await test('executeWithGuards returns -32800 error when request is cancelled during execution', async () => {
    const manager = new McpCancellationManager();
    const executionPromise = manager.executeWithGuards('req-4', 5000, async (signal) => {
      return new Promise((resolve, reject) => {
        signal.addEventListener('abort', () => {
          reject(signal.reason);
        });
      });
    });

    // Simulate client sending notifications/cancelled after 50ms
    setTimeout(() => {
      manager.handleCancelNotification({ requestId: 'req-4', reason: 'Client disconnected' });
    }, 50);

    const res = await executionPromise;
    assert.strictEqual(res.success, false);
    if (!res.success) {
      assert.strictEqual(res.errorResponse.error.code, MCP_ERROR_REQUEST_CANCELLED);
      assert.strictEqual(res.errorResponse.id, 'req-4');
      assert(res.errorResponse.error.message.includes('Client disconnected'));
      assert.strictEqual(res.errorResponse.error.data?.cancelled, true);
    }
    assert.strictEqual(manager.getInFlightCount(), 0);
  });

  await test('executeWithGuards returns -32000 error when execution exceeds deadline timeout', async () => {
    const manager = new McpCancellationManager();
    const res = await manager.executeWithGuards('req-5', 100, async (signal) => {
      return new Promise((resolve, reject) => {
        signal.addEventListener('abort', () => {
          reject(signal.reason);
        });
        setTimeout(resolve, 500); // 500ms > 100ms timeout
      });
    });

    assert.strictEqual(res.success, false);
    if (!res.success) {
      assert.strictEqual(res.errorResponse.error.code, MCP_ERROR_TIMEOUT);
      assert.strictEqual(res.errorResponse.id, 'req-5');
      assert(res.errorResponse.error.message.includes('deadline exceeded'));
      assert.strictEqual(res.errorResponse.error.data?.timeoutMs, 100);
    }
    assert.strictEqual(manager.getInFlightCount(), 0);
  });

  await test('CancelNotificationSchema validates both string and numeric request IDs', () => {
    const parsed1 = CancelNotificationSchema.parse({ requestId: 'abc-123', reason: 'abort' });
    assert.strictEqual(parsed1.requestId, 'abc-123');

    const parsed2 = CancelNotificationSchema.parse({ requestId: 42 });
    assert.strictEqual(parsed2.requestId, 42);
    assert.strictEqual(parsed2.reason, undefined);
  });

  await test('createCancellationJsonRpcError formats standard MCP error with timestamp', () => {
    const err = createCancellationJsonRpcError(99, 'Custom cancel');
    assert.strictEqual(err.jsonrpc, '2.0');
    assert.strictEqual(err.id, 99);
    assert.strictEqual(err.error.code, -32800);
    assert.strictEqual(err.error.message, 'Custom cancel');
    assert.strictEqual(err.error.data?.cancelled, true);
  });

  // 6. RFC 6750 Bearer Authentication & Tool RBAC Tests
  console.log('\n[Module: RFC 6750 Bearer Authentication & Tool RBAC Guard]');

  await test('timingSafeCompare correctly compares strings in constant time', () => {
    assert.strictEqual(timingSafeCompare('secret-token-123', 'secret-token-123'), true);
    assert.strictEqual(timingSafeCompare('secret-token-123', 'secret-token-456'), false);
    assert.strictEqual(timingSafeCompare('short', 'longer-string'), false);
  });

  await test('validateHeaders returns RFC 6750 compliant challenge without error="invalid_token" when no credentials sent', () => {
    const auth = new McpAuthGuard({ defaultScope: 'tools:all' });
    const res = auth.validateHeaders({});
    assert.strictEqual(res.authenticated, false);
    assert.strictEqual(res.statusCode, 401);
    assert(res.headers['WWW-Authenticate'].includes('Bearer realm="mcp", scope="tools:all"'));
    assert(!res.headers['WWW-Authenticate'].includes('invalid_token')); // Crucial RFC 6750 §3.1 check
  });

  await test('validateHeaders includes resource_metadata in challenge when configured', () => {
    const auth = new McpAuthGuard({
      defaultScope: 'mcp:read',
      resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource'
    });
    const res = auth.validateHeaders({});
    assert.strictEqual(res.statusCode, 401);
    assert(res.headers['WWW-Authenticate'].includes('resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"'));
  });

  await test('validateHeaders returns 401 with invalid_token when bad token is provided', () => {
    const auth = new McpAuthGuard();
    auth.registerToken('valid-token-xyz', { clientId: 'agent-1', roles: ['admin'], scopes: ['read', 'write'] });
    const res = auth.validateHeaders({ authorization: 'Bearer bad-token-123' });
    assert.strictEqual(res.authenticated, false);
    assert.strictEqual(res.statusCode, 401);
    assert(res.headers['WWW-Authenticate'].includes('error="invalid_token"'));
  });

  await test('validateHeaders returns 401 with invalid_token when token is expired', () => {
    const auth = new McpAuthGuard();
    auth.registerToken('expired-token', {
      clientId: 'agent-2',
      roles: ['viewer'],
      scopes: ['read'],
      expiresAt: Date.now() - 5000 // 5 seconds in the past
    });
    const res = auth.validateHeaders({ authorization: 'Bearer expired-token' });
    assert.strictEqual(res.authenticated, false);
    assert.strictEqual(res.statusCode, 401);
    assert(res.headers['WWW-Authenticate'].includes('The access token expired'));
  });

  await test('validateHeaders successfully authenticates valid Bearer token and returns AuthContext', () => {
    const auth = new McpAuthGuard();
    auth.registerToken('active-token-999', {
      clientId: 'cursor-agent-prod',
      tenantId: 'tenant-omega',
      roles: ['developer'],
      scopes: ['db:read', 'db:query']
    });
    const res = auth.validateHeaders({ Authorization: 'Bearer active-token-999' });
    assert.strictEqual(res.authenticated, true);
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.context?.clientId, 'cursor-agent-prod');
    assert.strictEqual(res.context?.tenantId, 'tenant-omega');
    assert(res.context?.scopes.includes('db:read'));
  });

  await test('validateHeaders successfully authenticates valid x-api-key header', () => {
    const auth = new McpAuthGuard();
    auth.registerToken('mcp_api_key_live_abc', {
      clientId: 'claude-desktop-user',
      roles: ['user'],
      scopes: ['tools:call']
    });
    const res = auth.validateHeaders({ 'x-api-key': 'mcp_api_key_live_abc' });
    assert.strictEqual(res.authenticated, true);
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.context?.clientId, 'claude-desktop-user');
  });

  await test('authorizeToolCall permits execution when tool has no required scopes', () => {
    const auth = new McpAuthGuard();
    const res = auth.authorizeToolCall('system_health', { clientId: 'guest', roles: [], scopes: [] });
    assert.strictEqual(res.allowed, true);
  });

  await test('authorizeToolCall permits execution when caller holds all required scopes', () => {
    const auth = new McpAuthGuard();
    auth.setRequiredToolScopes('query_postgres', ['db:read']);
    const res = auth.authorizeToolCall('query_postgres', {
      clientId: 'analyst',
      roles: ['viewer'],
      scopes: ['db:read', 'metrics:view']
    });
    assert.strictEqual(res.allowed, true);
  });

  await test('authorizeToolCall blocks execution with -32003 when caller lacks required scope', () => {
    const auth = new McpAuthGuard();
    auth.setRequiredToolScopes('mutate_records', ['db:write']);
    const res = auth.authorizeToolCall('mutate_records', {
      clientId: 'read-only-bot',
      roles: ['viewer'],
      scopes: ['db:read']
    }, 'req-403');

    assert.strictEqual(res.allowed, false);
    assert(res.jsonRpcError);
    assert.strictEqual(res.jsonRpcError?.error.code, MCP_ERROR_FORBIDDEN);
    assert.strictEqual(res.jsonRpcError?.id, 'req-403');
    assert(res.jsonRpcError?.error.message.includes("lacks required scope(s): db:write"));
  });

  // 7. Deterministic Tool Caching & Deduplication Tests
  console.log('\n[Module: Deterministic Tool Response Caching & Deduplication]');

  await test('canonicalJsonStringify recursively sorts dictionary keys for identical strings', () => {
    const obj1 = { b: 2, a: 1, nested: { y: 'bar', x: 'foo' } };
    const obj2 = { a: 1, nested: { x: 'foo', y: 'bar' }, b: 2 };
    assert.strictEqual(canonicalJsonStringify(obj1), canonicalJsonStringify(obj2));
  });

  await test('generateToolCacheKey yields identical SHA-256 hashes for out-of-order arguments', () => {
    const k1 = generateToolCacheKey('query_sql', { limit: 10, offset: 0, query: 'SELECT 1' });
    const k2 = generateToolCacheKey('query_sql', { query: 'SELECT 1', offset: 0, limit: 10 });
    assert.strictEqual(k1, k2);
  });

  await test('get returns hit=false on uncached tool call', () => {
    const cache = new McpToolCache();
    const res = cache.get('fetch_data', { id: 123 });
    assert.strictEqual(res.hit, false);
  });

  await test('set and get successfully cache and retrieve tool execution results', () => {
    const cache = new McpToolCache({ defaultTtlMs: 5000 });
    cache.set('fetch_data', { id: 123 }, { status: 'ok', payload: [1, 2, 3] });
    const res = cache.get<{ status: string; payload: number[] }>('fetch_data', { id: 123 });
    assert.strictEqual(res.hit, true);
    if (res.hit) {
      assert.strictEqual(res.value.status, 'ok');
      assert.strictEqual(res.value.payload.length, 3);
      assert(res.ageMs >= 0);
    }
  });

  await test('cache entry automatically expires past its TTL', async () => {
    const cache = new McpToolCache({ defaultTtlMs: 50 }); // 50ms TTL
    cache.set('quick_expire', { q: 'test' }, 'value');
    await new Promise(r => setTimeout(r, 70)); // wait past TTL
    const res = cache.get('quick_expire', { q: 'test' });
    assert.strictEqual(res.hit, false);
  });

  await test('stale writes are rejected when tool generation has advanced (resolves #3075)', () => {
    const cache = new McpToolCache();
    const oldGen = cache.captureGeneration('search_docs'); // generation 0
    cache.invalidateTool('search_docs'); // generation becomes 1
    const accepted = cache.set('search_docs', { q: 'stale' }, 'old_data', { generation: oldGen });
    assert.strictEqual(accepted, false);
    const res = cache.get('search_docs', { q: 'stale' });
    assert.strictEqual(res.hit, false); // Stale data was never written!
  });

  await test('executeWithCache executes executor on first call and returns cached=false', async () => {
    const cache = new McpToolCache();
    let executions = 0;
    const res = await cache.executeWithCache('heavy_job', { n: 5 }, async () => {
      executions++;
      return 5 * 2;
    });
    assert.strictEqual(executions, 1);
    assert.strictEqual(res.cached, false);
    assert.strictEqual(res.data, 10);
  });

  await test('executeWithCache returns cached result on subsequent call without re-invoking executor', async () => {
    const cache = new McpToolCache();
    let executions = 0;
    const fn = async () => {
      executions++;
      return 'calculated-val';
    };

    await cache.executeWithCache('heavy_job', { id: 42 }, fn);
    const res2 = await cache.executeWithCache('heavy_job', { id: 42 }, fn);

    assert.strictEqual(executions, 1); // Not called again!
    assert.strictEqual(res2.cached, true);
    assert.strictEqual(res2.data, 'calculated-val');
  });

  await test('thundering herd coalescing deduplicates concurrent executions onto a single promise', async () => {
    const cache = new McpToolCache();
    let backendCalls = 0;

    const slowQuery = async () => {
      backendCalls++;
      await new Promise(r => setTimeout(r, 60));
      return { rows: [100, 200] };
    };

    // Fire 3 simultaneous calls
    const [p1, p2, p3] = await Promise.all([
      cache.executeWithCache('shared_db_query', { table: 'users' }, slowQuery),
      cache.executeWithCache('shared_db_query', { table: 'users' }, slowQuery),
      cache.executeWithCache('shared_db_query', { table: 'users' }, slowQuery)
    ]);

    assert.strictEqual(backendCalls, 1); // Only ONE actual call to backend!
    assert.strictEqual(p1.data.rows.length, 2);
    assert.strictEqual(p2.data.rows.length, 2);
    assert.strictEqual(p3.data.rows.length, 2);
    assert.strictEqual(cache.getStats().coalesced, 2);
  });

  await test('invalidateTool forces next execution to fetch fresh data', async () => {
    const cache = new McpToolCache();
    let counter = 0;
    const getCounter = async () => ++counter;

    await cache.executeWithCache('dynamic_metric', {}, getCounter); // 1
    cache.invalidateTool('dynamic_metric'); // flush
    const res = await cache.executeWithCache('dynamic_metric', {}, getCounter); // 2

    assert.strictEqual(res.cached, false);
    assert.strictEqual(res.data, 2);
  });

  await test('maxEntries LRU capacity eviction evicts oldest key when capacity exceeded', () => {
    const cache = new McpToolCache({ maxEntries: 2 });
    cache.set('tool', { id: 1 }, 'first');
    cache.set('tool', { id: 2 }, 'second');
    cache.set('tool', { id: 3 }, 'third'); // should evict id:1

    assert.strictEqual(cache.get('tool', { id: 1 }).hit, false);
    assert.strictEqual(cache.get('tool', { id: 2 }).hit, true);
    assert.strictEqual(cache.get('tool', { id: 3 }).hit, true);
    assert.strictEqual(cache.getStats().evictions, 1);
  });

  // 8. Secret Redaction & Compliance Audit Logging Tests
  console.log('\n[Module: Secret Redaction & Compliance Audit Logger]');

  await test('redactSensitiveString masks database passwords in connection URIs', () => {
    const raw = 'postgres://admin:SuperSecretPass123!@db.internal.net:5432/prod_db';
    const redacted = redactSensitiveString(raw);
    assert.strictEqual(redacted, 'postgres://admin:***@db.internal.net:5432/prod_db');
  });

  await test('redactSensitiveString masks Bearer tokens and JWTs', () => {
    const header = 'Authorization: Bearer my-secret-session-token-xyz';
    assert.strictEqual(redactSensitiveString(header), 'Authorization: Bearer [REDACTED_TOKEN]');

    const jwt = 'Token is eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c in session';
    assert(redactSensitiveString(jwt).includes('[REDACTED_JWT]'));
  });

  await test('redactSensitiveString masks API keys (sk-, ghp_)', () => {
    const text = 'Using key sk-ant-api03-abcdef1234567890abcdef1234567890 and token ghp_123456789012345678901234567890123456';
    const redacted = redactSensitiveString(text);
    assert(!redacted.includes('sk-ant-'));
    assert(!redacted.includes('ghp_'));
    assert(redacted.includes('[REDACTED_API_KEY]'));
  });

  await test('redactSensitiveData recursively masks dictionary values for sensitive keys', () => {
    const input = {
      username: 'agent_007',
      password: 'cleartext-password!',
      api_key: 'secret-key-123',
      nested: {
        clientSecret: 'shhh-confidential',
        publicId: 'public-123'
      }
    };

    const sanitized = redactSensitiveData(input) as any;
    assert.strictEqual(sanitized.username, 'agent_007');
    assert.strictEqual(sanitized.password, '[REDACTED]');
    assert.strictEqual(sanitized.api_key, '[REDACTED]');
    assert.strictEqual(sanitized.nested.clientSecret, '[REDACTED]');
    assert.strictEqual(sanitized.nested.publicId, 'public-123');
  });

  await test('logEvent creates immutable structured audit entry with UUID and ISO timestamp', () => {
    const logger = new McpAuditLogger({ emitToStderr: false });
    const entry = logger.logEvent({
      toolName: 'query_db',
      clientId: 'agent-prod-1',
      status: 'SUCCESS',
      durationMs: 45,
      sanitizedArgs: { table: 'customers', apiKey: 'secret-123' }
    });

    assert(entry.eventId && entry.eventId.length > 10);
    assert(entry.timestamp.includes('T'));
    assert.strictEqual(entry.status, 'SUCCESS');
    assert.strictEqual(entry.durationMs, 45);
    assert.strictEqual(entry.sanitizedArgs.apiKey, '[REDACTED]');
  });

  await test('wrapExecution captures durationMs and logs SUCCESS on clean tool run', async () => {
    const logger = new McpAuditLogger({ emitToStderr: false });
    const res = await logger.wrapExecution('compute_sum', 'agent-a', { a: 10, b: 20 }, async () => {
      await new Promise(r => setTimeout(r, 20));
      return { content: [{ type: 'text', text: '30' }] };
    });

    assert.strictEqual((res as any).content[0].text, '30');
    const events = logger.getRecentEvents(1);
    assert.strictEqual(events.length, 1);
    assert.strictEqual(events[0].toolName, 'compute_sum');
    assert.strictEqual(events[0].status, 'SUCCESS');
    assert(events[0].durationMs >= 15);
  });

  await test('wrapExecution captures error message and logs ERROR on tool failure', async () => {
    const logger = new McpAuditLogger({ emitToStderr: false });
    await assert.rejects(async () => {
      await logger.wrapExecution('failing_tool', 'agent-b', { query: 'INVALID' }, async () => {
        throw new Error('Database connection failed');
      });
    }, /Database connection failed/);

    const events = logger.getRecentEvents(1);
    assert.strictEqual(events.length, 1);
    assert.strictEqual(events[0].toolName, 'failing_tool');
    assert.strictEqual(events[0].status, 'ERROR');
    assert.strictEqual(events[0].error?.message, 'Database connection failed');
  });

  await test('bounded ring buffer maintains max capacity and evicts oldest entries', () => {
    const logger = new McpAuditLogger({ maxBufferSize: 3, emitToStderr: false });
    logger.logEvent({ toolName: 't1', clientId: 'c', status: 'SUCCESS', durationMs: 1, sanitizedArgs: {} });
    logger.logEvent({ toolName: 't2', clientId: 'c', status: 'SUCCESS', durationMs: 1, sanitizedArgs: {} });
    logger.logEvent({ toolName: 't3', clientId: 'c', status: 'SUCCESS', durationMs: 1, sanitizedArgs: {} });
    logger.logEvent({ toolName: 't4', clientId: 'c', status: 'SUCCESS', durationMs: 1, sanitizedArgs: {} });

    const recent = logger.getRecentEvents(10);
    assert.strictEqual(recent.length, 3);
    assert.strictEqual(recent[0].toolName, 't2');
    assert.strictEqual(recent[2].toolName, 't4');
  });

  await test('getRecentEvents returns empty array after clear()', () => {
    const logger = new McpAuditLogger({ emitToStderr: false });
    logger.logEvent({ toolName: 't1', clientId: 'c', status: 'SUCCESS', durationMs: 1, sanitizedArgs: {} });
    assert.strictEqual(logger.getRecentEvents().length, 1);
    logger.clear();
    assert.strictEqual(logger.getRecentEvents().length, 0);
  });

  // --------------------------------------------------------------------------
  // Module 9: Host & Origin DNS Rebinding Protection Guard
  // --------------------------------------------------------------------------
  console.log('\n[Module: Host & Origin DNS Rebinding Protection Guard]');

  await test('parseHostHeader handles standard hostname and port', () => {
    const res = parseHostHeader('localhost:3000');
    assert.strictEqual(res.hostname, 'localhost');
    assert.strictEqual(res.port, 3000);

    const res2 = parseHostHeader('mcp.internal');
    assert.strictEqual(res2.hostname, 'mcp.internal');
    assert.strictEqual(res2.port, null);
  });

  await test('parseHostHeader handles IPv6 bracket notation', () => {
    const res = parseHostHeader('[::1]:8080');
    assert.strictEqual(res.hostname, '[::1]');
    assert.strictEqual(res.port, 8080);

    const res2 = parseHostHeader('[2001:db8::1]');
    assert.strictEqual(res2.hostname, '[2001:db8::1]');
    assert.strictEqual(res2.port, null);
  });

  await test('parseHostHeader rejects malformed host headers', () => {
    assert.throws(() => parseHostHeader('[::1:3000'), /missing closing bracket/);
    assert.throws(() => parseHostHeader('localhost:999999'), /Invalid port/);
    assert.throws(() => parseHostHeader('localhost:abc'), /Invalid port/);
    assert.throws(() => parseHostHeader('a:b:c'), /unbracketed IPv6 or excessive colons/);
  });

  await test('verifyHostAndOrigin allows standard loopback hosts by default', () => {
    assert.strictEqual(verifyHostAndOrigin({ host: 'localhost:3000' }).valid, true);
    assert.strictEqual(verifyHostAndOrigin({ host: '127.0.0.1:8080' }).valid, true);
    assert.strictEqual(verifyHostAndOrigin({ host: '[::1]:3000' }).valid, true);
  });

  await test('verifyHostAndOrigin rejects missing Host header with 400 and -32600', () => {
    const res = verifyHostAndOrigin({});
    assert.strictEqual(res.valid, false);
    assert.strictEqual(res.statusCode, 400);
    assert.strictEqual(res.jsonRpcError?.error.code, -32600);
    assert.strictEqual(res.jsonRpcError?.error.message, 'Invalid Request: Missing Host header');
  });

  await test('verifyHostAndOrigin blocks Host header injection control characters', () => {
    const res = verifyHostAndOrigin({ host: "localhost\r\nInjected-Header: evil" });
    assert.strictEqual(res.valid, false);
    assert.strictEqual(res.statusCode, 400);
    assert.strictEqual(res.jsonRpcError?.error.code, -32600);
  });

  await test('verifyHostAndOrigin blocks wildcard addresses in Host header', () => {
    const res = verifyHostAndOrigin({ host: '0.0.0.0:3000' });
    assert.strictEqual(res.valid, false);
    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.jsonRpcError?.error.code, -32600);
  });

  await test('verifyHostAndOrigin blocks unapproved external hosts (DNS Rebinding protection)', () => {
    const res = verifyHostAndOrigin({ host: 'rebind.attacker.com:3000' });
    assert.strictEqual(res.valid, false);
    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.jsonRpcError?.error.code, -32600);
    assert.ok(res.reason?.includes('DNS Rebinding'));
  });

  await test('verifyHostAndOrigin allows explicitly whitelisted hosts and wildcards', () => {
    const opts = { allowedHosts: ['mcp.internal', '*.company.corp'] };
    assert.strictEqual(verifyHostAndOrigin({ host: 'mcp.internal:3000' }, opts).valid, true);
    assert.strictEqual(verifyHostAndOrigin({ host: 'agent-1.company.corp:4000' }, opts).valid, true);
    assert.strictEqual(verifyHostAndOrigin({ host: 'other.corp' }, opts).valid, false);
  });

  await test('verifyHostAndOrigin enforces expected port when configured', () => {
    const opts = { enforcePort: true, expectedPort: 3000 };
    assert.strictEqual(verifyHostAndOrigin({ host: 'localhost:3000' }, opts).valid, true);
    const res = verifyHostAndOrigin({ host: 'localhost:8080' }, opts);
    assert.strictEqual(res.valid, false);
    assert.strictEqual(res.statusCode, 403);
    assert.ok(res.reason?.includes('Port mismatch'));
  });

  await test('verifyHostAndOrigin allows native clients without Origin header when allowNoOrigin is true', () => {
    const res = verifyHostAndOrigin({ host: 'localhost:3000' }, { allowNoOrigin: true });
    assert.strictEqual(res.valid, true);
  });

  await test('verifyHostAndOrigin blocks requests without Origin header when allowNoOrigin is false', () => {
    const res = verifyHostAndOrigin({ host: 'localhost:3000' }, { allowNoOrigin: false });
    assert.strictEqual(res.valid, false);
    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.jsonRpcError?.error.code, -32600);
  });

  await test('verifyHostAndOrigin rejects null Origin when allowNullOrigin is false', () => {
    const res = verifyHostAndOrigin({ host: 'localhost:3000', origin: 'null' }, { allowNullOrigin: false });
    assert.strictEqual(res.valid, false);
    assert.strictEqual(res.statusCode, 403);
    assert.ok(res.reason?.includes("Origin 'null'"));
  });

  await test('verifyHostAndOrigin blocks untrusted browser cross-origin requests', () => {
    const res = verifyHostAndOrigin({ host: 'localhost:3000', origin: 'https://evil-site.com' });
    assert.strictEqual(res.valid, false);
    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.jsonRpcError?.error.code, -32600);
  });

  await test('verifyHostAndOrigin permits approved origins and origin wildcards', () => {
    const opts = { allowedOrigins: ['https://claude.ai', 'https://*.corp.internal'] };
    assert.strictEqual(verifyHostAndOrigin({ host: 'localhost:3000', origin: 'https://claude.ai' }, opts).valid, true);
    assert.strictEqual(verifyHostAndOrigin({ host: 'localhost:3000', origin: 'https://studio.corp.internal' }, opts).valid, true);
    assert.strictEqual(verifyHostAndOrigin({ host: 'localhost:3000', origin: 'https://other.com' }, opts).valid, false);
  });

  await test('createHostGuardMiddleware integrates with HTTP server handlers', () => {
    const middleware = createHostGuardMiddleware({ allowedHosts: ['localhost'] });

    let nextCalled = false;
    middleware({ headers: { host: 'localhost:3000' } }, {}, () => { nextCalled = true; });
    assert.strictEqual(nextCalled, true);

    let endedStatus = 0;
    let endedBody = '';
    const fakeRes = {
      statusCode: 200,
      setHeader: () => {},
      end: (b: string) => { endedBody = b; endedStatus = fakeRes.statusCode; }
    };
    middleware({ headers: { host: 'rebind.attacker.com' } }, fakeRes, () => {});
    assert.strictEqual(endedStatus, 403);
    assert.ok(endedBody.includes('-32600'));
  });

  // --------------------------------------------------------------------------
  // Module 10: Mid-Execution Auth Challenge & Token Revocation Handler
  // --------------------------------------------------------------------------
  console.log('\n[Module: Mid-Execution Auth Challenge & Token Revocation Handler]');

  await test('AuthChallengeError.invalidToken creates 401 challenge with invalid_token and defaults', () => {
    const err = AuthChallengeError.invalidToken();
    assert.strictEqual(err.status, 401);
    assert.strictEqual(err.authError, 'invalid_token');
    assert.strictEqual(err.errorDescription, 'Session revoked; re-authentication required');
    assert.strictEqual(err.scopes, undefined);
  });

  await test('AuthChallengeError.invalidToken rejects options specifying scopes', () => {
    assert.throws(
      () => new AuthChallengeError({ status: 401, scopes: ['read:data'] }),
      /Scopes must not be specified on an invalid_token/
    );
  });

  await test('AuthChallengeError.insufficientScope creates 403 challenge with required scopes', () => {
    const err = AuthChallengeError.insufficientScope(['read:reports', 'write:reports'], 'Report access needed');
    assert.strictEqual(err.status, 403);
    assert.strictEqual(err.authError, 'insufficient_scope');
    assert.deepStrictEqual(err.scopes, ['read:reports', 'write:reports']);
    assert.strictEqual(err.errorDescription, 'Report access needed');
  });

  await test('AuthChallengeError.insufficientScope throws if scopes array is empty or missing', () => {
    assert.throws(
      () => new AuthChallengeError({ status: 403, scopes: [] }),
      /must specify the missing required scopes/
    );
  });

  await test('AuthChallengeError.sanitizeDescription redacts vendor API keys and secrets', () => {
    const raw = 'Upstream API failed for sk-ant-api03-abcdef1234567890_test with ghp_123456789012345678901234567890123456';
    const sanitized = AuthChallengeError.sanitizeDescription(raw);
    assert.ok(!sanitized.includes('sk-ant-'));
    assert.ok(!sanitized.includes('ghp_'));
    assert.ok(sanitized.includes('[REDACTED_SECRET]'));
  });

  await test('AuthChallengeError.sanitizeDescription redacts database URIs and connection passwords', () => {
    const raw = 'Failed to connect to postgres://app_user:secret_password_123@db.prod.internal:5432/mcp';
    const sanitized = AuthChallengeError.sanitizeDescription(raw);
    assert.ok(!sanitized.includes('secret_password_123'));
    assert.ok(sanitized.includes('postgres://app_user:[REDACTED]@db.prod.internal:5432/mcp'));
  });

  await test('formatWwwAuthenticateHeader formats RFC 6750 Bearer challenge for 401 invalid_token', () => {
    const err = AuthChallengeError.invalidToken('Upstream session expired', 'https://auth.example.com/.well-known/oauth');
    const header = formatWwwAuthenticateHeader(err);
    assert.ok(header.startsWith('Bearer '));
    assert.ok(header.includes('error="invalid_token"'));
    assert.ok(header.includes('error_description="Upstream session expired"'));
    assert.ok(header.includes('resource_metadata="https://auth.example.com/.well-known/oauth"'));
    assert.ok(!header.includes('scope='));
  });

  await test('formatWwwAuthenticateHeader formats RFC 6750 Bearer challenge for 403 insufficient_scope', () => {
    const err = AuthChallengeError.insufficientScope(['tools:execute', 'admin'], 'Admin rights required');
    const header = formatWwwAuthenticateHeader(err);
    assert.ok(header.startsWith('Bearer '));
    assert.ok(header.includes('error="insufficient_scope"'));
    assert.ok(header.includes('scope="tools:execute admin"'));
    assert.ok(header.includes('error_description="Admin rights required"'));
  });

  await test('formatAuthChallengeJsonRpc emits JSON-RPC -32001 with reauthorize=true on 401 challenge', () => {
    const err = AuthChallengeError.invalidToken('Session revoked', 'https://auth.example.com/meta');
    const rpc = formatAuthChallengeJsonRpc('req-1', err);
    assert.strictEqual(rpc.jsonrpc, '2.0');
    assert.strictEqual(rpc.id, 'req-1');
    assert.strictEqual(rpc.error.code, -32001);
    assert.strictEqual(rpc.error.data.status, 401);
    assert.strictEqual(rpc.error.data.error, 'invalid_token');
    assert.strictEqual(rpc.error.data.reauthorize, true);
    assert.strictEqual(rpc.error.data.resourceMetadata, 'https://auth.example.com/meta');
    assert.strictEqual(rpc.error.data.scopes, undefined);
  });

  await test('formatAuthChallengeJsonRpc emits JSON-RPC -32003 with reauthorize=false and scopes on 403 challenge', () => {
    const err = AuthChallengeError.insufficientScope(['metrics:read']);
    const rpc = formatAuthChallengeJsonRpc(42, err);
    assert.strictEqual(rpc.id, 42);
    assert.strictEqual(rpc.error.code, -32003);
    assert.strictEqual(rpc.error.data.status, 403);
    assert.strictEqual(rpc.error.data.error, 'insufficient_scope');
    assert.strictEqual(rpc.error.data.reauthorize, false);
    assert.deepStrictEqual(rpc.error.data.scopes, ['metrics:read']);
  });

  await test('wrapToolHandlerWithAuthCheck passes through successful executions', async () => {
    const wrapped = wrapToolHandlerWithAuthCheck(async (args: { num: number }) => {
      return { result: args.num * 2 };
    });
    const res = await wrapped({ num: 21 });
    assert.deepStrictEqual(res, { result: 42 });
  });

  await test('wrapToolHandlerWithAuthCheck intercepts AuthChallengeError and formats structured payload', async () => {
    let capturedChallenge: any = null;
    const wrapped = wrapToolHandlerWithAuthCheck(
      async () => {
        throw AuthChallengeError.invalidToken('Upstream OAuth revoked');
      },
      {
        resourceMetadata: 'https://auth.corp.net',
        onChallenge: (c) => { capturedChallenge = c; }
      }
    );

    const res = await wrapped({});
    assert.strictEqual((res as any).isError, true);
    assert.ok((res as any).content[0].text.includes('[AUTH_CHALLENGE:401]'));
    assert.strictEqual((res as any)._authChallenge?.status, 401);
    assert.strictEqual((res as any)._authChallenge?.error, 'invalid_token');
    assert.ok((res as any)._authChallenge?.wwwAuthenticate.includes('error="invalid_token"'));
    assert.strictEqual(capturedChallenge?.status, 401);
  });

  await test('wrapToolHandlerWithAuthCheck rethrows unexpected errors without interference', async () => {
    const wrapped = wrapToolHandlerWithAuthCheck(async () => {
      throw new Error('Database disk full');
    });

    await assert.rejects(
      async () => await wrapped({}),
      /Database disk full/
    );
  });

  // --------------------------------------------------------------------------
  // Module 11: Structured Input Validator, Self-Healing Coercion & RFC 9457
  // --------------------------------------------------------------------------
  console.log('\n[Module: Structured Input Validator, Self-Healing Coercion & RFC 9457]');

  await test('normalizeToolArguments coerces integer and float strings to numbers', () => {
    const raw = { limit: '50', score: '98.6', text: 'normal string' };
    const normalized = normalizeToolArguments(raw);
    assert.strictEqual(normalized.limit, 50);
    assert.strictEqual(normalized.score, 98.6);
    assert.strictEqual(normalized.text, 'normal string');
  });

  await test('normalizeToolArguments coerces boolean strings', () => {
    const raw = { active: 'true', disabled: 'false', uppercase: 'TRUE' };
    const normalized = normalizeToolArguments(raw);
    assert.strictEqual(normalized.active, true);
    assert.strictEqual(normalized.disabled, false);
    assert.strictEqual(normalized.uppercase, true);
  });

  await test('normalizeToolArguments parses stringified JSON objects and arrays', () => {
    const raw = {
      config: '{"timeout": 5000, "debug": true}',
      tags: '["alpha", "beta", "gamma"]'
    };
    const normalized = normalizeToolArguments(raw);
    assert.deepStrictEqual(normalized.config, { timeout: 5000, debug: true });
    assert.deepStrictEqual(normalized.tags, ['alpha', 'beta', 'gamma']);
  });

  await test('normalizeToolArguments recurses into nested dictionaries', () => {
    const raw = {
      user: {
        id: '123',
        verified: 'true',
        metadata: { retryCount: '3' }
      }
    };
    const normalized = normalizeToolArguments(raw);
    assert.deepStrictEqual(normalized, {
      user: {
        id: 123,
        verified: true,
        metadata: { retryCount: 3 }
      }
    });
  });

  await test('normalizeToolArguments preserves non-numeric strings and invalid JSON without corruption', () => {
    const raw = { code: 'abc123', brokenJson: '{not a json' };
    const normalized = normalizeToolArguments(raw);
    assert.strictEqual(normalized.code, 'abc123');
    assert.strictEqual(normalized.brokenJson, '{not a json');
  });

  await test('normalizeToolArguments leaves values unchanged when coercion options are disabled', () => {
    const raw = { count: '100', flag: 'true' };
    const normalized = normalizeToolArguments(raw, { autoCoercePrimitives: false });
    assert.strictEqual(normalized.count, '100');
    assert.strictEqual(normalized.flag, 'true');
  });

  await test('buildProblemDetails formats RFC 9457 compliant Problem Details', () => {
    const issues = [
      { name: 'limit', path: ['limit'], reason: 'Too small: expected number to be >=1', received: 0, expected: '>=1' }
    ];
    const problem = buildProblemDetails('query_database', issues, { limit: 0, query: 'SELECT 1' });
    assert.strictEqual(problem.type, 'https://modelcontextprotocol.io/errors/invalid-tool-arguments');
    assert.strictEqual(problem.title, 'Invalid Tool Arguments');
    assert.strictEqual(problem.status, 400);
    assert.strictEqual(problem.tool, 'query_database');
    assert.strictEqual(problem.invalidParams.length, 1);
    assert.deepStrictEqual(problem.receivedKeys, ['limit', 'query']);
  });

  await test('buildProblemDetails identifies missingKeys against expectedKeys', () => {
    const issues = [{ name: 'query', path: ['query'], reason: 'Required field missing' }];
    const problem = buildProblemDetails('query_database', issues, { limit: 10 }, ['query', 'limit']);
    assert.deepStrictEqual(problem.expectedKeys, ['query', 'limit']);
    assert.deepStrictEqual(problem.missingKeys, ['query']);
    assert.ok(problem.hint?.includes('Missing required parameters: query'));
  });

  await test('formatValidationSummary produces readable multi-line summary for prompt injection', () => {
    const problem = buildProblemDetails(
      'search_users',
      [{ name: 'role', path: ['role'], reason: 'Invalid enum value', received: 'superadmin' }],
      { role: 'superadmin' },
      ['role', 'tenantId']
    );
    const summary = formatValidationSummary(problem);
    assert.ok(summary.includes("Input validation error for tool 'search_users':"));
    assert.ok(summary.includes("Parameter 'role': Invalid enum value"));
    assert.ok(summary.includes("Missing required: [tenantId]"));
    assert.ok(summary.includes("Received keys: [role]"));
  });

  await test('createStructuredToolHandler heals arguments and executes tool successfully', async () => {
    const schemaValidator = (args: Record<string, unknown>) => {
      if (typeof args.limit === 'number' && typeof args.active === 'boolean') {
        return { success: true as const, data: { limit: args.limit, active: args.active } };
      }
      return {
        success: false as const,
        issues: [{ name: 'args', path: [], reason: 'Type error' }]
      };
    };

    const handler = createStructuredToolHandler(
      'get_items',
      schemaValidator,
      async (args) => ({ retrieved: args.limit, status: args.active })
    );

    // Call with stringified primitives emitted by an LLM
    const res = await handler({ limit: '25', active: 'true' });
    assert.deepStrictEqual(res, { retrieved: 25, status: true });
  });

  await test('createStructuredToolHandler returns RFC 9457 structuredContent and isError=true on failure', async () => {
    const schemaValidator = (args: Record<string, unknown>) => {
      if (typeof args.query === 'string' && args.query.length > 0) {
        return { success: true as const, data: { query: args.query } };
      }
      return {
        success: false as const,
        issues: [{ name: 'query', path: ['query'], reason: 'String must contain at least 1 character(s)', received: '' }]
      };
    };

    const handler = createStructuredToolHandler(
      'search_docs',
      schemaValidator,
      async (args) => ({ found: [args.query] }),
      { expectedKeys: ['query'] }
    );

    const res = await handler({ query: '' });
    assert.strictEqual((res as any).isError, true);
    assert.ok((res as any).content[0].text.includes("Input validation error for tool 'search_docs'"));
    assert.strictEqual((res as any).structuredContent?.status, 400);
    assert.strictEqual((res as any).structuredContent?.tool, 'search_docs');
    assert.strictEqual((res as any).structuredContent?.invalidParams[0].name, 'query');
  });

  await test('createStructuredToolHandler supports custom onValidationError hook', async () => {
    const schemaValidator = () => ({
      success: false as const,
      issues: [{ name: 'id', path: ['id'], reason: 'Not found' }]
    });

    const handler = createStructuredToolHandler(
      'custom_tool',
      schemaValidator,
      async () => ({ ok: true }),
      {
        onValidationError: ({ toolName, problem }) => ({
          text: `CUSTOM_ERROR:${toolName}`,
          structuredContent: { customCode: 'ERR_INVALID_PAYLOAD', detail: problem }
        })
      }
    );

    const res = await handler({});
    assert.strictEqual((res as any).isError, true);
    assert.strictEqual((res as any).content[0].text, 'CUSTOM_ERROR:custom_tool');
    assert.strictEqual((res as any).structuredContent?.customCode, 'ERR_INVALID_PAYLOAD');
  });

  // --------------------------------------------------------------------------
  // Module 12: Lossless 64-Bit Integer & BigInt Codec
  // --------------------------------------------------------------------------
  console.log('\n[Module: Lossless 64-Bit Integer & BigInt Codec]');

  await test('isUnsafeIntegerString identifies safe vs unsafe integers accurately', () => {
    assert.strictEqual(isUnsafeIntegerString('42'), false);
    assert.strictEqual(isUnsafeIntegerString('9007199254740991'), false); // MAX_SAFE_INTEGER
    assert.strictEqual(isUnsafeIntegerString('-9007199254740991'), false); // MIN_SAFE_INTEGER
    assert.strictEqual(isUnsafeIntegerString('9007199254740993'), true); // 2^53 + 1
    assert.strictEqual(isUnsafeIntegerString('9223372036854775807'), true); // int64 max
    assert.strictEqual(isUnsafeIntegerString('-9223372036854775808'), true); // int64 min
    assert.strictEqual(isUnsafeIntegerString('not_a_number'), false);
  });

  await test('detectPrecisionLoss detects unsafe integers in raw JSON strings', () => {
    const raw = '{"userId": 9007199254740993, "amount": 500, "txId": 9223372036854775807}';
    const detection = detectPrecisionLoss(raw);
    assert.strictEqual(detection.hasUnsafeIntegers, true);
    assert.strictEqual(detection.unsafeTokens.length, 2);
    assert.ok(detection.unsafeTokens.includes('9007199254740993'));
    assert.ok(detection.unsafeTokens.includes('9223372036854775807'));
  });

  await test('detectPrecisionLoss reports false on standard safe JSON', () => {
    const raw = '{"id": 42, "ratio": 3.14159, "flag": true}';
    const detection = detectPrecisionLoss(raw);
    assert.strictEqual(detection.hasUnsafeIntegers, false);
    assert.strictEqual(detection.unsafeTokens.length, 0);
  });

  await test('parseExactJson preserves standard safe numbers as JavaScript numbers', () => {
    const raw = '{"count": 100, "pi": 3.14}';
    const parsed = parseExactJson(raw) as any;
    assert.strictEqual(typeof parsed.count, 'number');
    assert.strictEqual(parsed.count, 100);
    assert.strictEqual(parsed.pi, 3.14);
  });

  await test('parseExactJson revives 9007199254740993 as BigInt without IEEE 754 rounding', () => {
    const raw = '{"snowflake": 9007199254740993}';
    const parsed = parseExactJson(raw) as any;
    assert.strictEqual(typeof parsed.snowflake, 'bigint');
    assert.strictEqual(parsed.snowflake, 9007199254740993n);
    assert.notStrictEqual(parsed.snowflake, 9007199254740992n);
  });

  await test('parseExactJson revives int64 max and min bounds exactly', () => {
    const raw = '{"max": 9223372036854775807, "min": -9223372036854775808}';
    const parsed = parseExactJson(raw) as any;
    assert.strictEqual(parsed.max, 9223372036854775807n);
    assert.strictEqual(parsed.min, -9223372036854775808n);
  });

  await test('parseExactJson supports useBigInt=false returning raw string', () => {
    const raw = '{"id": 9007199254740993}';
    const parsed = parseExactJson(raw, { useBigInt: false }) as any;
    assert.strictEqual(parsed.id, '9007199254740993');
  });

  await test('stringifyExactJson serializes BigInt without throwing TypeError', () => {
    const obj = { id: 9007199254740993n, name: 'record' };
    assert.doesNotThrow(() => stringifyExactJson(obj));
  });

  await test('stringifyExactJson in raw_number mode emits unquoted numeric tokens', () => {
    const obj = { id: 9007199254740993n, active: true };
    const json = stringifyExactJson(obj, { bigIntSerialization: 'raw_number' });
    assert.ok(json.includes('"id":9007199254740993') || json.includes('"id": 9007199254740993'));
    assert.ok(!json.includes('"id":"9007199254740993"'));
  });

  await test('stringifyExactJson in string mode emits quoted string tokens', () => {
    const obj = { id: 9007199254740993n };
    const json = stringifyExactJson(obj, { bigIntSerialization: 'string' });
    assert.ok(json.includes('"id":"9007199254740993"'));
  });

  await test('parseExactJson and stringifyExactJson achieve round-trip token-for-token fidelity', () => {
    const original = '{"big":9007199254740993,"int64Max":9223372036854775807,"safe":42}';
    const decoded = parseExactJson(original);
    const reEncoded = stringifyExactJson(decoded);
    assert.strictEqual(reEncoded, original);
  });

  await test('wrapToolResultWithExactNumbers packages BigInt results cleanly for MCP responses', () => {
    const toolOutput = {
      recordId: 9223372036854775807n,
      txHash: '0x123',
      timestampNs: 1716382910123456789n
    };
    const wrapped = wrapToolResultWithExactNumbers(toolOutput);
    assert.strictEqual(wrapped.content[0].type, 'text');
    assert.ok(wrapped.content[0].text.includes('9223372036854775807'));
    assert.ok(wrapped.content[0].text.includes('1716382910123456789'));
    assert.strictEqual(wrapped.structuredContent.recordId, 9223372036854775807n);
  });

  // --------------------------------------------------------------------------
  // Module 13: Zero-Overhead JSON-RPC Message Classifier & Fast-Path Dispatcher
  // --------------------------------------------------------------------------
  console.log('\n[Module: Zero-Overhead JSON-RPC Message Classifier & Fast-Path Dispatcher]');

  await test('classifyJsonRpcMessage classifies valid JSON-RPC request with string id', () => {
    const raw = { jsonrpc: '2.0', id: 'call-1', method: 'tools/call', params: { name: 'echo' } };
    const msg = classifyJsonRpcMessage(raw);
    assert.strictEqual(msg.kind, 'request');
    assert.strictEqual(msg.id, 'call-1');
    assert.strictEqual(msg.method, 'tools/call');
    assert.deepStrictEqual(msg.params, { name: 'echo' });
  });

  await test('classifyJsonRpcMessage classifies valid JSON-RPC request with numeric id', () => {
    const raw = { jsonrpc: '2.0', id: 42, method: 'tools/list' };
    const msg = classifyJsonRpcMessage(raw);
    assert.strictEqual(msg.kind, 'request');
    assert.strictEqual(msg.id, 42);
    assert.strictEqual(msg.method, 'tools/list');
  });

  await test('classifyJsonRpcMessage classifies valid JSON-RPC notification without id', () => {
    const raw = { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 42 } };
    const msg = classifyJsonRpcMessage(raw);
    assert.strictEqual(msg.kind, 'notification');
    assert.strictEqual(msg.id, undefined);
    assert.strictEqual(msg.method, 'notifications/cancelled');
  });

  await test('classifyJsonRpcMessage classifies valid JSON-RPC success response with result', () => {
    const raw = { jsonrpc: '2.0', id: 10, result: { content: [{ type: 'text', text: 'ok' }] } };
    const msg = classifyJsonRpcMessage(raw);
    assert.strictEqual(msg.kind, 'success_response');
    assert.strictEqual(msg.id, 10);
    assert.deepStrictEqual(msg.result, { content: [{ type: 'text', text: 'ok' }] });
  });

  await test('classifyJsonRpcMessage classifies valid JSON-RPC error response with code and message', () => {
    const raw = { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request', data: { detail: 'corrupt' } } };
    const msg = classifyJsonRpcMessage(raw);
    assert.strictEqual(msg.kind, 'error_response');
    assert.strictEqual(msg.id, null);
    assert.strictEqual(msg.error?.code, -32600);
    assert.strictEqual(msg.error?.message, 'Invalid Request');
    assert.deepStrictEqual(msg.error?.data, { detail: 'corrupt' });
  });

  await test('classifyJsonRpcMessage rejects non-object or null input as invalid', () => {
    assert.strictEqual(classifyJsonRpcMessage(null).kind, 'invalid');
    assert.strictEqual(classifyJsonRpcMessage('string').kind, 'invalid');
    assert.strictEqual(classifyJsonRpcMessage(123).kind, 'invalid');
  });

  await test('classifyJsonRpcMessage rejects missing or incorrect jsonrpc version', () => {
    assert.strictEqual(classifyJsonRpcMessage({ id: 1, method: 'test' }).kind, 'invalid');
    assert.strictEqual(classifyJsonRpcMessage({ jsonrpc: '1.0', id: 1, method: 'test' }).kind, 'invalid');
  });

  await test('classifyJsonRpcMessage rejects request with invalid id type (e.g. object or boolean)', () => {
    assert.strictEqual(classifyJsonRpcMessage({ jsonrpc: '2.0', id: { bad: true }, method: 'test' }).kind, 'invalid');
    assert.strictEqual(classifyJsonRpcMessage({ jsonrpc: '2.0', id: true, method: 'test' }).kind, 'invalid');
  });

  await test('classifyJsonRpcMessage rejects response with invalid id (e.g. array)', () => {
    assert.strictEqual(classifyJsonRpcMessage({ jsonrpc: '2.0', id: [1, 2], result: {} }).kind, 'invalid');
  });

  await test('classifyJsonRpcMessage rejects empty method string', () => {
    assert.strictEqual(classifyJsonRpcMessage({ jsonrpc: '2.0', id: 1, method: '' }).kind, 'invalid');
  });

  await test('classifyJsonRpcPayload parses batch array with mixed requests and notifications', () => {
    const batch = [
      { jsonrpc: '2.0', id: 1, method: 'tools/list' },
      { jsonrpc: '2.0', method: 'notifications/initialized' },
      { jsonrpc: '2.0', id: 2, result: { tools: [] } }
    ];
    const msgs = classifyJsonRpcPayload(batch);
    assert.strictEqual(msgs.length, 3);
    assert.strictEqual(msgs[0].kind, 'request');
    assert.strictEqual(msgs[1].kind, 'notification');
    assert.strictEqual(msgs[2].kind, 'success_response');
  });

  await test('classifyJsonRpcPayload rejects empty batch array as invalid', () => {
    const msgs = classifyJsonRpcPayload([]);
    assert.strictEqual(msgs.length, 1);
    assert.strictEqual(msgs[0].kind, 'invalid');
  });

  await test('FastPathDispatcher routes requests and notifications cleanly', async () => {
    const dispatcher = new FastPathDispatcher();
    let reqRan = false;
    let notifRan = false;

    await dispatcher.dispatch(
      { jsonrpc: '2.0', id: 1, method: 'tools/call' },
      {
        onRequest: () => { reqRan = true; return 'req_ok'; },
        onNotification: () => { notifRan = true; }
      },
      {}
    );
    assert.strictEqual(reqRan, true);

    await dispatcher.dispatch(
      { jsonrpc: '2.0', method: 'notifications/progress' },
      {
        onRequest: () => {},
        onNotification: () => { notifRan = true; }
      },
      {}
    );
    assert.strictEqual(notifRan, true);
  });

  await test('FastPathDispatcher tracks performance metrics and latency', async () => {
    const dispatcher = new FastPathDispatcher();
    await dispatcher.dispatch({ jsonrpc: '2.0', id: 1, method: 'm1' }, { onRequest: () => 1, onNotification: () => {} }, {});
    await dispatcher.dispatch({ jsonrpc: '2.0', id: 2, method: 'm2' }, { onRequest: () => 2, onNotification: () => {} }, {});
    await dispatcher.dispatch({ jsonrpc: '2.0', method: 'n1' }, { onRequest: () => {}, onNotification: () => {} }, {});

    const metrics = dispatcher.getMetrics();
    assert.strictEqual(metrics.totalProcessed, 3);
    assert.strictEqual(metrics.requestsCount, 2);
    assert.strictEqual(metrics.notificationsCount, 1);
    assert.ok(metrics.averageLatencyNs >= 0);
  });

  // =========================================================================
  // Module 15: HTTP & SSE Stream Lifecycle, Slowloris Guard & Instant Disconnect
  // =========================================================================
  console.log('\n[Module: HTTP & SSE Stream Lifecycle Guard & Slowloris Defense]');

  await test('readWebStream reads valid JSON payload within size and arrival deadlines', async () => {
    const guard = new StreamLifecycleGuard();
    const encoder = new TextEncoder();
    const payload = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' });

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(payload.slice(0, 10)));
        controller.enqueue(encoder.encode(payload.slice(10)));
        controller.close();
      }
    });

    const res = await guard.readWebStream(stream, { maxBytes: 1024, bodyTimeoutMs: 2000 });
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.bytesRead, payload.length);
    assert.deepStrictEqual(res.json, { jsonrpc: '2.0', id: 1, method: 'tools/list' });
  });

  await test('readWebStream rejects oversized body with 413 and cancels reader', async () => {
    const guard = new StreamLifecycleGuard();
    const encoder = new TextEncoder();
    let readerCancelled = false;

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('chunk-one-is-15-bytes-long'));
        controller.enqueue(encoder.encode('chunk-two-pushes-over-limit'));
        controller.close();
      },
      cancel() {
        readerCancelled = true;
      }
    });

    const res = await guard.readWebStream(stream, { maxBytes: 20, bodyTimeoutMs: 2000 });
    assert.strictEqual(res.success, false);
    assert.strictEqual(res.errorCode, 'PAYLOAD_TOO_LARGE');
    assert.strictEqual(res.statusCode, 413);
    assert.strictEqual(res.jsonRpcError?.error.code, -32600);
    assert.strictEqual(readerCancelled, true);
  });

  await test('readWebStream returns 408 on body arrival timeout and cancels reader (Slowloris)', async () => {
    const guard = new StreamLifecycleGuard();
    const encoder = new TextEncoder();
    let cancelCalled = false;

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('{"jsonrpc":"2.0",'));
      },
      cancel() {
        cancelCalled = true;
      }
    });

    const res = await guard.readWebStream(stream, { maxBytes: 1024, bodyTimeoutMs: 50 });
    assert.strictEqual(res.success, false);
    assert.strictEqual(res.errorCode, 'BODY_TIMEOUT');
    assert.strictEqual(res.statusCode, 408);
    assert.strictEqual(res.jsonRpcError?.error.code, -32000);
    assert.strictEqual(cancelCalled, true);
  });

  await test('readWebStream cancels reader on external AbortSignal (499)', async () => {
    const guard = new StreamLifecycleGuard();
    const controller = new AbortController();
    const encoder = new TextEncoder();
    let cancelCalled = false;

    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(encoder.encode('first-part'));
      },
      cancel() {
        cancelCalled = true;
      }
    });

    setTimeout(() => controller.abort(), 20);
    const res = await guard.readWebStream(stream, { maxBytes: 1024, bodyTimeoutMs: 5000, signal: controller.signal });
    assert.strictEqual(res.success, false);
    assert.strictEqual(res.errorCode, 'CLIENT_ABORTED');
    assert.strictEqual(res.statusCode, 499);
    assert.strictEqual(res.jsonRpcError?.error.code, -32800);
    assert.strictEqual(cancelCalled, true);
  });

  await test('readNodeStream reads standard Node.js readable streams successfully', async () => {
    const guard = new StreamLifecycleGuard();
    const payload = JSON.stringify({ jsonrpc: '2.0', id: 42, method: 'ping' });
    const nodeStream = Readable.from([Buffer.from(payload)]);

    const res = await guard.readNodeStream(nodeStream, { maxBytes: 1024, bodyTimeoutMs: 2000 });
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.text, payload);
    assert.deepStrictEqual(res.json, { jsonrpc: '2.0', id: 42, method: 'ping' });
  });

  await test('readNodeStream enforces maxBytes and destroys stream on oversized payload', async () => {
    const guard = new StreamLifecycleGuard();
    const chunks = [Buffer.from('hello-world-chunk-one'), Buffer.from('hello-world-chunk-two')];
    const nodeStream = Readable.from(chunks);

    const res = await guard.readNodeStream(nodeStream, { maxBytes: 15, bodyTimeoutMs: 2000 });
    assert.strictEqual(res.success, false);
    assert.strictEqual(res.errorCode, 'PAYLOAD_TOO_LARGE');
    assert.strictEqual(res.statusCode, 413);
  });

  await test('readNodeStream enforces body arrival timeout on stalled stream (Slowloris)', async () => {
    const guard = new StreamLifecycleGuard();
    let pushed = false;
    const stalledStream = new Readable({
      read() {
        if (!pushed) {
          pushed = true;
          this.push(Buffer.from('{'));
        }
      }
    });

    const res = await guard.readNodeStream(stalledStream, { maxBytes: 1024, bodyTimeoutMs: 50 });
    assert.strictEqual(res.success, false);
    assert.strictEqual(res.errorCode, 'BODY_TIMEOUT');
    assert.strictEqual(res.statusCode, 408);
  });

  await test('pumpSseStream pumps chunks and handles backpressure drain', async () => {
    const guard = new StreamLifecycleGuard();
    const encoder = new TextEncoder();
    const chunksReceived: string[] = [];

    const source = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(encoder.encode('event: message\ndata: hello\n\n'));
        c.enqueue(encoder.encode('event: message\ndata: world\n\n'));
        c.close();
      }
    });

    const mockTarget = new EventEmitter() as any;
    mockTarget.write = (chunk: Uint8Array) => {
      chunksReceived.push(new TextDecoder().decode(chunk));
      return true;
    };
    mockTarget.end = () => {};

    await guard.pumpSseStream(source, mockTarget);
    assert.strictEqual(chunksReceived.length, 2);
    assert.ok(chunksReceived[0].includes('hello'));
    assert.ok(chunksReceived[1].includes('world'));
  });

  await test('pumpSseStream instantly cancels reader and triggers onDisconnect when client disconnects (resolves #3148)', async () => {
    const guard = new StreamLifecycleGuard();
    let readerCancelled = false;
    let disconnectReason = '';

    const source = new ReadableStream<Uint8Array>({
      start(c) {},
      cancel(reason) {
        readerCancelled = true;
      }
    });

    const mockTarget = new EventEmitter() as any;
    mockTarget.write = () => true;
    mockTarget.end = () => {};

    const pumpPromise = guard.pumpSseStream(source, mockTarget, {
      onDisconnect: (reason) => {
        disconnectReason = reason;
      }
    });

    mockTarget.emit('close');
    await pumpPromise;

    assert.strictEqual(readerCancelled, true);
    assert.ok(disconnectReason.includes('Client socket disconnected'));
  });

  await test('StreamLifecycleGuard telemetry tracks reads, timeouts and instant disconnects', async () => {
    const guard = new StreamLifecycleGuard();
    const encoder = new TextEncoder();

    const s1 = new ReadableStream<Uint8Array>({
      start(c) { c.enqueue(encoder.encode('{"ok":true}')); c.close(); }
    });
    await guard.readWebStream(s1);

    const s2 = new ReadableStream<Uint8Array>({
      start(c) { c.enqueue(encoder.encode('{')); }
    });
    await guard.readWebStream(s2, { bodyTimeoutMs: 20 });

    const tel = guard.getTelemetry();
    assert.strictEqual(tel.totalReads, 2);
    assert.strictEqual(tel.successfulReads, 1);
    assert.strictEqual(tel.timedOutReads, 1);
  });

  // =========================================================================
  // Module 16: Filesystem Containment, Path Traversal Defense & Atomic Safe I/O
  // =========================================================================
  console.log('\n[Module: Filesystem Containment, Path Traversal Defense & Atomic I/O]');

  const testTempRoot = path.join(os.tmpdir(), `mcp_fs_test_${Date.now()}`);
  fs.mkdirSync(testTempRoot, { recursive: true });

  await test('resolveWithin resolves safe relative subpaths within workspace root', () => {
    const resolved = resolveWithin(testTempRoot, 'data/report.json');
    assert.strictEqual(resolved, path.resolve(testTempRoot, 'data', 'report.json'));
  });

  await test('resolveWithin handles nested directories and clean relative tokens', () => {
    const resolved = resolveWithin(testTempRoot, './sub/dir/../file.txt');
    assert.strictEqual(resolved, path.resolve(testTempRoot, 'sub', 'file.txt'));
  });

  await test('resolveWithin blocks directory traversal escape vectors (../../etc/passwd)', () => {
    assert.throws(() => {
      resolveWithin(testTempRoot, '../../../../etc/passwd');
    }, (err: any) => {
      return err instanceof PathTraversalError && err.code === 'PATH_TRAVERSAL_DETECTED';
    });
  });

  await test('resolveWithin blocks sibling directory breakout prefix bypass', () => {
    const fakeRoot = path.join(testTempRoot, 'workspace');
    fs.mkdirSync(fakeRoot, { recursive: true });

    assert.throws(() => {
      resolveWithin(fakeRoot, '../workspace_evil/payload.sh');
    }, (err: any) => {
      return err instanceof PathTraversalError;
    });
  });

  await test('resolveWithin strictly rejects absolute paths by default to surface injection signals', () => {
    assert.throws(() => {
      resolveWithin(testTempRoot, '/etc/shadow');
    }, (err: any) => {
      return err instanceof PathTraversalError && err.message.includes('Absolute path escape rejected');
    });

    assert.throws(() => {
      resolveWithin(testTempRoot, 'C:\\Windows\\System32\\cmd.exe');
    }, (err: any) => {
      return err instanceof PathTraversalError && err.message.includes('Absolute path escape rejected');
    });
  });

  await test('resolveWithin supports opt-in absolute path remapping when rejectAbsolute is false', () => {
    const remapped = resolveWithin(testTempRoot, '/etc/shadow', { rejectAbsolute: false });
    assert.strictEqual(remapped, path.resolve(testTempRoot, 'etc', 'shadow'));
  });

  await test('resolveWithin rejects null byte injection attempts', () => {
    assert.throws(() => {
      resolveWithin(testTempRoot, 'safe.txt\0/../../root');
    }, (err: any) => {
      return err instanceof PathTraversalError && err.message.includes('Null byte');
    });
  });

  await test('resolveWithin blocks Windows DOS reserved device names across all segments and superscripts', () => {
    // Basename check
    assert.throws(() => {
      resolveWithin(testTempRoot, 'con.txt');
    }, (err: any) => {
      return err instanceof PathTraversalError && err.message.includes('reserved system device');
    });

    // Directory component check (e.g. CON/x.txt)
    assert.throws(() => {
      resolveWithin(testTempRoot, 'CON/sub_report.txt');
    }, (err: any) => {
      return err instanceof PathTraversalError && err.message.includes('reserved system device');
    });

    // Nested directory component check (e.g. data/NUL/record.bin)
    assert.throws(() => {
      resolveWithin(testTempRoot, 'data/nul/record.bin');
    }, (err: any) => {
      return err instanceof PathTraversalError && err.message.includes('reserved system device');
    });

    // ISO 8859-1 superscript form (COM¹ / LPT²)
    assert.throws(() => {
      resolveWithin(testTempRoot, 'com\u00B9.log');
    }, (err: any) => {
      return err instanceof PathTraversalError && err.message.includes('reserved system device');
    });
  });

  await test('resolveWithin blocks symlink escape when ancestor directory is linked outside root', () => {
    const outsideTarget = path.join(os.tmpdir(), `mcp_outside_${Date.now()}`);
    fs.mkdirSync(outsideTarget, { recursive: true });

    const symlinkDir = path.join(testTempRoot, 'shared_symlink');
    try {
      fs.symlinkSync(outsideTarget, symlinkDir, 'junction');

      assert.throws(() => {
        resolveWithin(testTempRoot, 'shared_symlink/authorized_keys');
      }, (err: any) => {
        return err instanceof PathTraversalError && err.message.includes('Symlink boundary escape detected');
      });
    } catch (e: any) {
      // If OS requires elevated privileges for symlinks (non-admin Windows), skip silently
      if (e.code !== 'EPERM') throw e;
    }
  });

  await test('resolveWithin blocks sensitive configured files (.env, authorized_keys, id_rsa)', () => {
    const opts = { blockedFileNames: ['.env', 'authorized_keys', 'id_rsa'] };
    assert.throws(() => {
      resolveWithin(testTempRoot, '.env', opts);
    }, (err: any) => {
      return err instanceof PathTraversalError && err.message.includes('blocked by security policy');
    });

    assert.throws(() => {
      resolveWithin(testTempRoot, 'sub/nested/id_rsa', opts);
    }, (err: any) => {
      return err instanceof PathTraversalError && err.message.includes('blocked by security policy');
    });
  });

  await test('resolveWithin blocks hidden files when blockHiddenFiles is enabled', () => {
    assert.throws(() => {
      resolveWithin(testTempRoot, '.secret_config', { blockHiddenFiles: true });
    }, (err: any) => {
      return err instanceof PathTraversalError && err.message.includes('hidden path segment');
    });
  });

  await test('safeWriteFile writes atomically and safeReadFile retrieves content', async () => {
    const writeResult = await safeWriteFile(testTempRoot, 'reports/2026/audit.txt', 'audit-log-content');
    assert.strictEqual(writeResult.bytesWritten, 'audit-log-content'.length);
    assert.ok(fs.existsSync(writeResult.resolvedPath));

    const readResult = await safeReadFile(testTempRoot, 'reports/2026/audit.txt');
    assert.strictEqual(readResult.text, 'audit-log-content');
  });

  await test('PathTraversalError formats valid JSON-RPC 2.0 -32602 error envelope', () => {
    const err = new PathTraversalError('Path traversal detected', '../../escape.sh', testTempRoot);
    const rpc = err.toJsonRpcError('req-99');
    assert.strictEqual(rpc.jsonrpc, '2.0');
    assert.strictEqual(rpc.id, 'req-99');
    assert.strictEqual(rpc.error.code, -32602);
    assert.strictEqual(rpc.error.data.code, 'PATH_TRAVERSAL_DETECTED');
    assert.strictEqual(rpc.error.data.attemptedPath, '../../escape.sh');
  });

  // =========================================================================
  // Module 17: Resilient SSE Reconnect & Handshake Teardown Guard
  // =========================================================================
  console.log('\n[Module: Resilient SSE Reconnect & Handshake Teardown Guard]');

  await test('calculateBackoffDelay calculates bounded exponential delays', () => {
    const d1 = calculateBackoffDelay(1, 500, 10000, 2.0, false);
    const d2 = calculateBackoffDelay(2, 500, 10000, 2.0, false);
    const d3 = calculateBackoffDelay(3, 500, 10000, 2.0, false);
    const d10 = calculateBackoffDelay(10, 500, 5000, 2.0, false);

    assert.strictEqual(d1, 500);
    assert.strictEqual(d2, 1000);
    assert.strictEqual(d3, 2000);
    assert.strictEqual(d10, 5000);
  });

  await test('isNonRetryableError correctly identifies permanent HTTP status codes', () => {
    assert.strictEqual(isNonRetryableError({ status: 401 }), true);
    assert.strictEqual(isNonRetryableError({ statusCode: 403 }), true);
    assert.strictEqual(isNonRetryableError({ status_code: 404 }), true);
    assert.strictEqual(isNonRetryableError(new Error('Unauthorized access')), true);
    assert.strictEqual(isNonRetryableError(new Error('ECONNREFUSED 127.0.0.1')), false);
    assert.strictEqual(isNonRetryableError({ status: 503 }), false);
  });

  await test('connectWithGuard completes successfully on clean connection', async () => {
    const controller = new ResilientSseClientController();
    let closed = false;
    const mockSource = { close: () => { closed = true; } };

    const source = await controller.connectWithGuard(async () => mockSource);
    assert.strictEqual(source, mockSource);
    assert.strictEqual(closed, false);
    controller.close();
    assert.strictEqual(closed, true);
  });

  await test('connectWithGuard immediately closes EventSource when connect rejects (resolves #3193)', async () => {
    const controller = new ResilientSseClientController();

    await assert.rejects(async () => {
      await controller.connectWithGuard(async () => {
        throw new Error('TypeError: fetch failed: connect ECONNREFUSED');
      });
    });

    assert.strictEqual(controller.isClosed(), false);
    const tel = ResilientSseClientController.getTelemetry();
    assert.ok(tel.handshakeFailuresHandled >= 1);
  });

  await test('connectWithGuard aborts and closes when handshake exceeds timeout', async () => {
    const controller = new ResilientSseClientController({ handshakeTimeoutMs: 50 });

    await assert.rejects(async () => {
      await controller.connectWithGuard(() => {
        return new Promise((resolve) => {
          setTimeout(() => resolve({ close: () => {} }), 200);
        });
      });
    }, (err: any) => {
      return err instanceof SseTeardownError && err.message.includes('handshake timed out');
    });
  });

  await test('handleStreamError terminates immediately on non-retryable 401 error', () => {
    const controller = new ResilientSseClientController();
    let retryScheduled = false;

    const willRetry = controller.handleStreamError(new Error('401 Unauthorized'), () => {
      retryScheduled = true;
    });

    assert.strictEqual(willRetry, false);
    assert.strictEqual(retryScheduled, false);
    assert.strictEqual(controller.isClosed(), true);
  });

  await test('handleStreamError terminates and exhausts retries at maxRetries limit', () => {
    const controller = new ResilientSseClientController({ maxRetries: 2 });
    let terminalErr: any = null;
    controller.on('error', (err) => { terminalErr = err; });

    const r1 = controller.handleStreamError(new Error('ECONNRESET'), () => {});
    assert.strictEqual(r1, true);

    const r2 = controller.handleStreamError(new Error('ECONNRESET'), () => {});
    assert.strictEqual(r2, true);

    const r3 = controller.handleStreamError(new Error('ECONNRESET'), () => {});
    assert.strictEqual(r3, false);
    assert.strictEqual(controller.isClosed(), true);
    assert.ok(terminalErr instanceof SseTeardownError);
    assert.strictEqual(terminalErr.isTerminal, true);
  });

  await test('wrapTransportWithTeardownGuard invokes close on rejected start', async () => {
    let closeCalled = false;
    const mockTransport = {
      start: async () => {
        throw new Error('SSE connect failed');
      },
      close: async () => {
        closeCalled = true;
      }
    };

    const guarded = wrapTransportWithTeardownGuard(mockTransport);
    await assert.rejects(async () => {
      await guarded.start();
    });

    assert.strictEqual(closeCalled, true);
  });

  console.log('\n[Module: Stdio Lifecycle, Monotonic Epoch Fence & Subprocess Reaper]');

  await test('TransportEpochFence advances epoch monotonically on each fenced transport', () => {
    const fence = new TransportEpochFence();
    assert.strictEqual(fence.getActiveEpoch(), 0);

    const t1: any = { close: async () => {} };
    fence.fenceTransport(t1);
    assert.strictEqual(fence.getActiveEpoch(), 1);

    const t2: any = { close: async () => {} };
    fence.fenceTransport(t2);
    assert.strictEqual(fence.getActiveEpoch(), 2);
  });

  await test('TransportEpochFence suppresses stale onclose from a previous epoch (resolves #3194)', () => {
    const fence = new TransportEpochFence();
    let originalCloseCalled = false;
    let suppressedEvent: any = null;
    fence.on('stale_event_suppressed', (info) => { suppressedEvent = info; });

    const t1: any = {
      close: async () => {},
      onclose: () => { originalCloseCalled = true; }
    };
    fence.fenceTransport(t1);

    const t2: any = { close: async () => {} };
    fence.fenceTransport(t2); // advances to epoch 2

    // Now t1 emits close event (late exit from old child process)
    t1.onclose();

    assert.strictEqual(originalCloseCalled, false);
    assert.ok(suppressedEvent);
    assert.strictEqual(suppressedEvent.staleEpoch, 1);
    assert.strictEqual(suppressedEvent.activeEpoch, 2);
    assert.strictEqual(suppressedEvent.eventType, 'close');
  });

  await test('TransportEpochFence suppresses stale onerror from a previous epoch', () => {
    const fence = new TransportEpochFence();
    let originalErrorCalled = false;
    let suppressedEvent: any = null;
    fence.on('stale_event_suppressed', (info) => { suppressedEvent = info; });

    const t1: any = {
      close: async () => {},
      onerror: () => { originalErrorCalled = true; }
    };
    fence.fenceTransport(t1);

    const t2: any = { close: async () => {} };
    fence.fenceTransport(t2);

    t1.onerror(new Error('Old connection reset'));

    assert.strictEqual(originalErrorCalled, false);
    assert.ok(suppressedEvent);
    assert.strictEqual(suppressedEvent.eventType, 'error');
  });

  await test('TransportEpochFence suppresses stale onmessage from a previous epoch', () => {
    const fence = new TransportEpochFence();
    let originalMsgCalled = false;
    let suppressedEvent: any = null;
    fence.on('stale_event_suppressed', (info) => { suppressedEvent = info; });

    const t1: any = {
      close: async () => {},
      onmessage: () => { originalMsgCalled = true; }
    };
    fence.fenceTransport(t1);

    const t2: any = { close: async () => {} };
    fence.fenceTransport(t2);

    t1.onmessage({ jsonrpc: '2.0', result: 'stale' });

    assert.strictEqual(originalMsgCalled, false);
    assert.ok(suppressedEvent);
    assert.strictEqual(suppressedEvent.eventType, 'message');
  });

  await test('TransportEpochFence allows active epoch events to trigger original handlers', () => {
    const fence = new TransportEpochFence();
    let closeFired = false;
    let errorFired = false;
    let messageFired = false;

    const t1: any = {
      close: async () => {},
      onclose: () => { closeFired = true; },
      onerror: (err: any) => { errorFired = true; },
      onmessage: (msg: any) => { messageFired = true; }
    };

    fence.fenceTransport(t1);
    t1.onmessage('hello');
    t1.onerror(new Error('active err'));
    t1.onclose();

    assert.strictEqual(messageFired, true);
    assert.strictEqual(errorFired, true);
    assert.strictEqual(closeFired, true);
  });

  await test('connectWithFence awaits transport.close() before rethrowing on failed handshake', async () => {
    const fence = new TransportEpochFence();
    let closeSettled = false;
    let closeFinishedBeforeRethrow = false;

    const mockTransport: any = {
      close: async () => {
        await new Promise((r) => setTimeout(r, 20));
        closeSettled = true;
      }
    };

    const mockClient: any = {
      connect: async () => {
        throw new Error('Unsupported protocol version: 1999-01-01');
      }
    };

    try {
      await fence.connectWithFence(mockClient, () => mockTransport);
      assert.fail('Should have thrown');
    } catch (err: any) {
      closeFinishedBeforeRethrow = closeSettled;
      assert.ok(err.message.includes('Unsupported protocol version'));
    }

    assert.strictEqual(closeFinishedBeforeRethrow, true);
  });

  await test('connectWithFence disarms client.transport so stale transport is not visible in catch block', async () => {
    const fence = new TransportEpochFence();
    const mockTransport: any = {
      close: async () => {}
    };

    const mockClient: any = {
      transport: undefined,
      connect: async (t: any) => {
        mockClient.transport = t;
        throw new Error('Handshake rejected');
      }
    };

    let observedTransportInCatch: any = 'UNCHECKED';

    try {
      await fence.connectWithFence(mockClient, () => mockTransport);
    } catch (err) {
      observedTransportInCatch = mockClient.transport;
    }

    assert.strictEqual(observedTransportInCatch, undefined);
  });

  await test('Simulated #3194 reproduction: Retried connect succeeds despite late exit event from first child', async () => {
    const fence = new TransportEpochFence();

    let activeClientTransport: any = undefined;
    let inFlightHandshakeCancelled = false;

    const mockClient: any = {
      get transport() {
        return activeClientTransport;
      },
      set transport(t) {
        activeClientTransport = t;
      },
      close: async () => {
        if (activeClientTransport) await activeClientTransport.close();
      }
    };

    const t1: any = {
      close: async () => {
        setTimeout(() => {
          if (t1.onclose) t1.onclose();
        }, 15);
      }
    };

    let connect1Failed = false;
    try {
      await fence.connectWithFence(mockClient, () => {
        t1.onclose = () => {
          activeClientTransport = undefined;
          inFlightHandshakeCancelled = true;
        };
        return t1;
      });
    } catch {
      connect1Failed = true;
    }

    assert.strictEqual(connect1Failed, true);

    let t2Connected = false;
    const t2: any = {
      close: async () => {}
    };

    await fence.connectWithFence(mockClient, () => {
      mockClient.connect = async (t: any) => {
        mockClient.transport = t;
        await new Promise((r) => setTimeout(r, 25));
        if (inFlightHandshakeCancelled) {
          throw new Error('CONNECTION_CLOSED Connection closed');
        }
        t2Connected = true;
      };
      return t2;
    });

    assert.strictEqual(t2Connected, true);
    assert.strictEqual(inFlightHandshakeCancelled, false);
  });

  await test('connectWithFailover walks candidates sequentially and settles on working candidate', async () => {
    const fence = new TransportEpochFence({ retryDelayMs: 5 });
    const mockClient: any = {
      connect: async (t: any) => {
        if (t.isBad) throw new Error('Bad transport');
      }
    };

    const res = await fence.connectWithFailover(mockClient, [
      () => ({ isBad: true, close: async () => {} } as any),
      () => ({ isBad: true, close: async () => {} } as any),
      () => ({ isBad: false, close: async () => {} } as any)
    ]);

    assert.strictEqual(res.attempts, 3);
    assert.strictEqual(res.successfulIndex, 2);
  });

  await test('reapProcessTree handles non-existent or 0 PID cleanly without throwing', async () => {
    const res1 = await reapProcessTree(0);
    assert.strictEqual(res1, true);

    const res2 = await reapProcessTree(-1);
    assert.strictEqual(res2, true);

    const res3 = await reapProcessTree(999999);
    assert.strictEqual(res3, true);
  });

  await test('wrapClientWithLifecycleGuard exposes working helper bundle', async () => {
    const mockClient: any = {
      connect: async () => {},
      close: async () => {}
    };

    const bundle = wrapClientWithLifecycleGuard(mockClient);
    assert.ok(bundle.client);
    assert.ok(bundle.fence instanceof TransportEpochFence);
    assert.strictEqual(typeof bundle.connectSafely, 'function');
    assert.strictEqual(typeof bundle.connectWithFailover, 'function');

    await bundle.connectSafely(() => ({ close: async () => {} }));
    assert.strictEqual(bundle.fence.getActiveEpoch(), 1);
  });

  console.log('\n[Module: Client Session & Fail-Closed Capability Invariant Guard]');

  await test('ClientSessionGuard initializes with state DISCONNECTED', () => {
    const guard = new ClientSessionGuard();
    assert.strictEqual(guard.getState(), 'DISCONNECTED');
    assert.strictEqual(guard.isConnected(), false);
  });

  await test('ClientSessionGuard transitions state across connecting, connected, closing, and closed', () => {
    const guard = new ClientSessionGuard();
    const transitions: string[] = [];
    guard.on('state_change', (from, to) => transitions.push(`${from}->${to}`));

    guard.markConnecting();
    assert.strictEqual(guard.getState(), 'CONNECTING');

    guard.markConnected();
    assert.strictEqual(guard.getState(), 'CONNECTED');
    assert.strictEqual(guard.isConnected(), true);

    guard.markClosed();
    assert.strictEqual(guard.getState(), 'CLOSED');
    assert.strictEqual(guard.isConnected(), false);

    assert.deepStrictEqual(transitions, [
      'DISCONNECTED->CONNECTING',
      'CONNECTING->CONNECTED',
      'CONNECTED->CLOSED'
    ]);
  });

  await test('assertConnected throws ClientSessionError with ERR_CLIENT_NOT_CONNECTED on disconnected client', () => {
    const guard = new ClientSessionGuard();
    const mockClient: any = { transport: undefined };

    assert.throws(
      () => guard.assertConnected(mockClient, 'listTools'),
      (err: any) => {
        assert.ok(err instanceof ClientSessionError);
        assert.strictEqual(err.code, 'ERR_CLIENT_NOT_CONNECTED');
        assert.strictEqual(err.message, 'Not connected');
        assert.strictEqual(err.method, 'listTools');
        return true;
      }
    );
  });

  await test('assertConnected passes without error when client.transport is defined and state is CONNECTED', () => {
    const guard = new ClientSessionGuard();
    guard.markConnected();
    const mockClient: any = { transport: {} };

    assert.doesNotThrow(() => {
      guard.assertConnected(mockClient, 'listTools');
    });
  });

  await test('guardClient intercepts listTools() on a closed client and rejects with Not connected (resolves #3195)', async () => {
    const guard = new ClientSessionGuard();
    const rawClient: any = {
      transport: undefined,
      _serverCapabilities: undefined,
      listTools: async () => {
        // SDK behavior without guard: returns empty tools array
        return { tools: [] };
      },
      close: async () => {}
    };

    const client = guard.guardClient(rawClient);
    guard.markClosed();

    await assert.rejects(
      async () => await client.listTools(),
      (err: any) => {
        assert.ok(err instanceof ClientSessionError);
        assert.strictEqual(err.message, 'Not connected');
        assert.strictEqual(err.code, 'ERR_CLIENT_NOT_CONNECTED');
        return true;
      }
    );
  });

  await test('guardClient intercepts listPrompts() on a closed client and rejects with Not connected', async () => {
    const guard = new ClientSessionGuard();
    const rawClient: any = {
      transport: undefined,
      listPrompts: async () => ({ prompts: [] }),
      close: async () => {}
    };

    const client = guard.guardClient(rawClient);
    guard.markClosed();

    await assert.rejects(
      async () => await client.listPrompts(),
      (err: any) => {
        assert.ok(err instanceof ClientSessionError);
        assert.strictEqual(err.message, 'Not connected');
        return true;
      }
    );
  });

  await test('guardClient intercepts listResources() and listResourceTemplates() on closed client', async () => {
    const guard = new ClientSessionGuard();
    const rawClient: any = {
      transport: undefined,
      listResources: async () => ({ resources: [] }),
      listResourceTemplates: async () => ({ resourceTemplates: [] }),
      close: async () => {}
    };

    const client = guard.guardClient(rawClient);
    guard.markClosed();

    await assert.rejects(async () => await client.listResources(), /Not connected/);
    await assert.rejects(async () => await client.listResourceTemplates(), /Not connected/);
  });

  await test('guardClient allows listTools() to resolve empty array when connected but server lacks capability', async () => {
    const guard = new ClientSessionGuard();
    const rawClient: any = {
      transport: { mock: 'transport' },
      _serverCapabilities: {}, // Connected, but no tools key
      listTools: async () => {
        return { tools: [{ name: 'should_not_reach_here' }] };
      }
    };

    const client = guard.guardClient(rawClient);
    guard.markConnected();

    const res = await client.listTools();
    assert.deepStrictEqual(res, { tools: [] });
  });

  await test('guardClient allows listTools() to resolve tools when server has capability and is connected', async () => {
    const guard = new ClientSessionGuard();
    const rawClient: any = {
      transport: { mock: 'transport' },
      _serverCapabilities: { tools: {} },
      listTools: async () => {
        return { tools: [{ name: 'calculate_checksum', inputSchema: {} }] };
      }
    };

    const client = guard.guardClient(rawClient);
    guard.markConnected();

    const res = await client.listTools();
    assert.strictEqual(res.tools.length, 1);
    assert.strictEqual((res.tools[0] as any).name, 'calculate_checksum');
  });

  await test('guardClient callTool() and ping() reject with Not connected when disconnected', async () => {
    const guard = new ClientSessionGuard();
    const rawClient: any = {
      transport: undefined,
      callTool: async () => ({ content: [] }),
      ping: async () => ({})
    };

    const client = guard.guardClient(rawClient);

    await assert.rejects(async () => await client.callTool({ name: 'test' }), /Not connected/);
    await assert.rejects(async () => await client.ping(), /Not connected/);
  });

  await test('guardClient with autoReconnect=true triggers reconnectHandler on listTools() when disconnected', async () => {
    let reconnected = false;
    const rawClient: any = {
      transport: undefined,
      _serverCapabilities: { tools: {} },
      listTools: async () => ({ tools: [{ name: 'recovered_tool' }] })
    };

    const guard = new ClientSessionGuard({
      autoReconnect: true,
      reconnectHandler: async () => {
        reconnected = true;
        rawClient.transport = { mock: 'recovered_transport' };
        guard.markConnected();
      }
    });

    const client = guard.guardClient(rawClient);
    const res = await client.listTools();

    assert.strictEqual(reconnected, true);
    assert.strictEqual(res.tools.length, 1);
    assert.strictEqual((res.tools[0] as any).name, 'recovered_tool');
  });

  await test('wrapClientWithSessionGuard exposes working wrapper helper', async () => {
    const rawClient: any = {
      transport: undefined,
      listTools: async () => ({ tools: [] }),
      close: async () => {}
    };

    const bundle = wrapClientWithSessionGuard(rawClient);
    assert.ok(bundle.client);
    assert.ok(bundle.guard instanceof ClientSessionGuard);
    assert.strictEqual(bundle.guard.getState(), 'DISCONNECTED');
  });

  console.log('\n[Module: Resilient Subscription Router & Capacity Guard]');

  await test('computeHonoredSubset intersects requested notifications with server capabilities', () => {
    const requested = {
      toolsListChanged: true,
      promptsListChanged: true,
      resourcesListChanged: true
    };
    const capabilities = {
      tools: {},
      resources: { listChanged: true }
      // prompts omitted
    };

    const honored = computeHonoredSubset(requested, capabilities);
    assert.strictEqual(honored.toolsListChanged, true);
    assert.strictEqual(honored.resourcesListChanged, true);
    assert.strictEqual(honored.promptsListChanged, undefined);
  });

  await test('computeHonoredSubset returns empty object when requested capability is not advertised', () => {
    const requested = { promptsListChanged: true };
    const capabilities = { tools: {} };

    const honored = computeHonoredSubset(requested, capabilities);
    assert.deepStrictEqual(honored, {});
  });

  await test('hasActiveSubscriptionFilters correctly identifies non-empty filters', () => {
    assert.strictEqual(hasActiveSubscriptionFilters({}), false);
    assert.strictEqual(hasActiveSubscriptionFilters({ toolsListChanged: true }), true);
    assert.strictEqual(hasActiveSubscriptionFilters({ promptsListChanged: true }), true);
    assert.strictEqual(hasActiveSubscriptionFilters({ resourcesListChanged: true }), true);
    assert.strictEqual(hasActiveSubscriptionFilters({ resourceUpdated: ['file:///test.txt'] }), true);
    assert.strictEqual(hasActiveSubscriptionFilters({ resourceUpdated: [] }), false);
  });

  await test('SubscriptionRouterGuard immediately completes with complete result when honoredSubset is empty (resolves #3199)', () => {
    const guard = new SubscriptionRouterGuard({
      capabilities: { tools: {} },
      serverInfo: { name: 'test-server', version: '1.0.0' }
    });

    const sentMessages: any[] = [];
    const res = guard.handleListenRequest(
      101,
      { notifications: { promptsListChanged: true } },
      (msg) => sentMessages.push(msg)
    );

    assert.strictEqual(res.status, 'graceful_complete');
    assert.strictEqual(sentMessages.length, 2);

    // 1st message: acknowledged with empty notifications
    assert.strictEqual(sentMessages[0].method, 'notifications/subscriptions/acknowledged');
    assert.deepStrictEqual(sentMessages[0].params.notifications, {});

    // 2nd message: complete result with subscriptionId in _meta
    assert.strictEqual(sentMessages[1].id, 101);
    assert.strictEqual(sentMessages[1].result.resultType, 'complete');
    assert.strictEqual(sentMessages[1].result._meta['io.modelcontextprotocol/subscriptionId'], 101);
  });

  await test('SubscriptionRouterGuard does NOT retain subscription in activeSubscriptions when honoredSubset is empty', () => {
    const guard = new SubscriptionRouterGuard({ capabilities: { tools: {} } });

    guard.handleListenRequest(102, { notifications: { promptsListChanged: true } }, () => {});

    assert.strictEqual(guard.getActiveCount(), 0);
    assert.strictEqual(guard.hasSubscription(102), false);
  });

  await test('Reproduction of #3199: Empty subscriptions do NOT count against maxSubscriptions limit', () => {
    // Set maxSubscriptions to 1
    const guard = new SubscriptionRouterGuard({
      maxSubscriptions: 1,
      capabilities: { tools: {} }
    });

    const sentMessages: any[] = [];

    // 1st call: promptsListChanged (unadvertised, honored is {})
    const r1 = guard.handleListenRequest(
      1,
      { notifications: { promptsListChanged: true } },
      (msg) => sentMessages.push(msg)
    );
    assert.strictEqual(r1.status, 'graceful_complete');
    assert.strictEqual(guard.getActiveCount(), 0);

    // 2nd call: toolsListChanged (advertised, should SUCCEED and NOT be blocked by limit)
    const r2 = guard.handleListenRequest(
      2,
      { notifications: { toolsListChanged: true } },
      (msg) => sentMessages.push(msg)
    );

    // Resolves #3199: Must succeed, NOT fail with -32603 "Subscription limit reached"
    assert.strictEqual(r2.status, 'subscribed');
    assert.strictEqual(guard.getActiveCount(), 1);
    assert.strictEqual(guard.hasSubscription(2), true);
  });

  await test('SubscriptionRouterGuard accepts valid subscription when server advertises capability', () => {
    const guard = new SubscriptionRouterGuard({
      capabilities: { tools: {} }
    });

    const sent: any[] = [];
    const res = guard.handleListenRequest(103, { notifications: { toolsListChanged: true } }, (m) => sent.push(m));

    assert.strictEqual(res.status, 'subscribed');
    assert.strictEqual(sent.length, 1);
    assert.strictEqual(sent[0].method, 'notifications/subscriptions/acknowledged');
    assert.deepStrictEqual(sent[0].params.notifications, { toolsListChanged: true });
    assert.strictEqual(guard.getActiveCount(), 1);
  });

  await test('SubscriptionRouterGuard enforces maxSubscriptions limit when valid subscriptions exceed capacity (-32603)', () => {
    const guard = new SubscriptionRouterGuard({
      maxSubscriptions: 1,
      capabilities: { tools: {} }
    });

    const sent: any[] = [];
    guard.handleListenRequest(1, { notifications: { toolsListChanged: true } }, (m) => sent.push(m));
    assert.strictEqual(guard.getActiveCount(), 1);

    const r2 = guard.handleListenRequest(2, { notifications: { toolsListChanged: true } }, (m) => sent.push(m));
    assert.strictEqual(r2.status, 'rejected');
    assert.strictEqual(sent[1].error.code, -32603);
    assert.ok(sent[1].error.message.includes('Subscription limit reached'));
  });

  await test('SubscriptionRouterGuard releases slot immediately on handleCancel', () => {
    const guard = new SubscriptionRouterGuard({ capabilities: { tools: {} } });

    guard.handleListenRequest(50, { notifications: { toolsListChanged: true } }, () => {});
    assert.strictEqual(guard.getActiveCount(), 1);

    const cancelled = guard.handleCancel(50);
    assert.strictEqual(cancelled, true);
    assert.strictEqual(guard.getActiveCount(), 0);
  });

  await test('SubscriptionRouterGuard dispatchNotification sends event only to matching subscriptions', () => {
    const guard = new SubscriptionRouterGuard({
      capabilities: { tools: {}, prompts: {} }
    });

    guard.handleListenRequest(10, { notifications: { toolsListChanged: true } }, () => {});
    guard.handleListenRequest(20, { notifications: { promptsListChanged: true } }, () => {});

    const sent: any[] = [];
    const count = guard.dispatchNotification('toolsListChanged', { eventData: 'sample' }, (m) => sent.push(m));

    assert.strictEqual(count, 1);
    assert.strictEqual(sent.length, 1);
    assert.strictEqual(sent[0].method, 'notifications/toolsListChanged');
    assert.strictEqual(sent[0].params.subscriptionId, 10);
  });

  await test('SubscriptionRouterGuard clear() removes all subscriptions on transport teardown', () => {
    const guard = new SubscriptionRouterGuard({ capabilities: { tools: {} } });
    guard.handleListenRequest(1, { notifications: { toolsListChanged: true } }, () => {});
    guard.handleListenRequest(2, { notifications: { toolsListChanged: true } }, () => {});

    assert.strictEqual(guard.getActiveCount(), 2);
    guard.clear();
    assert.strictEqual(guard.getActiveCount(), 0);
  });

  await test('createGuardedSubscriptionRouter helper factory initializes cleanly', () => {
    const router = createGuardedSubscriptionRouter({ maxSubscriptions: 25 });
    assert.ok(router instanceof SubscriptionRouterGuard);
    assert.strictEqual(router.getMaxSubscriptions(), 25);
  });

  console.log('\n[Module: HTTP Transport & Body Parsing Normalizer]');

  await test('normalizeHttpRequestBody skips parsing for GET requests even with application/json header (resolves #3201)', async () => {
    const res = await normalizeHttpRequestBody('GET', 'application/json', () => '');
    assert.strictEqual(res.skipParsing, true);
    assert.strictEqual(res.isEmpty, true);
    assert.strictEqual(res.error, undefined);
  });

  await test('normalizeHttpRequestBody skips parsing for HEAD requests with application/json header', async () => {
    const res = await normalizeHttpRequestBody('HEAD', 'application/json', () => '');
    assert.strictEqual(res.skipParsing, true);
    assert.strictEqual(res.isEmpty, true);
    assert.strictEqual(res.error, undefined);
  });

  await test('normalizeHttpRequestBody skips parsing for non-JSON content-type', async () => {
    const res = await normalizeHttpRequestBody('POST', 'text/plain', () => 'hello');
    assert.strictEqual(res.skipParsing, true);
    assert.strictEqual(res.error, undefined);
  });

  await test('normalizeHttpRequestBody handles bodyless DELETE requests with application/json without throwing SyntaxError', async () => {
    // StreamableHTTPClientTransport copies Content-Type: application/json onto DELETE terminateSession()
    const res = await normalizeHttpRequestBody('DELETE', 'application/json', () => '');
    assert.strictEqual(res.skipParsing, false);
    assert.strictEqual(res.isEmpty, true);
    assert.strictEqual(res.parsedBody, undefined);
    assert.strictEqual(res.error, undefined);
  });

  await test('normalizeHttpRequestBody handles empty POST with application/json and leaves parsedBody undefined', async () => {
    const res = await normalizeHttpRequestBody('POST', 'application/json', () => '   ');
    assert.strictEqual(res.skipParsing, false);
    assert.strictEqual(res.isEmpty, true);
    assert.strictEqual(res.parsedBody, undefined);
    assert.strictEqual(res.error, undefined);
  });

  await test('normalizeHttpRequestBody parses valid JSON body on POST request', async () => {
    const payload = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    const res = await normalizeHttpRequestBody('POST', 'application/json', () => payload);

    assert.strictEqual(res.skipParsing, false);
    assert.strictEqual(res.isEmpty, false);
    assert.strictEqual(res.error, undefined);
    assert.deepStrictEqual((res.parsedBody as any).method, 'tools/list');
  });

  await test('normalizeHttpRequestBody catches malformed JSON on POST and returns jsonRpcCode -32700 error', async () => {
    const res = await normalizeHttpRequestBody('POST', 'application/json', () => '{ broken_json');

    assert.strictEqual(res.skipParsing, false);
    assert.ok(res.error);
    assert.strictEqual(res.error.statusCode, 400);
    assert.strictEqual(res.error.jsonRpcCode, -32700);
    assert.ok(res.error.message.includes('Parse error: Invalid JSON'));
  });

  await test('normalizeHttpRequestBody enforces maxBytes payload ceiling and returns 413 error', async () => {
    const bigString = 'a'.repeat(200);
    const res = await normalizeHttpRequestBody('POST', 'application/json', () => bigString, { maxBytes: 100 });

    assert.ok(res.error);
    assert.strictEqual(res.error.statusCode, 413);
    assert.strictEqual(res.tooLarge, true);
  });

  await test('formatJsonRpcParseError emits valid JSON-RPC 2.0 error structure', () => {
    const err = formatJsonRpcParseError('Invalid syntax');
    assert.strictEqual(err.jsonrpc, '2.0');
    assert.strictEqual(err.id, null);
    assert.strictEqual(err.error.code, -32700);
    assert.strictEqual(err.error.message, 'Invalid syntax');
  });

  await test('handleNormalizedFetch passes GET with application/json to nextHandler with status 200', async () => {
    const req = new Request('http://localhost:3000/sse', {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });

    let nextCalled = false;
    const res = await handleNormalizedFetch(req, async (_r, parsed) => {
      nextCalled = true;
      assert.strictEqual(parsed, undefined);
      return new Response('SSE stream active', { status: 200 });
    });

    assert.strictEqual(nextCalled, true);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(await res.text(), 'SSE stream active');
  });

  await test('handleNormalizedFetch returns 204 with CORS headers on OPTIONS preflight request', async () => {
    const req = new Request('http://localhost:3000/mcp', { method: 'OPTIONS' });
    const res = await handleNormalizedFetch(req, async () => new Response('not reached'));

    assert.strictEqual(res.status, 204);
    assert.ok(res.headers.get('access-control-allow-methods')?.includes('GET'));
  });

  await test('createMcpHonoNormalizerMiddleware populates c.set parsedBody and skips empty bodies without 400 error', async () => {
    const middleware = createMcpHonoNormalizerMiddleware();

    const contextMap = new Map<string, any>();
    const mockContext = {
      req: {
        method: 'GET',
        header: (name: string) => (name.toLowerCase() === 'content-type' ? 'application/json' : undefined),
        text: async () => ''
      },
      set: (key: string, val: any) => contextMap.set(key, val),
      text: (msg: string, code: number) => ({ body: msg, status: code })
    };

    let nextExecuted = false;
    await middleware(mockContext, async () => {
      nextExecuted = true;
    });

    assert.strictEqual(nextExecuted, true);
    assert.strictEqual(contextMap.get('parsedBody'), undefined);
    assert.strictEqual(contextMap.get('isBodyEmpty'), true);
  });

  console.log('\n[Module: Enterprise OAuth Issuer & Multi-Tenant Authority Guard]');

  await test('validateAuthorizationIssuer returns valid=true on exact matching URLs (RFC 8414 §3.3 standard case)', () => {
    const res = validateAuthorizationIssuer(
      'https://auth.enterprise.com/oauth/v2',
      'https://auth.enterprise.com/oauth/v2'
    );
    assert.strictEqual(res.valid, true);
    assert.strictEqual(res.isTemplateMatch, false);
    assert.strictEqual(res.error, undefined);
  });

  await test('validateAuthorizationIssuer matches Microsoft Entra ID /organizations/v2.0 against /{tenantid}/v2.0 template (resolves #3207)', () => {
    const res = validateAuthorizationIssuer(
      'https://login.microsoftonline.com/organizations/v2.0',
      'https://login.microsoftonline.com/{tenantid}/v2.0'
    );
    assert.strictEqual(res.valid, true);
    assert.strictEqual(res.isTemplateMatch, true);
    assert.strictEqual(res.resolvedTenantId, 'organizations');
    assert.strictEqual(res.error, undefined);
  });

  await test('validateAuthorizationIssuer matches Microsoft Entra ID /common/v2.0 against /{tenantid}/v2.0 template', () => {
    const res = validateAuthorizationIssuer(
      'https://login.microsoftonline.com/common/v2.0',
      'https://login.microsoftonline.com/{tenantid}/v2.0'
    );
    assert.strictEqual(res.valid, true);
    assert.strictEqual(res.isTemplateMatch, true);
    assert.strictEqual(res.resolvedTenantId, 'common');
  });

  await test('validateAuthorizationIssuer matches template when received is a real tenant UUID', () => {
    const tenantUuid = 'a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d';
    const res = validateAuthorizationIssuer(
      'https://login.microsoftonline.com/{tenantid}/v2.0',
      `https://login.microsoftonline.com/${tenantUuid}/v2.0`
    );
    assert.strictEqual(res.valid, true);
    assert.strictEqual(res.isTemplateMatch, true);
    assert.strictEqual(res.resolvedTenantId, tenantUuid);
  });

  await test('validateAuthorizationIssuer rejects origin mismatch (prevents IdP mix-up attacks)', () => {
    const res = validateAuthorizationIssuer(
      'https://login.microsoftonline.com/organizations/v2.0',
      'https://evil-attacker.com/{tenantid}/v2.0'
    );
    assert.strictEqual(res.valid, false);
    assert.strictEqual(res.isTemplateMatch, false);
    assert.ok(res.error?.includes('Origin mismatch'));
  });

  await test('validateAuthorizationIssuer rejects protocol downgrade attempts', () => {
    const res = validateAuthorizationIssuer(
      'https://login.microsoftonline.com/organizations/v2.0',
      'http://login.microsoftonline.com/{tenantid}/v2.0'
    );
    assert.strictEqual(res.valid, false);
    assert.ok(res.error?.includes('Origin mismatch'));
  });

  await test('validateAuthorizationIssuer rejects path segment length mismatch', () => {
    const res = validateAuthorizationIssuer(
      'https://login.microsoftonline.com/organizations/v2.0',
      'https://login.microsoftonline.com/{tenantid}/v2.0/extra'
    );
    assert.strictEqual(res.valid, false);
    assert.ok(res.error?.includes('Path segment length mismatch'));
  });

  await test('validateAuthorizationIssuer rejects template substitution on unapproved authority hosts', () => {
    const res = validateAuthorizationIssuer(
      'https://unapproved-idp.com/organizations/v2.0',
      'https://unapproved-idp.com/{tenantid}/v2.0'
    );
    assert.strictEqual(res.valid, false);
    assert.ok(res.error?.includes('rejected on unapproved authority host'));
  });

  await test('validateAuthorizationIssuer handles trailing slashes consistently', () => {
    const res = validateAuthorizationIssuer(
      'https://auth.company.com/v1/',
      'https://auth.company.com/v1'
    );
    assert.strictEqual(res.valid, true);
  });

  await test('validateTokenIssuerClaim accepts valid Entra token issuer with matching tenant ID', () => {
    const tenantId = '72f988bf-86f1-41af-91ab-2d7cd011db47';
    const tokenIssuer = `https://login.microsoftonline.com/${tenantId}/v2.0`;

    const isValid = validateTokenIssuerClaim(tokenIssuer, tenantId);
    assert.strictEqual(isValid, true);
  });

  await test('validateTokenIssuerClaim rejects token issuer with mismatched tenant ID or non-https scheme', () => {
    const tenantId = '72f988bf-86f1-41af-91ab-2d7cd011db47';
    const wrongTenant = '11111111-2222-3333-4444-555555555555';

    assert.strictEqual(validateTokenIssuerClaim(`https://login.microsoftonline.com/${wrongTenant}/v2.0`, tenantId), false);
    assert.strictEqual(validateTokenIssuerClaim(`http://login.microsoftonline.com/${tenantId}/v2.0`, tenantId), false);
    assert.strictEqual(validateTokenIssuerClaim('not-a-url', tenantId), false);
  });

  await test('createTenantAwareIssuerValidator pluggable predicate returns boolean compatible with discovery hooks', () => {
    const validator = createTenantAwareIssuerValidator();
    assert.strictEqual(typeof validator, 'function');

    const pass = validator(
      'https://login.microsoftonline.com/organizations/v2.0',
      'https://login.microsoftonline.com/{tenantid}/v2.0'
    );
    assert.strictEqual(pass, true);

    const fail = validator(
      'https://login.microsoftonline.com/organizations/v2.0',
      'https://attacker.com/organizations/v2.0'
    );
    assert.strictEqual(fail, false);
  });

  // ==========================================
  // Module 23: Stream Resumption, Truncation & Protocol Negotiation Guard
  // ==========================================
  console.log('\n[Module: Stream Resumption, Truncation & Protocol Negotiation Guard]');

  await test('StreamTruncationGuard registers request and unregisters cleanly upon response', () => {
    const guard = new StreamTruncationGuard();
    let rejected = false;
    const { markResponded } = guard.registerRequest(1, () => { rejected = true; }, 5000);
    assert.strictEqual(guard.activeCount, 1);
    markResponded();
    assert.strictEqual(guard.activeCount, 0);
    assert.strictEqual(rejected, false);
  });

  await test('StreamTruncationGuard handleStreamEnd immediately aborts with ConnectionClosed on unexpected stream close (resolves #3210)', () => {
    const guard = new StreamTruncationGuard();
    let caughtErr: any = null;
    guard.registerRequest(42, (err) => { caughtErr = err; }, 5000);

    const aborted = guard.handleStreamEnd(42, 'Per-request SSE stream closed before a JSON-RPC response was received');
    assert.strictEqual(aborted, true);
    assert.ok(caughtErr, 'Error should have been emitted');
    assert.strictEqual(caughtErr.code, MCP_ERROR_CONNECTION_CLOSED);
    assert.strictEqual(caughtErr.isConnectionClosed, true);
    assert.strictEqual(guard.activeCount, 0);
  });

  await test('StreamTruncationGuard handleStreamEnd ignores already responded streams without error', () => {
    const guard = new StreamTruncationGuard();
    let caughtErr: any = null;
    const { markResponded } = guard.registerRequest('req-99', (err) => { caughtErr = err; }, 5000);
    markResponded();
    const aborted = guard.handleStreamEnd('req-99');
    assert.strictEqual(aborted, false);
    assert.strictEqual(caughtErr, null);
  });

  await test('StreamTruncationGuard clear aborts all pending streams on transport disconnect', () => {
    const guard = new StreamTruncationGuard();
    const errors: any[] = [];
    guard.registerRequest('a', (err) => errors.push(err));
    guard.registerRequest('b', (err) => errors.push(err));
    assert.strictEqual(guard.activeCount, 2);

    guard.clear('Client transport disconnect');
    assert.strictEqual(guard.activeCount, 0);
    assert.strictEqual(errors.length, 2);
    assert.strictEqual(errors[0].code, MCP_ERROR_CONNECTION_CLOSED);
    assert.strictEqual(errors[1].code, MCP_ERROR_CONNECTION_CLOSED);
  });

  await test('validateResumptionAttempt identifies HTTP 405 Method Not Allowed as non-resumable terminal status (resolves #3210)', () => {
    const res = validateResumptionAttempt({
      resumptionToken: 'prev-event-token-123',
      httpStatus: 405
    });
    assert.strictEqual(res.canResume, false);
    assert.strictEqual(res.isTerminal, true);
    assert.strictEqual(res.status, 405);
    assert.ok(res.reason?.includes('HTTP 405 Method Not Allowed'));
  });

  await test('validateResumptionAttempt identifies HTTP 404, 410 and 403 as terminal errors', () => {
    const res404 = validateResumptionAttempt({ httpStatus: 404 });
    assert.strictEqual(res404.canResume, false);
    assert.strictEqual(res404.isTerminal, true);

    const res410 = validateResumptionAttempt({ httpStatus: 410 });
    assert.strictEqual(res410.canResume, false);
    assert.strictEqual(res410.isTerminal, true);

    const res403 = validateResumptionAttempt({ httpStatus: 403 });
    assert.strictEqual(res403.canResume, false);
    assert.strictEqual(res403.isTerminal, true);
  });

  await test('validateResumptionAttempt permits valid HTTP 200-299 responses and flags 500 as retryable non-terminal', () => {
    const res200 = validateResumptionAttempt({ httpStatus: 200 });
    assert.strictEqual(res200.canResume, true);
    assert.strictEqual(res200.isTerminal, false);

    const res503 = validateResumptionAttempt({ httpStatus: 503 });
    assert.strictEqual(res503.canResume, false);
    assert.strictEqual(res503.isTerminal, false);
    assert.ok(res503.reason?.includes('Transient server error 503'));
  });

  await test('validateProtocolVersion allows supported protocol revisions', () => {
    const msg = {
      jsonrpc: '2.0',
      id: 10,
      method: 'tools/list',
      params: {
        _meta: {
          'io.modelcontextprotocol/protocolVersion': '2026-07-28'
        }
      }
    };
    const check = validateProtocolVersion(msg, {
      supportedVersions: ['2024-11-05', '2025-11-25', '2026-07-28']
    });
    assert.strictEqual(check.valid, true);
    assert.strictEqual(check.requestedVersion, '2026-07-28');
  });

  await test('validateProtocolVersion rejects unsupported protocol version with JSON-RPC -32022 error (resolves #3179 / #3206)', () => {
    const msg = {
      jsonrpc: '2.0',
      id: 11,
      method: 'tools/call',
      params: {
        _meta: {
          'io.modelcontextprotocol/protocolVersion': '2099-01-01'
        }
      }
    };
    const check = validateProtocolVersion(msg, {
      supportedVersions: ['2026-07-28'],
      pinnedVersion: '2026-07-28'
    });
    assert.strictEqual(check.valid, false);
    assert.ok(check.jsonRpcError);
    assert.strictEqual(check.jsonRpcError.error.code, MCP_ERROR_UNSUPPORTED_PROTOCOL);
    assert.strictEqual(check.jsonRpcError.error.data.requested, '2099-01-01');
    assert.deepStrictEqual(check.jsonRpcError.error.data.supported, ['2026-07-28']);
  });

  await test('validateProtocolVersion rejects missing protocolVersion on modern pinned connection', () => {
    const msg = {
      jsonrpc: '2.0',
      id: 12,
      method: 'tools/list',
      params: {}
    };
    const check = validateProtocolVersion(msg, {
      supportedVersions: ['2026-07-28'],
      pinnedVersion: '2026-07-28'
    });
    assert.strictEqual(check.valid, false);
    assert.strictEqual(check.jsonRpcError?.error.code, MCP_ERROR_UNSUPPORTED_PROTOCOL);
  });

  await test('validateClientCapabilities permits call when client declared required capabilities', () => {
    const check = validateClientCapabilities(100, {
      declaredCapabilities: { tools: {}, sampling: {} },
      requiredCapabilities: ['sampling']
    });
    assert.strictEqual(check.valid, true);
    assert.strictEqual(check.missingCapabilities.length, 0);
  });

  await test('validateClientCapabilities returns JSON-RPC -32021 when required capability is missing (resolves #3202)', () => {
    const check = validateClientCapabilities(101, {
      declaredCapabilities: { tools: {} },
      requiredCapabilities: ['sampling', 'tasks']
    });
    assert.strictEqual(check.valid, false);
    assert.deepStrictEqual(check.missingCapabilities, ['sampling', 'tasks']);
    assert.ok(check.jsonRpcError);
    assert.strictEqual(check.jsonRpcError.error.code, MCP_ERROR_MISSING_CAPABILITY);
    assert.deepStrictEqual(check.jsonRpcError.error.data.requiredCapabilities, ['sampling', 'tasks']);
  });

  await test('createTerminalStreamError constructs compliant SSE JSON-RPC error frame', () => {
    const frame = createTerminalStreamError('msg-abc', -32603, 'Internal server stream termination');
    assert.ok(frame.startsWith('data: '));
    assert.ok(frame.endsWith('\n\n'));
    const parsed = JSON.parse(frame.slice(6).trim());
    assert.strictEqual(parsed.jsonrpc, '2.0');
    assert.strictEqual(parsed.id, 'msg-abc');
    assert.strictEqual(parsed.error.code, -32603);
    assert.strictEqual(parsed.error.message, 'Internal server stream termination');
  });

  // Summary
  console.log('\n------------------------------------------------------');
  console.log(`Pro Pack Test Execution Finished: ${passed} Passed, ${failed} Failed`);
  console.log('------------------------------------------------------\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runProPackTestSuite().catch(err => {
  console.error('Pro Pack test runner failure:', err);
  process.exit(1);
});
