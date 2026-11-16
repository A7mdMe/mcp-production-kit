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
