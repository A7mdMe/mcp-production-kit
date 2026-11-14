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
