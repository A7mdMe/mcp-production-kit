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
