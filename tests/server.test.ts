import assert from 'assert';
import { loadConfig } from '../dist/config.js';
import { Logger } from '../dist/logger.js';
import { executeSystemMetrics } from '../dist/tools/systemMetrics.js';
import { executeAgentMemory, globalMemoryStore } from '../dist/tools/agentMemory.js';
import { executeSecureFetch } from '../dist/tools/secureFetch.js';

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

async function runTestSuite() {
  console.log('\n=============================================');
  console.log('   MCP Production Kit - Automated Test Suite');
  console.log('=============================================\n');

  // 1. Config Tests
  console.log('[Module: Configuration]');
  await test('Default configuration loads valid types', () => {
    const config = loadConfig({});
    assert.strictEqual(config.SERVER_NAME, 'mcp-production-server');
    assert.strictEqual(config.PORT, 3000);
    assert.strictEqual(config.MAX_FETCH_SIZE_KB, 512);
  });

  await test('Catches invalid port or type coercion errors', () => {
    assert.throws(() => {
      loadConfig({ LOG_LEVEL: 'super_fatal' as any });
    }, /Invalid environment variables/);
  });

  // 2. System Metrics Tool Tests
  console.log('\n[Module: System Metrics Tool]');
  await test('executeSystemMetrics returns valid OS & memory telemetry', async () => {
    const result = await executeSystemMetrics({ includeMemoryDetails: true, includeNetworkInterfaces: false });
    assert(result.content && result.content[0]);
    const parsed = JSON.parse(result.content[0].text);
    assert(parsed.os && parsed.cpu && parsed.memory && parsed.processMemory);
    assert(typeof parsed.memory.totalMb === 'number');
    assert(parsed.memory.totalMb > 0);
  });

  // 3. Agent Memory Store Tests
  console.log('\n[Module: Agent Memory Store]');
  await test('agentMemory set, get, and list with namespace isolation', async () => {
    globalMemoryStore.clear('*');

    // Set key in ns1
    await executeAgentMemory({ action: 'set', namespace: 'agent_a', key: 'task_status', value: { step: 1, done: false } });
    
    // Set key in ns2
    await executeAgentMemory({ action: 'set', namespace: 'agent_b', key: 'task_status', value: { step: 99, done: true } });

    // Get from ns1
    const getA = await executeAgentMemory({ action: 'get', namespace: 'agent_a', key: 'task_status' });
    const parsedA = JSON.parse(getA.content[0].text);
    assert.strictEqual(parsedA.found, true);
    assert.strictEqual(parsedA.value.step, 1);

    // Get from ns2
    const getB = await executeAgentMemory({ action: 'get', namespace: 'agent_b', key: 'task_status' });
    const parsedB = JSON.parse(getB.content[0].text);
    assert.strictEqual(parsedB.found, true);
    assert.strictEqual(parsedB.value.step, 99);

    // List ns1
    const listA = await executeAgentMemory({ action: 'list', namespace: 'agent_a' });
    const parsedList = JSON.parse(listA.content[0].text);
    assert.strictEqual(parsedList.totalKeys, 1);

    // Delete
    const delA = await executeAgentMemory({ action: 'delete', namespace: 'agent_a', key: 'task_status' });
    const parsedDel = JSON.parse(delA.content[0].text);
    assert.strictEqual(parsedDel.deleted, true);
  });

  // 4. Secure Fetch Tool & SSRF Guard Tests
  console.log('\n[Module: Secure Fetch & SSRF Protection]');
  const mockConfig = loadConfig({});

  await test('Blocks SSRF attempts to localhost', async () => {
    await assert.rejects(
      async () => {
        await executeSecureFetch({ url: 'http://localhost:8080/admin', method: 'GET' }, mockConfig);
      },
      /Access to private host or link-local address 'localhost' is strictly blocked/
    );
  });

  await test('Blocks SSRF attempts to 127.0.0.1', async () => {
    await assert.rejects(
      async () => {
        await executeSecureFetch({ url: 'http://127.0.0.1:3000', method: 'GET' }, mockConfig);
      },
      /Access to private host or link-local address '127.0.0.1' is strictly blocked/
    );
  });

  await test('Blocks SSRF attempts to AWS metadata service 169.254.169.254', async () => {
    await assert.rejects(
      async () => {
        await executeSecureFetch({ url: 'http://169.254.169.254/latest/meta-data/', method: 'GET' }, mockConfig);
      },
      /Access to private host or link-local address '169.254.169.254' is strictly blocked/
    );
  });

  await test('Blocks non-HTTP protocols (e.g. file:// or ftp://)', async () => {
    await assert.rejects(
      async () => {
        await executeSecureFetch({ url: 'file:///etc/passwd', method: 'GET' }, mockConfig);
      },
      /Disallowed protocol 'file:'/
    );
  });

  // Summary
  console.log('\n---------------------------------------------');
  console.log(`Test Execution Finished: ${passed} Passed, ${failed} Failed`);
  console.log('---------------------------------------------\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTestSuite().catch(err => {
  console.error('Test runner failure:', err);
  process.exit(1);
});
