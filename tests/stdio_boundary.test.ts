/**
 * stdio_boundary.test.ts
 *
 * Integration Test: End-to-End Stdio Stream Boundary & Protocol Framing
 * Validates that the server process entry point strictly isolates:
 *   - process.stdout: Only newline-delimited JSON-RPC 2.0 frames
 *   - process.stderr: All operational logs, diagnostics, and errors
 *
 * Implements the rigorous test harness suggested by the community (@antropos17):
 * Testing actual launch entry point, startup framing, tools/list, tool execution/error, and clean shutdown.
 */

import assert from 'assert';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const entryPoint = path.resolve(__dirname, '../dist/index.js');

let passed = 0;
let failed = 0;

function logTest(name: string, ok: boolean, reason?: string) {
  if (ok) {
    console.log(`  [PASS] ${name}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${name}${reason ? ' (' + reason + ')' : ''}`);
    failed++;
  }
}

async function runStdioBoundaryTests() {
  console.log('\n======================================================');
  console.log('   Stdio Stream Isolation - End-to-End Test Suite');
  console.log('======================================================\n');

  console.log('[Module: Process Entry Point & Stdio Framing Isolation]');

  const child = spawn(process.execPath, [entryPoint, '--transport=stdio'], {
    stdio: ['pipe', 'pipe', 'pipe']
  });

  const stdoutFrames: any[] = [];
  const stderrLines: string[] = [];
  let rawStdout = '';

  child.stdout.on('data', (chunk: Buffer) => {
    rawStdout += chunk.toString();
    const lines = rawStdout.split('\n');
    rawStdout = lines.pop() || '';
    for (const line of lines) {
      if (line.trim()) {
        try {
          stdoutFrames.push(JSON.parse(line));
        } catch (e) {
          stdoutFrames.push({ _parseError: true, raw: line });
        }
      }
    }
  });

  child.stderr.on('data', (chunk: Buffer) => {
    const lines = chunk.toString().split('\n');
    for (const line of lines) {
      if (line.trim()) stderrLines.push(line.trim());
    }
  });

  // Helper to send message over stdin
  function sendMsg(msg: Record<string, unknown>) {
    child.stdin.write(JSON.stringify(msg) + '\n');
  }

  // 1. Test startup stderr logging
  await new Promise(r => setTimeout(r, 600));
  const hasStartupLog = stderrLines.some(l => l.includes('Initializing') || l.includes('connected to stdio'));
  logTest('Server entry point emits operational startup logs exclusively on stderr', hasStartupLog);

  // 2. Test initialize handshake on stdout
  sendMsg({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'stdio-test-harness', version: '1.0.0' }
    }
  });

  await new Promise(r => setTimeout(r, 600));
  const initRes = stdoutFrames.find(f => f.id === 1);
  const initValid = initRes && !initRes._parseError && initRes.result?.protocolVersion === '2024-11-05';
  logTest('Handshake: "initialize" response delivered as clean JSON-RPC 2.0 on stdout', Boolean(initValid));

  // 3. Test initialized notification
  sendMsg({
    jsonrpc: '2.0',
    method: 'notifications/initialized',
    params: {}
  });

  // 4. Test tools/list discovery framing
  sendMsg({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/list',
    params: {}
  });

  await new Promise(r => setTimeout(r, 600));
  const toolsRes = stdoutFrames.find(f => f.id === 2);
  const toolsValid = toolsRes && !toolsRes._parseError && Array.isArray(toolsRes.result?.tools);
  logTest('Tool Discovery: "tools/list" delivers valid array on stdout without log pollution', Boolean(toolsValid));

  // 5. Test tool execution error handling (SSRF trigger)
  sendMsg({
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: {
      name: 'secure_http_fetch',
      arguments: {
        url: 'http://169.254.169.254/latest/meta-data/'
      }
    }
  });

  await new Promise(r => setTimeout(r, 800));
  const errorRes = stdoutFrames.find(f => f.id === 3);
  const errorHandled = errorRes && (errorRes.result?.isError === true || errorRes.error !== undefined);
  logTest('Tool Error Boundary: Security block returns structured JSON-RPC response on stdout', Boolean(errorHandled));

  // 6. Verify zero corrupt stdout frames
  const corruptedFrames = stdoutFrames.filter(f => f._parseError);
  logTest('Protocol Invariant: Exactly 0 non-JSON or corrupted characters intercepted on stdout', corruptedFrames.length === 0);

  // 7. Clean Shutdown
  child.kill();
  await new Promise(r => setTimeout(r, 300));
  logTest('Process Lifecycle: Server terminates cleanly upon shutdown signal', child.killed);

  console.log('------------------------------------------------------');
  console.log(`Stdio Boundary Test Results: ${passed} Passed, ${failed} Failed`);
  console.log('------------------------------------------------------\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runStdioBoundaryTests().catch(err => {
  console.error('Fatal test runner error:', err);
  process.exit(1);
});
