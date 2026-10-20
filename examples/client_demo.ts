/**
 * Example Client Demonstration: Connecting to MCP Production Kit
 *
 * This script demonstrates how an AI agent or backend workflow can programmatically
 * connect to the MCP Production Kit server via StdioClientTransport, inspect tools,
 * call the diagnostic tool, and use the memory store.
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import path from 'path';

async function runDemo() {
  console.log('=== Connecting to MCP Production Kit Server ===');

  const serverPath = path.resolve(__dirname, '../dist/index.js');

  const transport = new StdioClientTransport({
    command: 'node',
    args: [serverPath, '--transport=stdio']
  });

  const client = new Client(
    { name: 'demo-agent-client', version: '1.0.0' },
    { capabilities: {} }
  );

  await client.connect(transport);
  console.log('Connected successfully via stdio transport!');

  // 1. List available tools
  const tools = await client.listTools();
  console.log('\nAvailable Tools:');
  for (const tool of tools.tools) {
    console.log(`- ${tool.name}: ${tool.description}`);
  }

  // 2. Call get_system_metrics
  console.log('\nCalling get_system_metrics...');
  const metricsResult = await client.callTool({
    name: 'get_system_metrics',
    arguments: {}
  });
  console.log('Metrics Output:', JSON.stringify(metricsResult, null, 2));

  // 3. Store agent memory
  console.log('\nStoring key-value in agent_memory_store...');
  const memSet = await client.callTool({
    name: 'agent_memory_store',
    arguments: {
      action: 'set',
      key: 'workflow_state',
      value: JSON.stringify({ phase: 'data_processing', step: 2 }),
      ttl_seconds: 3600
    }
  });
  console.log('Memory Set Result:', JSON.stringify(memSet, null, 2));

  // 4. Retrieve agent memory
  console.log('\nRetrieving key-value from agent_memory_store...');
  const memGet = await client.callTool({
    name: 'agent_memory_store',
    arguments: {
      action: 'get',
      key: 'workflow_state'
    }
  });
  console.log('Memory Get Result:', JSON.stringify(memGet, null, 2));

  await client.close();
  console.log('\nConnection cleanly closed.');
}

runDemo().catch(console.error);
