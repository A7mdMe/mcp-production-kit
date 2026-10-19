import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ServerConfig } from './config.js';
import { Logger } from './logger.js';
import { SystemMetricsInputSchema, executeSystemMetrics } from './tools/systemMetrics.js';
import { SecureFetchInputSchema, executeSecureFetch } from './tools/secureFetch.js';
import { AgentMemoryInputSchema, executeAgentMemory } from './tools/agentMemory.js';

export function createProductionServer(config: ServerConfig, logger: Logger) {
  const server = new McpServer({
    name: config.SERVER_NAME,
    version: config.SERVER_VERSION
  });

  // 1. Tool: get_system_metrics
  server.tool(
    'get_system_metrics',
    'Retrieve real-time operating system, CPU load, and memory telemetry for agent health introspection.',
    SystemMetricsInputSchema.shape,
    async (params) => {
      logger.debug('Executing get_system_metrics', { params });
      return await executeSystemMetrics(params);
    }
  );

  // 2. Tool: secure_http_fetch
  server.tool(
    'secure_http_fetch',
    'Execute SSRF-protected HTTP requests with domain whitelisting, payload size limits, and timeout controls.',
    SecureFetchInputSchema.shape,
    async (params) => {
      logger.info('Executing secure_http_fetch', { url: params.url, method: params.method });
      return await executeSecureFetch(params, config);
    }
  );

  // 3. Tool: agent_memory_store
  server.tool(
    'agent_memory_store',
    'In-memory key-value state store with namespace isolation and TTL support for persistent agent workflows.',
    AgentMemoryInputSchema.shape,
    async (params) => {
      logger.debug('Executing agent_memory_store', { action: params.action, key: params.key, namespace: params.namespace });
      return await executeAgentMemory(params);
    }
  );

  return server;
}
