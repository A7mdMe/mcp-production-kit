import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Logger } from '../logger.js';

export async function runStdioTransport(server: McpServer, logger: Logger) {
  const transport = new StdioServerTransport();

  logger.info('Starting MCP server on stdio transport...');

  const cleanup = async () => {
    logger.info('Shutting down stdio transport...');
    await transport.close();
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  await server.connect(transport);
  logger.info('MCP server successfully connected to stdio transport.');
}
