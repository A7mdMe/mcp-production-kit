import { loadConfig } from './config.js';
import { Logger } from './logger.js';
import { createProductionServer } from './server.js';
import { runStdioTransport } from './transports/stdio.js';
import { runHttpSseTransport } from './transports/httpSse.js';

function parseArgs() {
  const args = process.argv.slice(2);
  const options: Record<string, string> = {};

  for (const arg of args) {
    if (arg.startsWith('--')) {
      const [key, value] = arg.slice(2).split('=');
      options[key] = value || 'true';
    }
  }
  return options;
}

async function main() {
  const cliArgs = parseArgs();

  const config = loadConfig({
    ...process.env,
    ...(cliArgs.port ? { PORT: cliArgs.port } : {}),
    ...(cliArgs['log-level'] ? { LOG_LEVEL: cliArgs['log-level'] } : {})
  });

  const logger = new Logger(config.LOG_LEVEL);
  const transportMode = cliArgs.transport || process.env.MCP_TRANSPORT || 'stdio';

  logger.info(`Initializing ${config.SERVER_NAME} v${config.SERVER_VERSION} (Mode: ${transportMode})`);

  // Universal PID 1 Signal Handling for Docker & Process Orchestrators
  let isShuttingDown = false;
  const gracefulShutdown = (signal: string) => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    logger.info(`Received ${signal}, shutting down MCP server gracefully...`);

    // Force exit after 3 seconds if transport drain takes too long
    const forceExitTimer = setTimeout(() => {
      logger.warn('Forcing server exit after shutdown timeout');
      process.exit(0);
    }, 3000);
    if (typeof forceExitTimer.unref === 'function') forceExitTimer.unref();

    process.exit(0);
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  const server = createProductionServer(config, logger);

  if (transportMode === 'sse' || transportMode === 'http') {
    runHttpSseTransport(server, config, logger);
  } else if (transportMode === 'stdio') {
    await runStdioTransport(server, logger);
  } else {
    logger.error(`Unknown transport mode: ${transportMode}. Use 'stdio' or 'sse'.`);
    process.exit(1);
  }
}

main().catch(err => {
  process.stderr.write(`[Fatal Error] ${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(1);
});
