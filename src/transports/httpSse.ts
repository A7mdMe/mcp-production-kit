import http from 'http';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { ServerConfig } from '../config.js';
import { Logger } from '../logger.js';

export function runHttpSseTransport(server: McpServer, config: ServerConfig, logger: Logger) {
  const transports: Map<string, SSEServerTransport> = new Map();

  const httpServer = http.createServer(async (req: http.IncomingMessage, res: http.ServerResponse) => {
    // Enable CORS for web-based agent frontends
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

    // Optional Bearer Token Authentication
    if (config.AUTH_TOKEN && url.pathname !== '/health') {
      const authHeader = req.headers.authorization;
      const expected = `Bearer ${config.AUTH_TOKEN}`;
      if (!authHeader || authHeader !== expected) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Invalid or missing Bearer token' }));
        return;
      }
    }

    // 1. Healthcheck Endpoint
    if (url.pathname === '/health' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'healthy',
        server: config.SERVER_NAME,
        version: config.SERVER_VERSION,
        uptimeSeconds: Math.round(process.uptime()),
        activeSessions: transports.size
      }));
      return;
    }

    // 2. Server-Sent Events Endpoint
    if (url.pathname === '/sse' && req.method === 'GET') {
      logger.info('Incoming SSE connection initiated');
      const transport = new SSEServerTransport('/messages', res);
      const sessionId = transport.sessionId;

      transports.set(sessionId, transport);

      transport.onclose = () => {
        logger.info(`SSE session ${sessionId} closed`);
        transports.delete(sessionId);
      };

      await server.connect(transport);
      return;
    }

    // 3. Message Post Endpoint
    if (url.pathname === '/messages' && req.method === 'POST') {
      const sessionId = url.searchParams.get('sessionId');
      if (!sessionId || !transports.has(sessionId)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Request: Missing or invalid sessionId parameter' }));
        return;
      }

      const transport = transports.get(sessionId)!;
      await transport.handlePostMessage(req, res);
      return;
    }

    // 404 Fallback
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Endpoint not found' }));
  });

  httpServer.listen(config.PORT, () => {
    logger.info(`MCP HTTP/SSE Server listening on http://localhost:${config.PORT}`);
    logger.info(`Health check available at http://localhost:${config.PORT}/health`);
    logger.info(`SSE Stream available at http://localhost:${config.PORT}/sse`);
  });

  const cleanup = () => {
    logger.info('Gracefully closing HTTP/SSE server...');
    httpServer.close(() => {
      logger.info('HTTP server terminated.');
      process.exit(0);
    });
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  return httpServer;
}
