# Enterprise Deployment Guide for Model Context Protocol (MCP)

This guide walks through deploying a production-ready Model Context Protocol (MCP v2024-11-05) TypeScript server across different operational topologies: local desktop, containerized remote servers, and serverless edge runtimes.

---

## 1. Local Stdio Deployment (Claude Desktop / Cursor)

### The Stdio Protocol Requirement
When running an MCP server locally via `stdio`, the AI client communicates via Standard Input (`stdin`) and Standard Output (`stdout`). Every message must follow JSON-RPC 2.0 framing.

**Critical Rule:** Any unauthorized write to `stdout` (e.g. `console.log("Starting server...")`) will break the JSON framing and cause Claude Desktop or Cursor to terminate the connection.

### Configuration
Build your project and reference the compiled bundle:
```bash
npm run build
```

Add the following to your `claude_desktop_config.json`:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "production-kit": {
      "command": "node",
      "args": [
        "/absolute/path/to/mcp-production-kit/dist/index.js",
        "--transport=stdio"
      ]
    }
  }
}
```

---

## 2. Remote Containerized Deployment (Docker & SSE)

For multi-user teams, shared agents, or central infrastructure, deploy the server as a long-running HTTP service using Server-Sent Events (SSE).

### Multi-Stage Dockerfile Pattern
```dockerfile
# Stage 1: Build
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src/ ./src/
RUN npm run build

# Stage 2: Production Distroless / Non-Root Runner
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV TRANSPORT=sse
ENV PORT=3000

COPY package*.json ./
RUN npm ci --only=production
COPY --from=builder /app/dist ./dist

# Security: Run as non-root user
USER node
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

CMD ["node", "dist/index.js", "--transport=sse"]
```

### Build & Run
```bash
docker build -t mcp-production-server .
docker run -p 3000:3000 -e TRANSPORT=sse mcp-production-server
```

Endpoints available:
- `GET /health` — Returns JSON status `{"status": "healthy", "uptime": ...}`
- `GET /sse` — Establishes persistent Server-Sent Events stream for MCP communication.
- `POST /message?sessionId=...` — Delivers client JSON-RPC requests to the active SSE session.

---

## 3. Serverless Edge Deployment (Cloudflare Workers)

*Available via the [Commercial Pro Pack](https://whop.com/checkout/plan_eiKHeRpooY3yc)*

For low-latency edge deployments without managing dedicated VM instances, Cloudflare Workers provides an optimal edge architecture:
- Low-latency edge execution using Cloudflare Workers.
- Bearer token authentication via Worker secrets (`MCP_AUTH_TOKEN`).
- Native SSE response streaming utilizing standard Web Streams API.

---

## 4. Production Security Checklist

1. **SSRF Guarding:** Never allow tools to make arbitrary outbound network requests to internal networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`, or `169.254.169.254`).
2. **Read-Only Database Permissions:** Grant minimal database roles (`SELECT` only) when providing SQL tools, with comment-stripping and keyword validation to block destructive DDL and stacked queries.
3. **Structured Stderr Logging:** Always route operational logs and errors to `stderr` with automated credential masking.
