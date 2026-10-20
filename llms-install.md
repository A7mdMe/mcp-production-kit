# MCP Production Kit — Cline / LLM Installation Guide

This guide provides explicit configuration instructions for automated coding agents (such as Cline, Claude Desktop, and Cursor) to build, configure, and run **mcp-production-kit**.

## Prerequisites
- Node.js >= 20.0.0
- npm >= 9.0.0

## Local Build & Run
```bash
npm ci
npm run build
node dist/index.js
```

## Cline MCP Configuration
Add to your Cline MCP settings (`cline_mcp_settings.json`):

```json
{
  "mcpServers": {
    "mcp-production-kit": {
      "command": "node",
      "args": ["<PATH_TO_CLONED_REPO>/dist/index.js"],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

## Docker Execution Setup
```bash
docker build -t mcp-production-kit .
```

```json
{
  "mcpServers": {
    "mcp-production-kit": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "mcp-production-kit:latest"],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

## Tools Provided
- `fetch_web_clean`: Fetches external web content into clean Markdown while enforcing SSRF protection against RFC-1918 private subnets and metadata IPs.
- `query_postgres_read_only`: Executes read-only SQL queries with comment stripping and mutation keyword blocking.
- `execute_cloudflare_worker`: Dispatches tasks to serverless edge execution on Cloudflare Workers.
