# Multi-stage build for MCP Production Kit (Open-Source Core)
FROM node:24-alpine AS builder

WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src/ ./src/
RUN npx tsc

# Production runtime stage
FROM node:24-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production

# Install tini to handle PID 1 signal forwarding & zombie reaping (resolves servers #5611)
RUN apk add --no-cache tini

COPY package*.json ./
RUN npm ci --only=production
COPY --from=builder /app/dist ./dist

# Run as non-root user for security
USER node

# Default to stdio transport for local agents & Glama introspection
ENTRYPOINT ["/sbin/tini", "--", "node", "dist/index.js"]
CMD ["--transport=stdio"]
