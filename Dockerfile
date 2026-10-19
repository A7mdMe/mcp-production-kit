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

COPY package*.json ./
RUN npm ci --only=production
COPY --from=builder /app/dist ./dist

# Run as non-root user for security
USER node

# Default to stdio transport for local agents & Glama introspection
ENTRYPOINT ["node", "dist/index.js"]
CMD ["--transport=stdio"]
