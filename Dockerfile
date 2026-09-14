# ============================================================================
# Stage 1: Build & Compilation Stage
# ============================================================================
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Install all dependencies (including devDependencies for TypeScript compilation)
COPY package.json package-lock.json ./
RUN npm ci

# Copy TypeScript configuration and source tree
COPY tsconfig.json ./
COPY src/ ./src/
COPY tests/ ./tests/

# Compile TypeScript to /app/dist
RUN npm run build

# Remove development dependencies for minimal footprint
RUN npm prune --omit=dev

# ============================================================================
# Stage 2: Minimal Zero-Trust Runtime Stage (<256MB RAM Footprint)
# ============================================================================
FROM node:20-alpine AS runner

WORKDIR /app

# Security: Non-root user execution
USER node

# Production configuration and V8 heap constraint for low-memory environments
ENV NODE_ENV=production
ENV NODE_OPTIONS="--max-old-space-size=192"
ENV RELAY_P2P_PORT=9090
ENV RELAY_CONTROL_PORT=9091
ENV ORIGIN_HOST=127.0.0.1
ENV ORIGIN_PORT=8080

# Copy runtime files with ownership
COPY --chown=node:node --from=builder /app/package.json ./
COPY --chown=node:node --from=builder /app/node_modules ./node_modules
COPY --chown=node:node --from=builder /app/dist ./dist

# Expose Noise TCP relay port and telemetry control port
EXPOSE 9090 9091

# Health check
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "import('http').then(h => h.get('http://127.0.0.1:9091/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1)))"

# Start relay node
CMD ["node", "dist/src/relay.js"]