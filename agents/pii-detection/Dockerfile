# PII Detection Agent - Docker Image
#
# Multi-stage build for optimized production deployment
# on Google Cloud Run and other container platforms.
#
# Build:
#   docker build -t pii-detection-agent .
#
# Run:
#   docker run -p 8080:8080 pii-detection-agent

# =============================================================================
# Stage 1: Build
# =============================================================================
FROM node:20-slim AS builder

WORKDIR /app

# Copy package files
COPY package.json ./
COPY tsconfig.json ./

# Copy source code
COPY src ./src

# Install dependencies (including dev dependencies for build)
RUN npm install

# Build TypeScript
RUN npm run build

# =============================================================================
# Stage 2: Production
# =============================================================================
FROM node:20-slim AS production

# Security: Run as non-root user
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 agent

WORKDIR /app

# Copy package files
COPY --from=builder /app/package.json ./

# Install production dependencies only
RUN npm install --omit=dev && npm cache clean --force

# Copy built files
COPY --from=builder /app/dist ./dist

# Copy agent specification
COPY AGENT.md ./

# Set ownership
RUN chown -R agent:nodejs /app

# Switch to non-root user
USER agent

# Environment configuration
ENV NODE_ENV=production
ENV PORT=8080

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Start the agent
CMD ["node", "dist/edge-handler.js"]
