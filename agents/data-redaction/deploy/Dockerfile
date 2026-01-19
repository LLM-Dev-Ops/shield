# Data Redaction Agent - Container Image
# LLM-Shield - Google Cloud Edge Function Deployment
#
# Build: docker build -t data-redaction-agent .
# Run:   docker run -p 8080:8080 data-redaction-agent

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production=false

# Copy source
COPY src/ ./src/

# Build TypeScript
RUN npm run build

# Stage 2: Production
FROM node:20-alpine AS production

# Add non-root user
RUN addgroup -g 1001 -S agent && \
    adduser -u 1001 -S agent -G agent

WORKDIR /app

# Copy production dependencies
COPY package.json package-lock.json* ./
RUN npm ci --only=production && npm cache clean --force

# Copy built files
COPY --from=builder /app/dist ./dist

# Copy agent metadata
COPY AGENT.md ./

# Set ownership
RUN chown -R agent:agent /app

# Switch to non-root user
USER agent

# Environment variables
ENV NODE_ENV=production
ENV PORT=8080

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:8080/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

# Start the agent
CMD ["node", "dist/index.js"]
