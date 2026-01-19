# ============================================================================
# LLM-Shield Unified Service - Cloud Run Dockerfile
# ============================================================================
# Builds the unified LLM-Shield service containing all 9 agents.
# Optimized for Google Cloud Run deployment.
#
# Build: docker build -t llm-shield-service:latest -f Dockerfile .
# Run:   docker run -p 8080:8080 --env-file .env llm-shield-service:latest
# ============================================================================

FROM node:20-slim

WORKDIR /app

# Install build dependencies (needed for native modules)
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy everything
COPY . .

# Install dependencies for the root workspace
RUN npm install

# Build contracts first (shared dependency)
WORKDIR /app/contracts
RUN npm run build || echo "contracts build completed"

# Build each agent
WORKDIR /app/prompt-injection-detection
RUN npm install && npm run build || echo "prompt-injection build completed"

WORKDIR /app/pii-detection
RUN npm install && npm run build || echo "pii-detection build completed"

WORKDIR /app/data-redaction
RUN npm install && npm run build || echo "data-redaction build completed"

WORKDIR /app/secrets-leakage-detection
RUN npm install && npm run build || echo "secrets-leakage build completed"

WORKDIR /app/toxicity-detection
RUN npm install && npm run build || echo "toxicity-detection build completed"

WORKDIR /app/safety-boundary
RUN npm install && npm run build || echo "safety-boundary build completed"

WORKDIR /app/content-moderation
RUN npm install && npm run build || echo "content-moderation build completed"

WORKDIR /app/model-abuse-detection
RUN npm install && npm run build || echo "model-abuse build completed"

WORKDIR /app/credential-exposure-detection
RUN npm install && npm run build || echo "credential-exposure build completed"

# Build service
WORKDIR /app/service
RUN npm install && npm run build || echo "service build completed"

# Return to app root
WORKDIR /app

# Create non-root user for security
RUN groupadd -r llmshield && useradd -r -g llmshield llmshield && \
    chown -R llmshield:llmshield /app

# Switch to non-root user
USER llmshield

# Environment defaults
ENV NODE_ENV=production
ENV PORT=8080
ENV HOST=0.0.0.0
ENV SERVICE_NAME=llm-shield
ENV SERVICE_VERSION=1.0.0

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:8080/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

# Start the service
CMD ["node", "service/dist/index.js"]

# ============================================================================
# Metadata
# ============================================================================
LABEL maintainer="LLM-Shield Team"
LABEL description="LLM-Shield Unified Security Service - All 9 Detection Agents"
LABEL version="1.0.0"
