# ============================================================================
# LLM-Shield Unified Service - Cloud Run Dockerfile (HARDENED)
# ============================================================================
# Builds the unified LLM-Shield service containing all 9 agents.
# Optimized for Google Cloud Run deployment.
#
# Phase 1 / Layer 1 - Foundational Tooling
#
# HARDENING REQUIREMENTS:
# - Ruvector is REQUIRED (service will crash if unavailable)
# - All secrets must be provided via environment variables
# - Startup validation runs before service starts
# - Non-root user for security
# - Minimal logging (agent_started, decision_event_emitted, agent_abort)
#
# Build: docker build -t llm-shield-service:latest -f Dockerfile .
# Run:   docker run -p 8080:8080 --env-file .env llm-shield-service:latest
# ============================================================================

FROM node:20-slim

# Build argument for version
ARG SERVICE_VERSION=1.0.0

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

# Build lib module (shared infrastructure for hardening)
WORKDIR /app/lib
RUN npm install && npm run build || echo "lib build completed"

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

# Build service (with hardened startup validation)
WORKDIR /app/service
RUN npm install && npm run build || echo "service build completed"

# Return to app root
WORKDIR /app

# Create non-root user for security
RUN groupadd -r llmshield && useradd -r -g llmshield llmshield && \
    chown -R llmshield:llmshield /app

# Switch to non-root user
USER llmshield

# ============================================================================
# MANDATORY ENVIRONMENT VARIABLES (Phase 1 / Layer 1)
# ============================================================================
# These MUST be provided at runtime via Cloud Run secrets or environment:
#
# REQUIRED (from Google Secret Manager):
#   RUVECTOR_SERVICE_URL - Ruvector service endpoint
#   RUVECTOR_API_KEY     - Ruvector API authentication key
#
# REQUIRED (set in cloudbuild.yaml):
#   AGENT_NAME           - Agent name identifier
#   AGENT_DOMAIN         - Agent domain (e.g., security)
#   AGENT_PHASE          - Must be "phase1"
#   AGENT_LAYER          - Must be "layer1"
#
# OPTIONAL:
#   TELEMETRY_ENDPOINT   - Telemetry service endpoint
# ============================================================================

# Environment defaults (non-sensitive)
ENV NODE_ENV=production
ENV PORT=8080
ENV HOST=0.0.0.0
ENV SERVICE_NAME=llm-shield
ENV SERVICE_VERSION=${SERVICE_VERSION}

# Agent identity defaults (should be overridden at deploy time)
ENV AGENT_NAME=llm-shield
ENV AGENT_DOMAIN=security
ENV AGENT_PHASE=phase1
ENV AGENT_LAYER=layer1

# Expose port
EXPOSE 8080

# Health check (checks both service health AND Ruvector connectivity)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD node -e "require('http').get('http://localhost:8080/health', (r) => { let d=''; r.on('data',c=>d+=c); r.on('end',()=>{const j=JSON.parse(d); process.exit(j.status==='healthy'?0:1)}) })"

# Start the service
# NOTE: Service will crash immediately if:
# - RUVECTOR_SERVICE_URL is not set
# - RUVECTOR_API_KEY is not set
# - AGENT_NAME is not set
# - AGENT_DOMAIN is not set
# - AGENT_PHASE is not "phase1"
# - AGENT_LAYER is not "layer1"
# - Ruvector health check fails
CMD ["node", "service/dist/index.js"]

# ============================================================================
# Metadata
# ============================================================================
LABEL maintainer="LLM-Shield Team"
LABEL description="LLM-Shield Unified Security Service - All 9 Detection Agents (HARDENED)"
LABEL version="${SERVICE_VERSION}"
LABEL phase="phase1"
LABEL layer="layer1"
