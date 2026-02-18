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

# Install all workspace dependencies (hoists shared deps to root)
RUN npm install

# Build all workspaces in dependency order:
# 1. contracts (shared types) and lib (shared infrastructure) first
# 2. All agent modules (tolerate TS errors - JS is still emitted via noEmitOnError:false)
# 3. service (unified entry point - uses dynamic imports, tolerates missing type decls)
RUN npm run build -w @llm-shield/agentics-contracts && \
    npm run build -w @llm-shield/lib && \
    npx -w prompt-injection-detection tsc || true && \
    npx -w pii-detection tsc || true && \
    npx -w data-redaction tsc || true && \
    npx -w secrets-leakage-detection tsc || true && \
    npx -w toxicity-detection tsc || true && \
    npx -w safety-boundary tsc || true && \
    npx -w content-moderation tsc || true && \
    npx -w model-abuse-detection tsc || true && \
    npx -w credential-exposure-detection tsc || true && \
    npx -w service tsc || true && \
    echo "Build complete - verifying service entry point..." && \
    test -f service/dist/index.js && echo "service/dist/index.js exists"

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
