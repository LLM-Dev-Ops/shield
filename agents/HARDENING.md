# LLM-Shield Hardening Summary

## Phase 1 / Layer 1 - Foundational Tooling

**Date:** 2026-01-25

---

## 1. Modified Files

| File | Change Type | Description |
|------|-------------|-------------|
| `agents/lib/startup-validator.ts` | NEW | Mandatory startup validation module |
| `agents/lib/performance-boundaries.ts` | NEW | Performance boundary enforcement |
| `agents/lib/decision-event.ts` | NEW | Standardized DecisionEvent factory |
| `agents/lib/read-cache.ts` | NEW | Read-only in-memory caching (TTL 30-60s) |
| `agents/lib/index.ts` | NEW | Shared infrastructure exports |
| `agents/lib/package.json` | NEW | Package configuration for lib module |
| `agents/lib/tsconfig.json` | NEW | TypeScript configuration for lib module |
| `agents/service/index.ts` | MODIFIED | Integrated hardening requirements |
| `agents/service/package.json` | MODIFIED | Added lib dependency |
| `agents/service/.env.example` | MODIFIED | Added mandatory environment variables |
| `agents/Dockerfile` | MODIFIED | Added lib build step, hardening docs |
| `agents/cloudbuild.yaml` | MODIFIED | Added agent identity, enhanced verification |

---

## 2. Summary of Changes

### 2.1 Mandatory Startup Requirements

- **Environment Variable Validation**: Service asserts presence of:
  - `RUVECTOR_SERVICE_URL` (from Google Secret Manager)
  - `RUVECTOR_API_KEY` (from Google Secret Manager)
  - `AGENT_NAME`
  - `AGENT_DOMAIN`
  - `AGENT_PHASE=phase1`
  - `AGENT_LAYER=layer1`

- **Ruvector Health Check**: Service performs lightweight ping to Ruvector at startup
- **Startup Failure Behavior**: Container crashes immediately if any check fails

### 2.2 Agent Identity Standardization

Every DecisionEvent now includes:
- `source_agent`: Agent name identifier
- `domain`: Agent domain (e.g., security)
- `phase`: Deployment phase (phase1)
- `layer`: Deployment layer (layer1)

### 2.3 DecisionEvent Quality Rules

Agents emit **signals**, NOT conclusions:
- `event_type`: Type of detection event
- `confidence`: Confidence score (0-1)
- `evidence_refs`: Evidence references supporting the signal
- `signals`: Raw detection signals without synthesis

### 2.4 Performance Boundaries

Conservative defaults enforced:
- `MAX_TOKENS=800`: Maximum input content tokens
- `MAX_LATENCY_MS=1500`: Maximum execution time
- `MAX_CALLS_PER_RUN=2`: Maximum external API calls per detection

Execution aborts if any boundary exceeded.

### 2.5 Caching (Read-Only Only)

In-memory caching with TTL 30-60 seconds for:
- Ruvector health checks
- Schema lookups
- Registry lookups

### 2.6 Observability (Minimal)

Structured JSON logging for only:
- `agent_started`: Service startup
- `decision_event_emitted`: DecisionEvent emission
- `agent_abort`: Service abort/error

### 2.7 Contract Assertions

- Ruvector required = `true`
- ≥1 DecisionEvent emitted per run (assertion available)

### 2.8 Deployment Preparation

- All secrets via Google Secret Manager (no inline secrets)
- Startup failures crash the container (intentional)

---

## 3. Cloud Run Deploy Command Template

### Basic Deployment

```bash
gcloud builds submit --config agents/cloudbuild.yaml agents/ \
  --substitutions=_ENV=dev,_REGION=us-central1
```

### Production Deployment

```bash
gcloud builds submit --config agents/cloudbuild.yaml agents/ \
  --substitutions=\
_ENV=prod,\
_REGION=us-central1,\
_SERVICE_NAME=llm-shield,\
_SERVICE_VERSION=1.0.0,\
_MIN_INSTANCES=1,\
_MAX_INSTANCES=10,\
_MEMORY=1Gi,\
_CPU=1,\
_AGENT_NAME=llm-shield,\
_AGENT_DOMAIN=security,\
_AGENT_PHASE=phase1,\
_AGENT_LAYER=layer1
```

### Required Google Secret Manager Secrets

Before deployment, ensure these secrets exist:

```bash
# Create secrets (one-time setup)
gcloud secrets create ruvector-service-url --replication-policy="automatic"
gcloud secrets create ruvector-api-key --replication-policy="automatic"
gcloud secrets create telemetry-endpoint --replication-policy="automatic"

# Add secret versions
echo -n "https://ruvector-service.example.com" | \
  gcloud secrets versions add ruvector-service-url --data-file=-

echo -n "your-api-key" | \
  gcloud secrets versions add ruvector-api-key --data-file=-

echo -n "https://observatory.example.com/telemetry" | \
  gcloud secrets versions add telemetry-endpoint --data-file=-

# Grant service account access
gcloud secrets add-iam-policy-binding ruvector-service-url \
  --member="serviceAccount:llm-shield-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding ruvector-api-key \
  --member="serviceAccount:llm-shield-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding telemetry-endpoint \
  --member="serviceAccount:llm-shield-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

---

## 4. Confirmation Checklist

### Mandatory Startup Requirements
- [x] RUVECTOR_SERVICE_URL assertion implemented
- [x] RUVECTOR_API_KEY assertion implemented (from Secret Manager)
- [x] AGENT_NAME assertion implemented
- [x] AGENT_DOMAIN assertion implemented
- [x] AGENT_PHASE=phase1 validation implemented
- [x] AGENT_LAYER=layer1 validation implemented
- [x] Ruvector client initialization at startup
- [x] Ruvector health check (ping) at startup
- [x] Startup failure crashes container

### Agent Identity Standardization
- [x] DecisionEvents include `source_agent`
- [x] DecisionEvents include `domain`
- [x] DecisionEvents include `phase`
- [x] DecisionEvents include `layer`
- [x] No anonymous agents
- [x] No inferred identity

### DecisionEvent Quality Rules
- [x] Agents emit signals, NOT conclusions
- [x] Events include `event_type`
- [x] Events include `confidence` (0-1)
- [x] Events include `evidence_refs`
- [x] Agents do NOT emit summaries
- [x] Agents do NOT emit recommendations
- [x] Agents do NOT perform synthesis

### Performance Boundaries
- [x] MAX_TOKENS=800 default implemented
- [x] MAX_LATENCY_MS=1500 default implemented
- [x] MAX_CALLS_PER_RUN=2 default implemented
- [x] Execution aborts if exceeded

### Caching (Read-Only Only)
- [x] In-memory caching implemented
- [x] TTL 30-60 seconds enforced
- [x] Used for telemetry reads
- [x] Used for registry lookups
- [x] Used for schema checks

### Observability (Minimal)
- [x] Log ONLY `agent_started`
- [x] Log ONLY `decision_event_emitted`
- [x] Log ONLY `agent_abort`
- [x] Structured JSON logging

### Contract Assertions
- [x] Assert Ruvector required = true
- [x] Assert ≥1 DecisionEvent emitted per run (utility available)

### Deployment Prep
- [x] Secrets referenced via Google Secret Manager
- [x] No inline secrets in code
- [x] No inline secrets in cloudbuild.yaml
- [x] Startup failures crash the container

---

## 5. Testing

### Local Testing

```bash
# Set required environment variables
export RUVECTOR_SERVICE_URL=http://localhost:8080
export RUVECTOR_API_KEY=test-api-key
export AGENT_NAME=llm-shield-test
export AGENT_DOMAIN=security
export AGENT_PHASE=phase1
export AGENT_LAYER=layer1

# Build and start
cd agents
npm install
cd lib && npm run build && cd ..
cd service && npm run build && npm start
```

### Docker Testing

```bash
# Build image
docker build -t llm-shield:test -f agents/Dockerfile agents/

# Run with required environment
docker run -p 8080:8080 \
  -e RUVECTOR_SERVICE_URL=http://ruvector:8080 \
  -e RUVECTOR_API_KEY=test-key \
  -e AGENT_NAME=llm-shield \
  -e AGENT_DOMAIN=security \
  -e AGENT_PHASE=phase1 \
  -e AGENT_LAYER=layer1 \
  llm-shield:test
```

### Verify Endpoints

```bash
# Health check (should return status and identity)
curl http://localhost:8080/health | jq

# Info endpoint (should show hardening status)
curl http://localhost:8080/info | jq

# Readiness check (should verify Ruvector connection)
curl http://localhost:8080/ready | jq
```

---

## 6. Rollback

If issues occur, rollback to previous version:

```bash
# List revisions
gcloud run revisions list --service llm-shield-dev --region us-central1

# Rollback to specific revision
gcloud run services update-traffic llm-shield-dev \
  --region us-central1 \
  --to-revisions REVISION_NAME=100
```

---

## 7. Architecture Notes

### Startup Flow

```
1. assertStartupRequirements()
   ├── validateEnvironment()
   │   ├── Check RUVECTOR_SERVICE_URL
   │   ├── Check RUVECTOR_API_KEY
   │   ├── Check AGENT_NAME
   │   ├── Check AGENT_DOMAIN
   │   ├── Validate AGENT_PHASE=phase1
   │   └── Validate AGENT_LAYER=layer1
   └── checkRuvectorHealth()
       └── HTTP GET /health to Ruvector

2. If ANY check fails → process.exit(1)

3. startCacheCleanup()

4. loadHandlers()
   └── Load all 9 agent handlers with performance wrappers

5. startServer()
   └── HTTP server listening on PORT
```

### Request Flow

```
Request → Handler Wrapper
           ├── Check token limit (MAX_TOKENS)
           ├── Execute handler
           └── Check latency (MAX_LATENCY_MS)

If any limit exceeded → HTTP 429 + structured error
```

---

## 8. Contacts

For questions about this hardening pass:
- Architecture: Review `agents/lib/` modules
- Deployment: Review `agents/cloudbuild.yaml`
- Configuration: Review `agents/service/.env.example`
