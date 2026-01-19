# Model Abuse Detection Agent Contract

## Agent Identity

| Property | Value |
|----------|-------|
| **Agent ID** | `model-abuse-detection-agent` |
| **Version** | `1.0.0` |
| **Classification** | `DETECTION_ONLY` |
| **Decision Type** | `model_abuse_detection` |

## Purpose Statement

The Model Abuse Detection Agent detects patterns of misuse, abuse, or exploitation of LLM systems. It identifies unauthorized access attempts, rate limit evasion, model extraction attacks, training data extraction attempts, adversarial inputs, and other abuse patterns that could compromise system integrity or security.

This agent provides **DETECTION ONLY** - it identifies and reports abuse patterns but does not take enforcement actions. All decisions are persisted to ruvector-service for analysis and potential downstream enforcement by other agents.

## This Agent Does NOT:

- Modify or redact content
- Block or allow requests
- Orchestrate workflows
- Connect directly to databases
- Perform retries on failures
- Trigger alerts or incidents
- Modify policies or thresholds dynamically

## Detection Categories

| Category | Description | Severity Range |
|----------|-------------|----------------|
| `unauthorized_access` | Unauthorized API/model access attempts | critical |
| `rate_limit_evasion` | Attempts to evade rate limits | high |
| `credential_stuffing` | Automated credential testing | critical |
| `model_extraction` | Attempts to extract model weights/behavior | critical-high |
| `prompt_harvesting` | Systematic prompt collection | high |
| `training_data_extraction` | Attempts to extract training data | critical-high |
| `resource_exhaustion` | Intentional resource overconsumption | critical-high |
| `api_abuse` | General API misuse patterns | low-medium |
| `inference_attack` | Model inference/membership attacks | high |
| `adversarial_input` | Adversarial examples targeting model behavior | medium |
| `fingerprinting` | Model fingerprinting attempts | low |
| `context_manipulation` | Manipulating context windows maliciously | high |

## Input Schema

**Reference:** `@llm-shield/agentics-contracts.ModelAbuseDetectionInput`

```typescript
interface ModelAbuseDetectionInput {
  // Base detection input
  content: string;                    // Content to analyze
  context: InvocationContext;         // Execution context
  config_overrides?: Record<string, unknown>;

  // Detection configuration
  sensitivity?: number;               // 0.0-1.0, default 0.5
  threshold?: number;                 // 0.0-1.0, default 0.7
  detect_categories?: ModelAbuseCategory[];  // Subset of categories

  // Request metadata (for behavioral analysis)
  request_metadata?: {
    request_rate?: number;            // Requests per minute
    client_ip_hash?: string;          // Anonymized client identifier
    user_agent_hash?: string;         // Anonymized user agent
    session_request_count?: number;   // Requests in session
    session_token_usage?: number;     // Tokens used in session
    appears_automated?: boolean;      // Automation indicator
    api_endpoint?: string;            // Endpoint being accessed
    request_timestamp?: string;       // For temporal analysis
  };

  // Historical context
  historical_context?: {
    previous_request_count?: number;  // Previous requests from source
    previous_violation_count?: number; // Previous violations
    session_duration_seconds?: number; // Session duration
  };
}
```

## Output Schema

**Reference:** `@llm-shield/agentics-contracts.ModelAbuseDetectionAgentOutput`

```typescript
interface ModelAbuseDetectionAgentOutput {
  agent: AgentIdentity;
  result: ModelAbuseDetectionResult;
  duration_ms: number;
  cached: boolean;
}

interface ModelAbuseDetectionResult {
  abuse_detected: boolean;           // Whether abuse was detected
  risk_score: number;                // 0.0-1.0 overall risk
  severity: Severity;                // Overall severity level
  confidence: number;                // 0.0-1.0 overall confidence
  entities: ModelAbuseDetectedEntity[];  // Detected entities
  risk_factors: RiskFactor[];        // Contributing risk factors
  pattern_match_count: number;       // Number of patterns matched
  detected_categories: ModelAbuseCategory[];  // Categories detected
  category_counts: Record<string, number>;    // Count per category
  behavioral_summary?: {
    appears_automated: boolean;
    abnormal_rate: boolean;
    matches_abuse_signature: boolean;
    red_flag_count: number;
  };
}
```

## DecisionEvent Mapping

**Reference:** `@llm-shield/agentics-contracts.ModelAbuseDetectionDecisionEvent`

Every invocation emits exactly ONE DecisionEvent to ruvector-service:

```typescript
interface ModelAbuseDetectionDecisionEvent {
  agent_id: "model-abuse-detection-agent";
  agent_version: string;
  decision_type: "model_abuse_detection";
  inputs_hash: string;               // SHA-256 of content (NOT raw content)
  outputs: {
    abuse_detected: boolean;
    risk_score: number;
    severity: Severity;
    confidence: number;
    pattern_match_count: number;
    detected_categories: string[];
    entity_count: number;
    category_counts: Record<string, number>;
    behavioral_summary?: { ... };
  };
  confidence: number;
  constraints_applied: PolicyReference[];
  execution_ref: string;             // UUID for tracing
  timestamp: string;                 // UTC ISO 8601
  duration_ms: number;
  telemetry?: {
    content_length: number;
    content_source: string;
    session_id?: string;
    caller_id?: string;
    threshold_used?: number;
    categories_checked?: string[];
    request_rate_bucket?: string;    // "low", "medium", "high", "extreme"
    session_request_bucket?: string; // "few", "some", "many", "excessive"
  };
}
```

## Data Persistence Rules

### PERSISTED to ruvector-service:

- Input content hash (SHA-256) - never raw content
- Detection outputs (abuse_detected, risk_score, severity, confidence)
- Pattern match count
- Detected categories (names only)
- Entity count
- Category counts
- Behavioral summary (boolean flags and counts)
- Execution metadata (duration, timestamp, execution_ref)
- Telemetry (content length, source, bucketed rates)

### NEVER PERSISTED:

- Raw content (prompts, outputs)
- Raw patterns matched (only IDs)
- IP addresses (only hashes if provided)
- User agent strings (only hashes if provided)
- Session identifiers (only if explicitly provided in context)
- Any personally identifiable information

## CLI Contract

```bash
# Test mode - execute detection with persistence
model-abuse-detection-agent test --content "..." [options]

# Simulate mode - execute detection WITHOUT persistence
model-abuse-detection-agent simulate --content "..." [options]

# Inspect mode - display agent information
model-abuse-detection-agent inspect [--verbose] [--format json|text|table]

# Help
model-abuse-detection-agent help

# Version
model-abuse-detection-agent version
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--content, -c` | Content to analyze (required for test/simulate) | - |
| `--sensitivity, -s` | Detection sensitivity (0-1) | 0.5 |
| `--threshold, -t` | Detection threshold (0-1) | 0.7 |
| `--categories` | Comma-separated categories to detect | all |
| `--format, -f` | Output format: json, text, table | text |
| `--verbose, -v` | Include detailed output | false |
| `--request-rate` | Simulated request rate (requests/min) | - |
| `--session-requests` | Simulated session request count | - |
| `--automated` | Mark request as appearing automated | false |

### Exit Codes

- `0` - No abuse detected (or successful non-detection command)
- `1` - Abuse detected (or error occurred)

## Invocation Sources

This agent MAY be invoked by:

- LLM-Edge-Agent (input/output inspection)
- Core Bundles (pre-processing, post-processing)
- agentics-cli (testing, inspection)
- CI/CD pipelines (security testing)

This agent MUST NOT invoke other agents.

## Explicit Non-Responsibilities

1. **No Enforcement**: This agent does not block, allow, or modify content
2. **No Orchestration**: This agent does not coordinate with other agents
3. **No Retries**: This agent does not retry failed operations
4. **No Alerts**: This agent does not trigger alerts or incidents
5. **No Policy Modification**: This agent does not modify detection policies
6. **No Database Access**: This agent only communicates with ruvector-service
7. **No Caching**: This agent does not cache results across invocations

## Failure Modes

| Error Code | Cause | Response |
|------------|-------|----------|
| `INVALID_INPUT` | Input validation failed | Return error with validation details |
| `VALIDATION_FAILED` | Schema validation failed | Return error with schema errors |
| `TIMEOUT` | Operation exceeded timeout | Return error, no partial results |
| `INTERNAL_ERROR` | Unexpected error in detection | Return error with message |
| `CONFIGURATION_ERROR` | Invalid configuration | Return error with config details |
| `PERSISTENCE_ERROR` | Failed to persist to ruvector-service | Log error, return result anyway |

## Versioning Rules

- **Major version** (1.x.x → 2.x.x): Breaking changes to input/output schema
- **Minor version** (1.0.x → 1.1.x): New detection patterns, categories, or features
- **Patch version** (1.0.0 → 1.0.1): Bug fixes, pattern tuning, performance improvements

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUVECTOR_ENDPOINT` | ruvector-service URL | `http://localhost:8080` |
| `RUVECTOR_API_KEY` | API authentication key | - |
| `RUVECTOR_TIMEOUT` | Request timeout (ms) | `5000` |
| `TELEMETRY_ENABLED` | Enable telemetry emission | `true` |
| `TELEMETRY_ENDPOINT` | Telemetry service URL | - |
| `TELEMETRY_API_KEY` | Telemetry API key | - |

## Deployment

This agent is deployed as a Google Cloud Edge Function as part of the LLM-Shield unified service.

### Entry Point

```typescript
// Edge Function export
export default {
  async fetch(request: Request): Promise<Response>
}
```

### Deployment Steps

1. Build: `npm run build`
2. Upload `dist/handler.js` to Google Cloud Functions
3. Set entry point to `fetch`
4. Configure environment variables
5. Deploy as part of LLM-Shield service
