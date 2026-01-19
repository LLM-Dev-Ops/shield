# Secrets Leakage Detection Agent Contract

## Agent Identity

| Property | Value |
|----------|-------|
| **Agent ID** | `secrets-leakage-detection-agent` |
| **Version** | `1.0.0` |
| **Classification** | `DETECTION_ONLY` |
| **Decision Type** | `secret_detection` |

## Purpose Statement

Detects exposure of API keys, tokens, credentials, private keys, passwords, and other sensitive secrets in model inputs or outputs. This agent analyzes content using pattern matching and entropy-based detection to identify potential credential leaks with confidence scoring.

**This agent does NOT:**
- Modify, sanitize, or redact content
- Block or allow content (enforcement decisions)
- Orchestrate workflows
- Trigger retries or escalations
- Modify policies or thresholds
- Connect directly to databases
- Store raw secrets or matched content

## Classification: DETECTION-ONLY

This agent:
- Inspects prompts, model outputs, and tool calls
- Detects secret patterns using regex and entropy analysis
- Calculates confidence scores
- Emits DecisionEvents to ruvector-service
- Does NOT modify content
- Does NOT enforce decisions
- Does NOT persist raw secrets

## Input Schema

**Reference:** `@llm-shield/agentics-contracts.SecretsLeakageDetectionInput`

```typescript
interface SecretsLeakageDetectionInput {
  // Content to analyze (REQUIRED)
  content: string;

  // Invocation context (REQUIRED)
  context: {
    execution_ref: string;      // UUID for tracing
    timestamp: string;          // UTC ISO 8601
    content_source: 'user_input' | 'model_output' | 'tool_call' | 'system';
    caller_id?: string;
    session_id?: string;
    policies?: PolicyReference[];
    metadata?: Record<string, unknown>;
  };

  // Detection sensitivity (0.0 - 1.0, default: 0.5)
  sensitivity?: number;

  // Categories of secrets to detect (optional, defaults to all)
  detect_categories?: Array<
    | 'aws_credentials'
    | 'github_token'
    | 'stripe_key'
    | 'openai_key'
    | 'anthropic_key'
    | 'slack_token'
    | 'google_api_key'
    | 'private_key'
    | 'jwt_token'
    | 'database_url'
    | 'generic_api_key'
    | 'generic_secret'
    | 'password'
    | 'connection_string'
  >;

  // Enable entropy-based detection (default: true)
  entropy_detection?: boolean;

  // Entropy threshold for generic detection (0.0 - 8.0, default: 4.5)
  entropy_threshold?: number;

  // Custom patterns (pattern_id -> regex string)
  custom_patterns?: Record<string, string>;
}
```

## Output Schema

**Reference:** `@llm-shield/agentics-contracts.AgentOutput`

```typescript
interface AgentOutput {
  agent: {
    agent_id: 'secrets-leakage-detection-agent';
    agent_version: '1.0.0';
    classification: 'DETECTION_ONLY';
    decision_type: 'secret_detection';
  };

  result: {
    threats_detected: boolean;
    risk_score: number;           // 0.0 - 1.0
    severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
    confidence: number;           // 0.0 - 1.0
    entities: DetectedSecretEntity[];   // Detected secrets
    risk_factors: RiskFactor[];   // Contributing factors
    pattern_match_count: number;
    detected_categories: string[];
  };

  duration_ms: number;
  cached: boolean;
}

interface DetectedSecretEntity {
  entity_type: string;
  category: string;
  start: number;
  end: number;
  confidence: number;
  pattern_id?: string;
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  secret_type: SecretTypeCategory;
  entropy_based: boolean;
  entropy_value?: number;
  redacted_preview?: string;  // e.g., "AKIA****1234"
}
```

## DecisionEvent Mapping

**Reference:** `@llm-shield/agentics-contracts.DecisionEvent`

Every invocation emits exactly ONE DecisionEvent to ruvector-service:

```typescript
interface DecisionEvent {
  agent_id: 'secrets-leakage-detection-agent';
  agent_version: '1.0.0';
  decision_type: 'secret_detection';

  // SHA-256 hash of content (NOT raw content)
  inputs_hash: string;

  // Sanitized outputs (no raw content, no matched secrets)
  outputs: {
    threats_detected: boolean;
    risk_score: number;
    severity: string;
    confidence: number;
    pattern_match_count: number;
    detected_categories: string[];
    entity_count: number;
  };

  confidence: number;
  constraints_applied: PolicyReference[];
  execution_ref: string;
  timestamp: string;
  duration_ms: number;

  telemetry: {
    content_length: number;
    content_source: string;
    session_id?: string;
    caller_id?: string;
  };
}
```

### Data Persistence Rules

**PERSISTED to ruvector-service:**
- Input content hash (SHA-256)
- Detection metadata
- Risk scores and confidence
- Pattern match counts
- Category classifications (types of secrets found)
- Execution timing
- Entity counts

**NEVER PERSISTED:**
- Raw input content
- Matched secret values
- Actual API keys, tokens, or credentials
- Redacted previews with partial values
- Private key contents
- Database connection strings
- Passwords

## CLI Contract

### Test Mode
Validates agent functionality with sample input:
```bash
shield-agent secrets-leakage-detection test \
  --content "My API key is sk-1234567890abcdef" \
  --format json
```

### Simulate Mode
Runs detection with custom configuration:
```bash
shield-agent secrets-leakage-detection simulate \
  --content "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
  --sensitivity 0.8 \
  --categories aws_credentials,generic_secret \
  --entropy-detection true
```

### Inspect Mode
Retrieves detection result by execution reference:
```bash
shield-agent secrets-leakage-detection inspect \
  --execution-ref <uuid> \
  --verbose
```

## Detection Categories

| Category | Description | Example Patterns |
|----------|-------------|------------------|
| `aws_credentials` | AWS access keys and secrets | `AKIA...`, `aws_secret_access_key=...` |
| `github_token` | GitHub personal/OAuth/app tokens | `ghp_...`, `gho_...`, `github_pat_...` |
| `stripe_key` | Stripe API keys | `sk_live_...`, `sk_test_...`, `rk_live_...` |
| `openai_key` | OpenAI API keys | `sk-...` (48 chars) |
| `anthropic_key` | Anthropic API keys | `sk-ant-...` |
| `slack_token` | Slack tokens and webhooks | `xox[baprs]-...`, Slack webhook URLs |
| `google_api_key` | Google Cloud API keys | `AIza...` |
| `private_key` | RSA/EC/PGP private keys | `-----BEGIN PRIVATE KEY-----` |
| `jwt_token` | JSON Web Tokens | `eyJ...` (Base64 encoded) |
| `database_url` | Database connection strings | `postgres://...`, `mongodb://...` |
| `generic_api_key` | Generic API key patterns | `api_key=...`, `apiKey:...` |
| `generic_secret` | Generic secret patterns | `secret=...`, `SECRET_KEY=...` |
| `password` | Exposed passwords | `password=...`, `passwd:...` |
| `connection_string` | Connection strings | `Server=...;Password=...` |

## Confidence Semantics

Confidence scores are **heuristic-based** (not probabilistic):

| Score Range | Interpretation |
|-------------|----------------|
| 0.0 - 0.3 | Low confidence - possible false positive or generic match |
| 0.3 - 0.6 | Medium confidence - likely credential exposure |
| 0.6 - 0.8 | High confidence - strong secret indicators |
| 0.8 - 1.0 | Very high confidence - definite credential leak |

Factors affecting confidence:
- Pattern specificity (vendor-specific vs generic)
- Entropy score (higher entropy = higher confidence for generic secrets)
- Pattern severity weights
- Context indicators (key/value assignments)

## Entropy-Based Detection

For secrets that don't match vendor-specific patterns, entropy analysis identifies high-randomness strings:

| Entropy Value | Interpretation |
|---------------|----------------|
| < 3.0 | Low entropy - unlikely to be a secret |
| 3.0 - 4.0 | Medium entropy - possible but uncertain |
| 4.0 - 5.5 | High entropy - likely random/generated |
| > 5.5 | Very high entropy - almost certainly random |

Default threshold: 4.5 (configurable via `entropy_threshold`)

## Severity Mapping

| Secret Type | Default Severity |
|-------------|------------------|
| Private keys | `critical` |
| AWS credentials | `critical` |
| Database URLs with passwords | `critical` |
| Production API keys (live) | `critical` |
| GitHub tokens | `high` |
| OpenAI/Anthropic keys | `high` |
| Slack tokens | `high` |
| Passwords | `high` |
| Test API keys | `medium` |
| Generic secrets | `medium` |
| JWT tokens | `high` |
| Publishable keys | `low` |

## Constraints Applied (Policy References)

When policies are provided in context:
- Policy IDs are recorded in `constraints_applied`
- No policy logic is executed (consumer-only)
- Policy rules may specify detection thresholds
- Policy may whitelist specific pattern IDs

## Invocation Sources

This agent MAY be invoked by:
- LLM-Edge-Agent bundles
- LLM-Core bundles
- Direct CLI invocation
- Test harnesses

This agent MUST NEVER:
- Invoke other agents
- Trigger external services (except ruvector-service)
- Modify calling context
- Store raw secret values

## Failure Modes

| Error Code | Description | Response |
|------------|-------------|----------|
| `INVALID_INPUT` | Input validation failed | Return AgentError with validation details |
| `VALIDATION_FAILED` | Schema validation error | Return AgentError with schema path |
| `TIMEOUT` | Detection exceeded timeout | Return partial results if available |
| `INTERNAL_ERROR` | Unexpected error | Return AgentError, emit telemetry |
| `CONFIGURATION_ERROR` | Invalid custom patterns | Return AgentError with pattern ID |
| `PERSISTENCE_ERROR` | ruvector-service unavailable | Complete detection, mark event failed |

## Non-Responsibilities

This agent explicitly MUST NOT:

1. **Orchestrate workflows** - No task scheduling, no agent spawning
2. **Perform retries** - Single invocation, single response
3. **Trigger alerts** - Detection only, no notifications
4. **Modify policies** - Consumer of policies, not producer
5. **Escalate incidents** - Report findings only
6. **Block content** - Detection classification only
7. **Connect to SQL** - All persistence via ruvector-service client
8. **Store raw secrets** - Only hashes, counts, and categories
9. **Redact content** - Detection only, no modification

## Versioning Rules

- **Major version**: Breaking schema changes, pattern format changes
- **Minor version**: New secret type categories, new detection patterns
- **Patch version**: Pattern refinements, threshold adjustments, bug fixes

Version is embedded in:
- Agent identity
- DecisionEvent
- Error responses
- Telemetry emissions

## Platform Registration

Registered in:
- `@llm-shield/agentics-contracts` (schema definitions)
- LLM-Shield unified GCP service (Edge Function endpoint)
- `agentics-cli` (test/simulate/inspect commands)

## Smoke Test Commands

```bash
# Basic functionality test
shield-agent secrets-leakage-detection test \
  --content "AKIAIOSFODNN7EXAMPLE" \
  --format json

# Expected: threats_detected=true, category=aws_credentials, severity=critical

# Entropy detection test
shield-agent secrets-leakage-detection test \
  --content "token=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6" \
  --entropy-detection true \
  --format json

# Expected: threats_detected=true, category=generic_secret

# No secrets test
shield-agent secrets-leakage-detection test \
  --content "Hello, this is a normal message without secrets" \
  --format json

# Expected: threats_detected=false, entity_count=0
```

## Integration Verification Checklist

- [ ] Agent imports schemas from `@llm-shield/agentics-contracts`
- [ ] Input validated against `SecretsLeakageDetectionInput`
- [ ] Output validated against `AgentOutput`
- [ ] DecisionEvent emitted to ruvector-service
- [ ] No raw secrets in persisted data
- [ ] Telemetry compatible with LLM-Observatory
- [ ] CLI commands functional (test/simulate/inspect)
- [ ] Deployable as Google Edge Function
- [ ] Deterministic, stateless execution
- [ ] No orchestration, retry, or alert logic
