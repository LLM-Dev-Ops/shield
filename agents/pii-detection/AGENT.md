# PII Detection Agent Contract

## Agent Identity

| Property | Value |
|----------|-------|
| **Agent ID** | `pii-detection-agent` |
| **Version** | `1.0.0` |
| **Classification** | `DETECTION_ONLY` |
| **Decision Type** | `pii_detection` |

## Purpose Statement

Detects Personally Identifiable Information (PII) within prompts, outputs, or tool payloads. This agent analyzes text using pattern matching and validation algorithms to identify PII entities including email addresses, phone numbers, Social Security Numbers, credit card numbers, IP addresses, passport numbers, and driver's license numbers with confidence scoring.

**This agent does NOT:**
- Modify, sanitize, or redact content
- Block or allow content (enforcement decisions)
- Orchestrate workflows
- Trigger retries or escalations
- Modify policies or thresholds
- Connect directly to databases

## Classification: DETECTION-ONLY

This agent:
- ✅ Inspects prompts, outputs, and tool calls
- ✅ Detects PII patterns
- ✅ Validates potential matches (Luhn check, SSN area validation)
- ✅ Calculates confidence scores
- ✅ Emits DecisionEvents
- ❌ Does NOT modify content
- ❌ Does NOT redact PII
- ❌ Does NOT enforce decisions

## Input Schema

**Reference:** `@llm-shield/agentics-contracts.PIIDetectionInput`

```typescript
interface PIIDetectionInput {
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

  // PII types to detect (optional, defaults to all)
  detect_types?: Array<
    | 'email'
    | 'phone'
    | 'ssn'
    | 'credit_card'
    | 'ip_address'
    | 'passport'
    | 'drivers_license'
    | 'date_of_birth'
    | 'address'
    | 'name'
  >;

  // Country-specific formats (optional)
  countries?: Array<'US' | 'UK' | 'CA' | 'AU' | 'EU'>;
}
```

## Output Schema

**Reference:** `@llm-shield/agentics-contracts.AgentOutput`

```typescript
interface AgentOutput {
  agent: {
    agent_id: 'pii-detection-agent';
    agent_version: '1.0.0';
    classification: 'DETECTION_ONLY';
    decision_type: 'pii_detection';
  };

  result: {
    threats_detected: boolean;
    risk_score: number;           // 0.0 - 1.0
    severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
    confidence: number;           // 0.0 - 1.0
    entities: DetectedEntity[];   // Detected PII (positions only, NO raw values)
    risk_factors: RiskFactor[];   // Contributing factors
    pattern_match_count: number;
    detected_categories: string[];
  };

  duration_ms: number;
  cached: boolean;
}
```

## DecisionEvent Mapping

**Reference:** `@llm-shield/agentics-contracts.DecisionEvent`

Every invocation emits exactly ONE DecisionEvent to ruvector-service:

```typescript
interface DecisionEvent {
  agent_id: 'pii-detection-agent';
  agent_version: '1.0.0';
  decision_type: 'pii_detection';

  // SHA-256 hash of content (NOT raw content)
  inputs_hash: string;

  // Sanitized outputs (no raw content, no PII values)
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
- PII type classifications (e.g., "email", "ssn")
- Execution timing

**NEVER PERSISTED:**
- Raw input content
- Actual PII values (email addresses, SSNs, credit card numbers, etc.)
- Matched text excerpts
- System prompts
- API keys or secrets
- Exact entity positions (only counts)

## CLI Contract

### Test Mode
```bash
shield-agent pii-detection test \
  --content "Contact me at john@example.com" \
  --format json
```

### Simulate Mode
```bash
shield-agent pii-detection simulate \
  --content "SSN: 123-45-6789, Card: 4111111111111111" \
  --sensitivity 0.8 \
  --types email,ssn,credit_card
```

### Inspect Mode
```bash
shield-agent pii-detection inspect \
  --execution-ref <uuid> \
  --verbose
```

## Detection Categories

| Category | Description | Example Patterns | Severity |
|----------|-------------|------------------|----------|
| `email` | Email addresses | RFC 5322 compliant patterns | medium |
| `phone` | Phone numbers (US, UK, International) | +1-xxx-xxx-xxxx, +44 xxxx xxxxxx | medium |
| `ssn` | US Social Security Numbers | xxx-xx-xxxx (with area validation) | critical |
| `credit_card` | Credit card numbers | Visa, Mastercard, Amex, Discover (Luhn validated) | critical |
| `ip_address` | IPv4 and IPv6 addresses | 192.168.x.x, fe80::1 | low |
| `passport` | Passport numbers | US format: X12345678 | high |
| `drivers_license` | Driver's license numbers | State-specific formats | high |
| `date_of_birth` | Birth dates | MM/DD/YYYY, YYYY-MM-DD | medium |
| `address` | Physical addresses | Street, city, state, zip patterns | medium |
| `name` | Personal names | NER-based detection | low |

## Confidence Semantics

Confidence scores are **validation-based**:

| Score Range | Interpretation |
|-------------|----------------|
| 0.0 - 0.3 | Low confidence - pattern match only, no validation |
| 0.3 - 0.6 | Medium confidence - pattern match with basic validation |
| 0.6 - 0.8 | High confidence - pattern match with strong validation |
| 0.8 - 1.0 | Very high confidence - validated match (Luhn check passed, etc.) |

Per-type baseline confidence:
- `credit_card` (Luhn validated): 0.99
- `email`: 0.95
- `ssn` (area validated): 0.90
- `phone`: 0.75
- `ip_address`: 0.85
- `passport`: 0.80
- `drivers_license`: 0.75

## Validation Methods

| PII Type | Validation Method |
|----------|-------------------|
| `credit_card` | Luhn algorithm (mod 10 checksum) |
| `ssn` | Area number validation (not 000, 666, or 9xx) |
| `email` | Basic RFC validation (@ and domain present) |
| `phone` | Country-specific format validation |
| `ip_address` | IPv4/IPv6 range validation |

## Severity Calculation

Severity is determined by the highest-severity PII type detected:

| PII Type | Base Severity |
|----------|---------------|
| `ssn` | critical |
| `credit_card` | critical |
| `passport` | high |
| `drivers_license` | high |
| `date_of_birth` | medium |
| `email` | medium |
| `phone` | medium |
| `address` | medium |
| `ip_address` | low |
| `name` | low |

## Constraints Applied (Policy References)

When policies are provided in context:
- Policy IDs are recorded in `constraints_applied`
- No policy logic is executed (consumer-only)
- Policy rules affect detection sensitivity if specified
- Country-specific formats are applied based on policy

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
- Return raw PII values in output

## Failure Modes

| Error Code | Description | Response |
|------------|-------------|----------|
| `INVALID_INPUT` | Input validation failed | Return AgentError with details |
| `VALIDATION_FAILED` | Schema validation error | Return AgentError with path |
| `TIMEOUT` | Detection exceeded timeout | Return partial results if available |
| `INTERNAL_ERROR` | Unexpected error | Return AgentError, log to telemetry |
| `PERSISTENCE_ERROR` | ruvector-service unavailable | Complete detection, mark event failed |
| `CONFIGURATION_ERROR` | Invalid PII types or countries | Return AgentError with config details |

## Non-Responsibilities

This agent explicitly MUST NOT:

1. **Orchestrate workflows** - No task scheduling, no agent spawning
2. **Perform retries** - Single invocation, single response
3. **Trigger alerts** - Detection only, no notifications
4. **Modify policies** - Consumer of policies, not producer
5. **Escalate incidents** - Report findings only
6. **Block content** - Detection classification only
7. **Connect to SQL** - All persistence via ruvector-service client
8. **Store PII values** - Only counts and categories
9. **Redact content** - DETECTION_ONLY classification
10. **Return raw PII** - Entity positions without values

## Versioning Rules

- Major version: Breaking schema changes
- Minor version: New PII types, new country formats
- Patch version: Bug fixes, validation improvements, threshold adjustments

Version is embedded in:
- Agent identity
- DecisionEvent
- Error responses
- Telemetry emissions

## Performance Characteristics

| Metric | Target |
|--------|--------|
| Latency p50 | < 5ms |
| Latency p99 | < 20ms |
| Memory usage | < 50MB |
| Pattern count | 40+ patterns |
| False positive rate | < 2% |
| True positive rate | > 98% |
