# Toxicity Detection Agent Contract

## Agent Identity

| Property | Value |
|----------|-------|
| **Agent ID** | `toxicity-detection-agent` |
| **Version** | `1.0.0` |
| **Classification** | `DETECTION_ONLY` |
| **Decision Type** | `toxicity_detection` |

## Purpose Statement

Detects abusive, hateful, or toxic language in model outputs, prompts, and tool payloads. This agent analyzes text using pattern matching and confidence scoring to identify toxic content across multiple categories including general toxicity, severe toxicity, obscene language, threats, insults, and identity-based hate speech.

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
- ✅ Detects toxicity patterns
- ✅ Classifies toxicity by category
- ✅ Calculates confidence scores
- ✅ Emits DecisionEvents
- ❌ Does NOT modify content
- ❌ Does NOT redact toxic content
- ❌ Does NOT enforce decisions

## Input Schema

**Reference:** `@llm-shield/agentics-contracts.ToxicityDetectionInput`

```typescript
interface ToxicityDetectionInput {
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

  // Toxicity threshold (0.0 - 1.0, default: 0.7)
  threshold?: number;

  // Categories to detect (optional, defaults to all)
  detect_categories?: Array<
    | 'toxic'
    | 'severe_toxic'
    | 'obscene'
    | 'threat'
    | 'insult'
    | 'identity_hate'
  >;
}
```

## Output Schema

**Reference:** `@llm-shield/agentics-contracts.ToxicityDetectionAgentOutput`

```typescript
interface ToxicityDetectionAgentOutput {
  agent: {
    agent_id: 'toxicity-detection-agent';
    agent_version: '1.0.0';
    classification: 'DETECTION_ONLY';
    decision_type: 'toxicity_detection';
  };

  result: {
    toxicity_detected: boolean;
    risk_score: number;           // 0.0 - 1.0
    severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
    confidence: number;           // 0.0 - 1.0
    entities: ToxicityDetectedEntity[];   // Detected toxicity (NO raw values)
    risk_factors: RiskFactor[];   // Contributing factors
    pattern_match_count: number;
    detected_categories: string[];
  };

  duration_ms: number;
  cached: boolean;
}
```

## DecisionEvent Mapping

**Reference:** `@llm-shield/agentics-contracts.ToxicityDetectionDecisionEvent`

Every invocation emits exactly ONE DecisionEvent to ruvector-service:

```typescript
interface ToxicityDetectionDecisionEvent {
  agent_id: 'toxicity-detection-agent';
  agent_version: '1.0.0';
  decision_type: 'toxicity_detection';

  // SHA-256 hash of content (NOT raw content)
  inputs_hash: string;

  // Sanitized outputs (no raw content)
  outputs: {
    toxicity_detected: boolean;
    risk_score: number;
    severity: string;
    confidence: number;
    pattern_match_count: number;
    detected_categories: string[];
    entity_count: number;
    category_counts: Record<string, number>;
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
    threshold_used?: number;
    categories_checked?: string[];
  };
}
```

### Data Persistence Rules

**PERSISTED to ruvector-service:**
- Input content hash (SHA-256)
- Detection metadata
- Risk scores and confidence
- Pattern match counts
- Toxicity category classifications
- Execution timing

**NEVER PERSISTED:**
- Raw input content
- Actual toxic text excerpts
- Matched phrases
- System prompts
- API keys or secrets
- Exact entity positions (only counts)

## CLI Contract

### Test Mode
```bash
shield-agent toxicity-detection test \
  --content "You are an idiot" \
  --format json
```

### Simulate Mode
```bash
shield-agent toxicity-detection simulate \
  --content "I hate you and will hurt you" \
  --sensitivity 0.8 \
  --threshold 0.6 \
  --categories threat,insult
```

### Inspect Mode
```bash
shield-agent toxicity-detection inspect \
  --execution-ref <uuid> \
  --verbose
```

## Detection Categories

| Category | Description | Example Patterns | Severity |
|----------|-------------|------------------|----------|
| `toxic` | General toxic language | Multiple toxic indicators | medium |
| `severe_toxic` | Strong profanity, slurs | Severe profanity, extreme language | critical |
| `obscene` | Obscene/vulgar language | Sexual references, crude language | high |
| `threat` | Threatening language | "kill you", "hurt you", violence | critical |
| `insult` | Insulting language | "idiot", "stupid", "moron" | medium |
| `identity_hate` | Identity-based hate | Racist, sexist, bigoted language | critical |

## Confidence Semantics

Confidence scores are **pattern and context-based**:

| Score Range | Interpretation |
|-------------|----------------|
| 0.0 - 0.3 | Low confidence - weak pattern match |
| 0.3 - 0.6 | Medium confidence - moderate indicators |
| 0.6 - 0.8 | High confidence - strong indicators |
| 0.8 - 1.0 | Very high confidence - clear toxic content |

Per-category baseline confidence:
- `severe_toxic`: 0.95
- `threat`: 0.90
- `identity_hate`: 0.85
- `insult`: 0.75
- `obscene`: 0.80
- `toxic` (general): 0.70

## Severity Calculation

Severity is determined by the highest-severity toxicity category detected:

| Category | Base Severity |
|----------|---------------|
| `severe_toxic` | critical |
| `threat` | critical |
| `identity_hate` | critical |
| `obscene` | high |
| `insult` | medium |
| `toxic` | medium |

## Constraints Applied (Policy References)

When policies are provided in context:
- Policy IDs are recorded in `constraints_applied`
- No policy logic is executed (consumer-only)
- Policy rules affect detection sensitivity if specified
- Threshold adjustments based on policy rules

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
- Return raw toxic content in output

## Failure Modes

| Error Code | Description | Response |
|------------|-------------|----------|
| `INVALID_INPUT` | Input validation failed | Return AgentError with details |
| `VALIDATION_FAILED` | Schema validation error | Return AgentError with path |
| `TIMEOUT` | Detection exceeded timeout | Return partial results if available |
| `INTERNAL_ERROR` | Unexpected error | Return AgentError, log to telemetry |
| `PERSISTENCE_ERROR` | ruvector-service unavailable | Complete detection, mark event failed |
| `CONFIGURATION_ERROR` | Invalid categories or threshold | Return AgentError with config details |

## Non-Responsibilities

This agent explicitly MUST NOT:

1. **Orchestrate workflows** - No task scheduling, no agent spawning
2. **Perform retries** - Single invocation, single response
3. **Trigger alerts** - Detection only, no notifications
4. **Modify policies** - Consumer of policies, not producer
5. **Escalate incidents** - Report findings only
6. **Block content** - Detection classification only
7. **Connect to SQL** - All persistence via ruvector-service client
8. **Store toxic content** - Only counts and categories
9. **Redact content** - DETECTION_ONLY classification
10. **Return raw toxic text** - Category counts without values

## Versioning Rules

- Major version: Breaking schema changes
- Minor version: New toxicity categories, new detection patterns
- Patch version: Bug fixes, threshold adjustments, pattern improvements

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
| Pattern count | 100+ patterns |
| False positive rate | < 3% |
| True positive rate | > 95% |
