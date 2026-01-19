# Content Moderation Agent Contract Specification

## Agent Identity

| Property | Value |
|----------|-------|
| **Agent ID** | `content-moderation-agent` |
| **Version** | `1.0.0` |
| **Classification** | `ENFORCEMENT` |
| **Decision Type** | `content_moderation` |

## Purpose Statement

The Content Moderation Agent applies moderation policies to classify or block disallowed content categories. It evaluates text content against a comprehensive set of moderation patterns and makes enforcement decisions (ALLOW, BLOCK, FLAG, WARN, AGE_GATE) based on detected violations, policy rules, and user context.

## Classification: ENFORCEMENT-CLASS

This agent is classified as **ENFORCEMENT-CLASS**, meaning it:
- Makes binding enforcement decisions
- Returns action recommendations (ALLOW/BLOCK/FLAG/WARN/AGE_GATE)
- Evaluates content against moderation policies
- Emits DecisionEvents for audit and compliance

## Input Schema

**Reference:** `@llm-shield/agentics-contracts#ContentModerationAgentInput`

```typescript
interface ContentModerationAgentInput {
  // Required
  content: string;                           // Content to analyze
  context: InvocationContext;                // Execution context

  // Optional
  sensitivity?: number;                      // 0.0-1.0, default 0.7
  moderate_categories?: ContentModerationCategory[];  // Categories to check
  default_action?: ModerationAction;         // Default action, default 'BLOCK'
  moderation_rules?: ContentModerationRule[]; // Custom rules
  user_age_verified?: boolean;               // Age verification status
  min_moderation_confidence?: number;        // Confidence threshold
  content_type?: ContentType;                // Content type hint
  include_violation_details?: boolean;       // Include violation details
}
```

## Output Schema

**Reference:** `@llm-shield/agentics-contracts#ContentModerationAgentOutput`

```typescript
interface ContentModerationAgentOutput {
  agent: AgentIdentity;
  result: ContentModerationResult;
  duration_ms: number;
  cached: boolean;
}

interface ContentModerationResult {
  allowed: boolean;                          // Whether content is allowed
  action: ModerationAction;                  // Action taken
  violations_detected: boolean;              // Whether violations found
  risk_score: number;                        // 0.0-1.0
  severity: Severity;                        // none/low/medium/high/critical
  confidence: number;                        // Detection confidence
  violations: ContentModerationViolation[];  // Violation details
  violated_categories: ContentModerationCategory[];
  pattern_match_count: number;
  category_counts: Record<string, number>;
  decision_reason: string;
  risk_factors: RiskFactor[];
  requires_human_review: boolean;
  content_warning?: string;                  // Warning message if applicable
}
```

## DecisionEvent Mapping

**Reference:** `@llm-shield/agentics-contracts#ContentModerationDecisionEvent`

| Field | Source | Notes |
|-------|--------|-------|
| `agent_id` | Constant | `"content-moderation-agent"` |
| `agent_version` | Constant | `"1.0.0"` |
| `decision_type` | Constant | `"content_moderation"` |
| `inputs_hash` | SHA-256(content) | Raw content NEVER stored |
| `outputs` | Result object | Sanitized moderation results |
| `confidence` | Calculated | Overall detection confidence |
| `constraints_applied` | Input policies | Policy references |
| `execution_ref` | Input context | UUID for tracing |
| `timestamp` | Input context | UTC ISO 8601 |
| `duration_ms` | Measured | Execution time |
| `telemetry` | Metadata | No PII, no content |

### Data NEVER Persisted
- Raw input content
- Matched text fragments
- User identifiable information
- Actual content that triggered violations

## CLI Contract

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/moderate` | POST | Execute content moderation |
| `/cli` | POST | CLI invocation (test/simulate/inspect) |
| `/health` | GET | Health check |
| `/info` | GET | Agent information |

### CLI Modes

#### Test Mode
Execute moderation on content with full persistence.

```bash
content-moderation test \
  --content "Content to moderate" \
  --sensitivity 0.7 \
  --format json
```

#### Simulate Mode
Execute moderation without persistence (dry run).

```bash
content-moderation simulate \
  --content "Content to moderate" \
  --verbose \
  --format text
```

#### Inspect Mode
Return agent configuration and pattern information.

```bash
content-moderation inspect \
  --content "" \
  --format json
```

## Moderation Categories

| Category | Severity | Critical | Age-Restricted |
|----------|----------|----------|----------------|
| `child_safety` | critical | Yes | No |
| `terrorism_extremism` | critical | Yes | No |
| `hate_discriminatory` | critical | Yes | No |
| `self_harm` | critical | Yes | No |
| `illegal_regulated` | critical | Yes | No |
| `violence_graphic` | high | No | Yes |
| `harassment_bullying` | high | No | No |
| `adult_content` | medium | No | Yes |
| `spam_misleading` | low | No | No |
| `misinformation` | medium | No | No |

## Moderation Actions

| Action | Allowed | Description |
|--------|---------|-------------|
| `ALLOW` | Yes | Content is safe |
| `WARN` | Yes | Content allowed with warning |
| `FLAG` | Yes | Content allowed, flagged for review |
| `AGE_GATE` | No | Requires age verification |
| `BLOCK` | No | Content blocked |

## Core Bundles That May Invoke This Agent

- **LLM-Edge-Agent**: For real-time content moderation
- **Core Input Validator**: For input content screening
- **Core Output Validator**: For output content screening
- **Safety Boundary Agent**: For combined safety enforcement

## Explicit Non-Responsibilities

This agent MUST NOT:

1. **Modify content** - Enforcement only, no redaction
2. **Orchestrate workflows** - No workflow management
3. **Retry operations** - No automatic retry logic
4. **Connect to databases** - No direct SQL access
5. **Trigger alerts** - No incident/alert management
6. **Modify policies** - No runtime policy changes
7. **Store raw content** - Only hashes persisted
8. **Execute external calls** - Beyond ruvector-service
9. **Make network requests** - Except to allowed services
10. **Access filesystem** - Stateless execution only

## Failure Modes

| Error Code | Condition | Response |
|------------|-----------|----------|
| `INVALID_INPUT` | Malformed input | 400 with validation errors |
| `VALIDATION_FAILED` | Schema validation fails | 400 with error details |
| `TIMEOUT` | Operation exceeds timeout | 504 with timeout info |
| `INTERNAL_ERROR` | Unexpected error | 500 with sanitized message |
| `PERSISTENCE_ERROR` | ruvector-service failure | Agent completes, logs error |

## Confidence Semantics

- **0.0-0.3**: Low confidence, may be false positive
- **0.3-0.6**: Moderate confidence, consider context
- **0.6-0.8**: High confidence, likely valid detection
- **0.8-1.0**: Very high confidence, strong match

Confidence is adjusted by:
- Sensitivity setting (higher = more aggressive)
- Pattern base confidence
- Number of matching patterns
- Match specificity

## Severity Mapping

| Score | Severity | Action Threshold |
|-------|----------|------------------|
| 0.9+ | critical | Immediate block |
| 0.7-0.9 | high | Block by default |
| 0.4-0.7 | medium | Flag for review |
| 0.1-0.4 | low | Allow with audit |
| 0.0-0.1 | none | Allow |

## Versioning Rules

1. **Major version**: Breaking changes to input/output schemas
2. **Minor version**: New categories, patterns, or features
3. **Patch version**: Bug fixes, pattern updates

Version string format: `MAJOR.MINOR.PATCH` (e.g., `1.0.0`)

## Performance Targets

| Metric | Target |
|--------|--------|
| Latency (p50) | < 10ms |
| Latency (p99) | < 50ms |
| Throughput | > 1000 req/s |
| Memory | < 128MB |
