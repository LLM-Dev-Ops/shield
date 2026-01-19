# Safety Boundary Agent Contract Specification

## Agent Identity

| Field | Value |
|-------|-------|
| **Agent ID** | `safety-boundary-agent` |
| **Version** | `1.0.0` |
| **Classification** | `ENFORCEMENT` |
| **Decision Type** | `safety_boundary_enforcement` |

## Purpose Statement

Enforce safety boundaries by evaluating content against configurable safety policies and making ALLOW/BLOCK enforcement decisions. This agent inspects content for policy violations and returns deterministic enforcement outcomes based on provided policy inputs at invocation time.

## Classification

- **ENFORCEMENT-CLASS** (ALLOW / BLOCK)
- This agent **makes enforcement decisions** on content
- This agent **does NOT modify content** (unlike REDACTION class)
- This agent **does NOT orchestrate workflows**

## Input Schema Reference

**Schema**: `SafetyBoundaryAgentInput` from `@llm-shield/agentics-contracts`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `content` | `string` | Yes | - | Content to evaluate |
| `context` | `InvocationContext` | Yes | - | Execution context |
| `sensitivity` | `number` (0-1) | No | `0.7` | Enforcement strictness |
| `enforce_categories` | `SafetyBoundaryCategory[]` | No | All | Categories to check |
| `default_action` | `EnforcementAction` | No | `BLOCK` | Action on violation |
| `policy_rules` | `SafetyPolicyRule[]` | No | - | Custom policy rules |
| `min_enforcement_confidence` | `number` (0-1) | No | `0.8` | Minimum confidence for action |

## Output Schema Reference

**Schema**: `SafetyBoundaryAgentOutput` from `@llm-shield/agentics-contracts`

| Field | Type | Description |
|-------|------|-------------|
| `agent` | `AgentIdentity` | Agent identification |
| `result` | `SafetyBoundaryResult` | Enforcement result |
| `duration_ms` | `number` | Execution time |
| `cached` | `boolean` | Whether cached |

### SafetyBoundaryResult Fields

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | `boolean` | Whether content is allowed |
| `action` | `EnforcementAction` | Action taken (ALLOW/BLOCK) |
| `violations_detected` | `boolean` | Whether violations found |
| `risk_score` | `number` (0-1) | Overall risk score |
| `severity` | `Severity` | Highest severity level |
| `confidence` | `number` (0-1) | Detection confidence |
| `violations` | `SafetyBoundaryViolation[]` | Detected violations |
| `violated_categories` | `SafetyBoundaryCategory[]` | Categories violated |
| `pattern_match_count` | `number` | Number of patterns matched |
| `category_counts` | `Record<string, number>` | Count by category |
| `decision_reason` | `string` | Human-readable reason |
| `risk_factors` | `RiskFactor[]` | Contributing factors |

## DecisionEvent Mapping

**Schema**: `SafetyBoundaryDecisionEvent`

| Field | Mapping |
|-------|---------|
| `agent_id` | `'safety-boundary-agent'` |
| `agent_version` | `'1.0.0'` |
| `decision_type` | `'safety_boundary_enforcement'` |
| `inputs_hash` | SHA-256 of input content |
| `outputs` | Sanitized result (no raw content) |
| `confidence` | Overall confidence |
| `constraints_applied` | Policy references from context |
| `execution_ref` | From invocation context |
| `timestamp` | UTC ISO 8601 |
| `duration_ms` | Execution duration |
| `telemetry` | Metadata (no PII) |

### What IS Persisted

- Enforcement decision (allowed/blocked)
- Action taken
- Risk score and severity
- Violation counts by category
- Pattern match counts
- Decision reason
- Content length (not content)
- Execution metadata

### What is NOT Persisted

- Raw input content
- Actual text that violated boundaries
- PII or sensitive data
- Secrets or credentials
- Position details in content

## CLI Contract

### Modes

| Mode | Description | Persists |
|------|-------------|----------|
| `test` | Full execution with persistence | Yes |
| `simulate` | Full execution without persistence | No |
| `inspect` | Return agent metadata | No |

### CLI Invocation

```bash
# Test mode - with persistence
curl -X POST http://localhost:8080/cli \
  -H "Content-Type: application/json" \
  -d '{"mode": "test", "content": "...", "config": {"sensitivity": 0.8}}'

# Simulate mode - without persistence
curl -X POST http://localhost:8080/cli \
  -H "Content-Type: application/json" \
  -d '{"mode": "simulate", "content": "..."}'

# Inspect mode
curl -X POST http://localhost:8080/cli \
  -H "Content-Type: application/json" \
  -d '{"mode": "inspect", "content": ""}'
```

### Output Formats

- `json` (default): Full JSON output
- `text`: Human-readable text
- `table`: ASCII table format

## Detection/Enforcement Classification

This agent is **ENFORCEMENT-CLASS**:

1. **Detects** violations against safety boundaries
2. **Evaluates** content against policy rules
3. **Makes enforcement decision** (ALLOW/BLOCK)
4. **Returns deterministic outcome** based on policy

### Enforcement Flow

```
Input Content
     |
     v
Pattern Matching (detect violations)
     |
     v
Policy Evaluation (apply rules)
     |
     v
Confidence Threshold Check
     |
     v
Enforcement Decision (ALLOW/BLOCK)
     |
     v
DecisionEvent Emission
```

## Safety Categories

| Category | Description | Default Severity |
|----------|-------------|-----------------|
| `harmful_content` | General harmful content | `high` |
| `explicit_content` | Adult/explicit material | `medium` |
| `hate_speech` | Discriminatory content | `critical` |
| `violence` | Violent content | `high` |
| `self_harm` | Self-harm content | `critical` |
| `illegal_activity` | Illegal instructions | `critical` |
| `dangerous_instructions` | Dangerous how-tos | `high` |
| `deceptive_content` | Misinformation | `medium` |
| `privacy_violation` | Personal data exposure | `high` |
| `intellectual_property` | Copyright violation | `medium` |

## Explicit Non-Responsibilities

This agent **MUST NEVER**:

1. **Orchestrate workflows** - No triggering of other agents
2. **Perform retries** - No retry logic for external calls
3. **Trigger alerts** - No incident escalation
4. **Modify policies** - No runtime policy changes
5. **Modify thresholds dynamically** - Thresholds from input only
6. **Connect to databases** - Only via ruvector-service
7. **Execute SQL** - Never direct SQL access
8. **Persist raw content** - Only hashes and metadata
9. **Store PII** - Never store identifiable information
10. **Invoke other agents** - Standalone execution only

## Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| `INVALID_INPUT` | 400 | Input validation failed |
| `VALIDATION_FAILED` | 400 | Schema validation error |
| `TIMEOUT` | 504 | Execution timeout |
| `INTERNAL_ERROR` | 500 | Unexpected error |
| `CONFIGURATION_ERROR` | 500 | Config issue |
| `PERSISTENCE_ERROR` | 200* | Storage failed (non-fatal) |

*Note: Persistence errors do not fail the request; agent continues.

## Failure Modes

### Input Validation Failure

```json
{
  "code": "VALIDATION_FAILED",
  "message": "Input validation failed",
  "agent": {"agent_id": "safety-boundary-agent", ...},
  "timestamp": "2024-01-15T10:30:00.000Z",
  "details": {
    "errors": [{"path": "content", "message": "Required"}]
  }
}
```

### Persistence Failure (Non-Fatal)

- Agent completes successfully
- Telemetry emits `agent.persistence.failure`
- Result still returned to caller

### Timeout

- Returns `TIMEOUT` error after configured duration
- Default timeout: 30 seconds
- No partial results

## Invocation Sources

This agent MAY be invoked by:

- LLM-Edge-Agent (edge gateway)
- Core bundles (backend services)
- agentics-cli (testing/inspection)

This agent MUST NOT be invoked by:

- Other Shield agents
- External services directly
- User applications (must go through Edge/Core)

## Versioning Rules

1. Semantic versioning (MAJOR.MINOR.PATCH)
2. Breaking changes increment MAJOR
3. New features increment MINOR
4. Bug fixes increment PATCH
5. Version included in all DecisionEvents
6. CLI inspect returns version

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUVECTOR_SERVICE_URL` | `http://localhost:8080` | ruvector-service URL |
| `RUVECTOR_API_KEY` | - | API key for auth |
| `TELEMETRY_ENABLED` | `true` | Enable telemetry |
| `LLM_OBSERVATORY_URL` | `http://localhost:9090` | Observatory URL |
| `DEFAULT_SENSITIVITY` | `0.7` | Default sensitivity |
| `DEFAULT_ACTION` | `BLOCK` | Default enforcement action |

## Testing

```bash
# Run unit tests
npm test

# Run with coverage
npm run test:coverage

# CLI test
npm run cli:test -- "test content here"

# CLI simulate
npm run cli:simulate -- "test content here"

# CLI inspect
npm run cli:inspect
```
