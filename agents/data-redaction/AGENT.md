# Data Redaction Agent Contract

## Agent Identity

| Property | Value |
|----------|-------|
| **Agent ID** | `data-redaction-agent` |
| **Version** | `1.0.0` |
| **Classification** | `REDACTION` |
| **Decision Type** | `data_redaction` |

## Purpose Statement

Detects and redacts sensitive data (PII, secrets, credentials) from prompts or outputs. This agent analyzes content using pattern matching and validation logic, then produces sanitized output with sensitive data replaced according to the configured redaction strategy.

**This agent does:**
- Detect PII (email, SSN, credit cards, phone numbers, etc.)
- Detect secrets (API keys, tokens, private keys, passwords)
- Detect credentials (database URLs, connection strings)
- Redact detected sensitive data using configurable strategies
- Return sanitized content safe for further processing
- Emit DecisionEvents to ruvector-service

**This agent does NOT:**
- Orchestrate workflows
- Trigger retries or escalations
- Modify policies or thresholds
- Connect directly to databases
- Store raw PII, secrets, or credentials
- Invoke other agents

## Classification: REDACTION

This agent:
- Inspects prompts, model outputs, and tool calls
- Detects sensitive data using regex patterns and validation
- Redacts detected content using the specified strategy
- Returns sanitized (safe) content
- Emits DecisionEvents to ruvector-service
- Does NOT persist raw sensitive data
- Does NOT block content (that's ENFORCEMENT class)

## Input Schema

**Reference:** `@llm-shield/agentics-contracts.DataRedactionAgentInput`

```typescript
interface DataRedactionAgentInput {
  // Content to analyze and redact (REQUIRED)
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

  // Detection sensitivity (0.0 - 1.0, default: 0.7)
  sensitivity?: number;

  // Redaction strategy (default: 'mask')
  redaction_strategy?: 'mask' | 'hash' | 'pseudonymize' | 'remove' | 'partial_mask';

  // PII types to detect (optional, defaults to all)
  pii_types?: Array<
    | 'email'
    | 'phone_number'
    | 'ssn'
    | 'credit_card'
    | 'ip_address'
    | 'passport'
    | 'drivers_license'
    | 'date_of_birth'
    | 'address'
    | 'name'
    | 'bank_account'
    | 'national_id'
  >;

  // Secret types to detect (optional, defaults to all)
  secret_types?: Array<
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

  // Enable/disable detection categories
  detect_pii?: boolean;        // default: true
  detect_secrets?: boolean;    // default: true
  detect_credentials?: boolean; // default: true

  // Minimum confidence for redaction (0.0 - 1.0, default: 0.8)
  min_confidence_threshold?: number;

  // Whether to include redacted content in output (default: true)
  return_redacted_content?: boolean;

  // Custom placeholder for redaction (e.g., "[REDACTED]")
  custom_placeholder?: string;

  // Characters to preserve for partial_mask strategy (default: 4)
  partial_mask_chars?: number;
}
```

## Output Schema

**Reference:** `@llm-shield/agentics-contracts.DataRedactionAgentOutput`

```typescript
interface DataRedactionAgentOutput {
  agent: {
    agent_id: 'data-redaction-agent';
    agent_version: '1.0.0';
    classification: 'REDACTION';
    decision_type: 'data_redaction';
  };

  result: {
    data_redacted: boolean;
    redaction_count: number;
    original_risk_score: number;        // 0.0 - 1.0
    severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
    confidence: number;                 // 0.0 - 1.0
    redacted_entities: RedactedEntity[];
    redacted_content?: string;          // Sanitized content (safe to expose)
    detected_categories: string[];
    category_counts: Record<string, number>;
    severity_counts: Record<string, number>;
  };

  duration_ms: number;
  cached: boolean;
}

interface RedactedEntity {
  entity_type: string;              // e.g., "email", "ssn", "api_key"
  category: 'pii' | 'secret' | 'credential';
  original_start: number;           // Position in original content
  original_end: number;
  redacted_start: number;           // Position in redacted content
  redacted_end: number;
  confidence: number;               // 0.0 - 1.0
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  pattern_id?: string;
  strategy_applied: string;         // Redaction strategy used
  original_length: number;          // Length of original (NOT the value)
  redacted_placeholder: string;     // The placeholder used
}
```

## DecisionEvent Mapping

**Reference:** `@llm-shield/agentics-contracts.DataRedactionDecisionEvent`

Every invocation emits exactly ONE DecisionEvent to ruvector-service:

```typescript
interface DataRedactionDecisionEvent {
  agent_id: 'data-redaction-agent';
  agent_version: '1.0.0';
  decision_type: 'data_redaction';

  // SHA-256 hash of ORIGINAL content (NOT raw content)
  inputs_hash: string;

  // SHA-256 hash of REDACTED content
  outputs_hash: string;

  // Redaction outputs (sanitized - no raw content)
  outputs: {
    data_redacted: boolean;
    redaction_count: number;
    original_risk_score: number;
    severity: string;
    confidence: number;
    detected_categories: string[];
    category_counts: Record<string, number>;
    severity_counts: Record<string, number>;
    entity_type_counts: Record<string, number>;  // Count by type, no values
  };

  confidence: number;
  constraints_applied: PolicyReference[];
  execution_ref: string;
  timestamp: string;
  duration_ms: number;

  telemetry: {
    original_content_length: number;
    redacted_content_length: number;
    content_source: string;
    session_id?: string;
    caller_id?: string;
    redaction_strategy: string;
  };
}
```

### Data Persistence Rules

**PERSISTED to ruvector-service:**
- Input content hash (SHA-256)
- Redacted content hash (SHA-256)
- Redaction metadata (counts, categories, positions)
- Risk scores and confidence
- Entity counts by type
- Execution timing
- Redaction strategy used

**NEVER PERSISTED:**
- Raw input content
- Actual PII values (emails, SSNs, credit cards)
- Matched secret values (API keys, tokens)
- Passwords or credentials
- Partial values or redacted previews with real data
- Private key contents
- Original text segments

## Redaction Strategies

| Strategy | Description | Example |
|----------|-------------|---------|
| `mask` | Replace with type placeholder | `[EMAIL]`, `[SSN]`, `[API_KEY]` |
| `hash` | Replace with SHA-256 hash (deterministic) | `[HASH:a1b2c3...]` |
| `pseudonymize` | Replace with consistent fake data | `john.doe@example.com` → `user_7x9a@fake.com` |
| `remove` | Remove entirely | (content is simply removed) |
| `partial_mask` | Keep first/last N chars | `john****@example.com`, `****-****-****-1234` |

## CLI Contract

### Test Mode
Validates agent functionality with sample input:
```bash
shield-agent data-redaction test \
  --content "My email is john@example.com and SSN is 123-45-6789" \
  --format json
```

### Simulate Mode
Runs redaction with custom configuration:
```bash
shield-agent data-redaction simulate \
  --content "API key: sk-ant-1234567890abcdef" \
  --strategy partial_mask \
  --sensitivity 0.9 \
  --pii-types email,ssn \
  --format json
```

### Inspect Mode
Retrieves redaction result by execution reference:
```bash
shield-agent data-redaction inspect \
  --execution-ref <uuid> \
  --verbose
```

## Detection Categories

### PII Types

| Type | Description | Severity | Example Patterns |
|------|-------------|----------|------------------|
| `email` | Email addresses | `medium` | `user@domain.com` |
| `phone_number` | Phone numbers (international) | `medium` | `+1-555-123-4567` |
| `ssn` | Social Security Numbers | `critical` | `123-45-6789` |
| `credit_card` | Credit card numbers | `critical` | `4111-1111-1111-1111` |
| `ip_address` | IPv4/IPv6 addresses | `low` | `192.168.1.1` |
| `passport` | Passport numbers | `high` | `A12345678` |
| `drivers_license` | Driver's license numbers | `high` | State-specific patterns |
| `date_of_birth` | Dates of birth | `medium` | `1990-01-15` |
| `address` | Physical addresses | `medium` | Street address patterns |
| `name` | Personal names | `low` | Named entity detection |
| `bank_account` | Bank account numbers | `critical` | Routing + account numbers |
| `national_id` | National ID numbers | `high` | Country-specific patterns |

### Secret Types

| Type | Description | Severity | Example Patterns |
|------|-------------|----------|------------------|
| `aws_credentials` | AWS access keys | `critical` | `AKIA...`, `aws_secret_access_key=...` |
| `github_token` | GitHub tokens | `high` | `ghp_...`, `gho_...` |
| `stripe_key` | Stripe API keys | `critical`/`medium` | `sk_live_...`, `sk_test_...` |
| `openai_key` | OpenAI API keys | `high` | `sk-...` (48+ chars) |
| `anthropic_key` | Anthropic API keys | `high` | `sk-ant-...` |
| `slack_token` | Slack tokens | `high` | `xox[baprs]-...` |
| `google_api_key` | Google API keys | `high` | `AIza...` |
| `private_key` | Private keys | `critical` | `-----BEGIN PRIVATE KEY-----` |
| `jwt_token` | JWT tokens | `high` | `eyJ...` (Base64) |
| `database_url` | Database URLs | `critical` | `postgres://...`, `mongodb://...` |
| `generic_api_key` | Generic API keys | `medium` | `api_key=...` |
| `generic_secret` | Generic secrets | `medium` | `secret=...` |
| `password` | Passwords | `high` | `password=...` |
| `connection_string` | Connection strings | `critical` | `Server=...;Password=...` |

## Confidence Semantics

Confidence scores are **heuristic-based** (not probabilistic):

| Score Range | Interpretation |
|-------------|----------------|
| 0.0 - 0.3 | Low confidence - possible false positive |
| 0.3 - 0.6 | Medium confidence - likely sensitive data |
| 0.6 - 0.8 | High confidence - strong indicators |
| 0.8 - 1.0 | Very high confidence - definite sensitive data |

Only entities meeting `min_confidence_threshold` (default: 0.8) are redacted.

## Severity Mapping

| Data Type | Default Severity |
|-----------|------------------|
| SSN, Credit Card, Bank Account | `critical` |
| Private Keys, AWS Credentials, Database URLs | `critical` |
| Passwords, Passport, Driver's License | `high` |
| GitHub/Stripe/OpenAI/Anthropic Keys | `high` |
| Email, Phone, Address, DOB | `medium` |
| IP Address, Generic API Key | `low` |
| Name (if detected) | `low` |

## Constraints Applied (Policy References)

When policies are provided in context:
- Policy IDs are recorded in `constraints_applied`
- No policy logic is executed (consumer-only)
- Policy rules may specify:
  - Which PII/secret types to detect
  - Minimum confidence thresholds
  - Redaction strategy preferences
  - Whitelisted patterns

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
- Store raw sensitive values
- Orchestrate workflows
- Perform retries

## Failure Modes

| Error Code | Description | Response |
|------------|-------------|----------|
| `INVALID_INPUT` | Input validation failed | Return AgentError with validation details |
| `VALIDATION_FAILED` | Schema validation error | Return AgentError with schema path |
| `TIMEOUT` | Redaction exceeded timeout | Return partial results if available |
| `INTERNAL_ERROR` | Unexpected error | Return AgentError, emit telemetry |
| `CONFIGURATION_ERROR` | Invalid configuration | Return AgentError with config details |
| `PERSISTENCE_ERROR` | ruvector-service unavailable | Complete redaction, mark event failed |

## Non-Responsibilities

This agent explicitly MUST NOT:

1. **Orchestrate workflows** - No task scheduling, no agent spawning
2. **Perform retries** - Single invocation, single response
3. **Trigger alerts** - Redaction only, no notifications
4. **Modify policies** - Consumer of policies, not producer
5. **Escalate incidents** - Report findings only
6. **Block content** - Redaction only (ENFORCEMENT class would block)
7. **Connect to SQL** - All persistence via ruvector-service client
8. **Store raw data** - Only hashes, counts, and metadata
9. **Invoke other agents** - Self-contained execution

## Versioning Rules

- **Major version**: Breaking schema changes, strategy format changes
- **Minor version**: New PII/secret types, new redaction strategies
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
# Basic PII redaction test
shield-agent data-redaction test \
  --content "Contact me at john@example.com or 555-123-4567" \
  --format json

# Expected: data_redacted=true, redacted_content="Contact me at [EMAIL] or [PHONE]"

# Secret redaction test
shield-agent data-redaction test \
  --content "export OPENAI_API_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyz123456" \
  --format json

# Expected: data_redacted=true, category=secret, severity=high

# Partial mask strategy test
shield-agent data-redaction test \
  --content "Card: 4111111111111111" \
  --strategy partial_mask \
  --format json

# Expected: redacted_content="Card: 4111****1111"

# No sensitive data test
shield-agent data-redaction test \
  --content "Hello, this is a normal message" \
  --format json

# Expected: data_redacted=false, redaction_count=0
```

## Integration Verification Checklist

- [ ] Agent imports schemas from `@llm-shield/agentics-contracts`
- [ ] Input validated against `DataRedactionAgentInput`
- [ ] Output validated against `DataRedactionAgentOutput`
- [ ] DecisionEvent emitted to ruvector-service
- [ ] No raw PII/secrets in persisted data
- [ ] Redacted content is safe to expose
- [ ] Telemetry compatible with LLM-Observatory
- [ ] CLI commands functional (test/simulate/inspect)
- [ ] Deployable as Google Edge Function
- [ ] Deterministic, stateless execution
- [ ] No orchestration, retry, or alert logic
