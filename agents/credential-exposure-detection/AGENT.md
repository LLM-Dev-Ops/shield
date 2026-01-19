# Credential Exposure Detection Agent

## Agent Contract & Boundary Definition

### Agent Purpose Statement

**Detect accidental exposure of usernames, passwords, access keys, or authentication artifacts in LLM inputs, outputs, and tool calls.**

This agent analyzes content for credential exposure patterns including:
- Username/password combinations
- Basic and Bearer authentication headers
- Database connection credentials
- API credentials and OAuth tokens
- Hardcoded credentials in code
- Environment variable credential patterns
- SSH, FTP, SMTP, LDAP credentials

### Agent Classification

| Property | Value |
|----------|-------|
| Agent ID | `credential-exposure-detection-agent` |
| Version | `1.0.0` |
| Classification | **DETECTION_ONLY** |
| Decision Type | `credential_exposure_detection` |
| Deployment | Google Cloud Edge Function |

**DETECTION_ONLY** means this agent:
- ✅ Detects and reports credential exposure
- ✅ Calculates risk scores and confidence
- ✅ Emits DecisionEvents for audit
- ❌ Does NOT redact or sanitize content
- ❌ Does NOT block or allow content
- ❌ Does NOT modify the input in any way

---

## Input Schema

**Import from**: `@llm-shield/agentics-contracts`

```typescript
import { CredentialExposureDetectionInput } from '@llm-shield/agentics-contracts';
```

### Input Structure

```typescript
interface CredentialExposureDetectionInput {
  // Required
  content: string;                    // Content to analyze
  context: InvocationContext;         // Execution context

  // Optional configuration
  sensitivity?: number;               // 0.0-1.0, default: 0.5
  threshold?: number;                 // 0.0-1.0, default: 0.7
  detect_types?: CredentialType[];    // Types to detect
  detect_password_patterns?: boolean; // default: true
  detect_username_patterns?: boolean; // default: true
  detect_auth_headers?: boolean;      // default: true
  detect_credential_pairs?: boolean;  // default: true
  min_password_length?: number;       // 1-100, default: 6
  custom_patterns?: Record<string, string>; // Custom regex patterns
}

interface InvocationContext {
  execution_ref: string;              // UUID for tracing
  timestamp: string;                  // ISO 8601 UTC
  content_source: 'user_input' | 'model_output' | 'tool_call' | 'system';
  caller_id?: string;
  session_id?: string;
  policies?: PolicyReference[];
  metadata?: Record<string, unknown>;
}
```

### Validation Rules

1. `content` - Required, non-empty string
2. `context.execution_ref` - Required, valid UUID v4
3. `context.timestamp` - Required, valid ISO 8601 datetime
4. `context.content_source` - Required, one of: `user_input`, `model_output`, `tool_call`, `system`
5. `sensitivity` - Optional, number 0.0-1.0
6. `threshold` - Optional, number 0.0-1.0
7. `min_password_length` - Optional, integer 1-100

---

## Output Schema

**Import from**: `@llm-shield/agentics-contracts`

```typescript
import {
  CredentialExposureDetectionAgentOutput,
  CredentialExposureDetectionResult,
  CredentialExposureDetectedEntity
} from '@llm-shield/agentics-contracts';
```

### Output Structure

```typescript
interface CredentialExposureDetectionAgentOutput {
  agent: AgentIdentity;
  result: CredentialExposureDetectionResult;
  duration_ms: number;
  cached: boolean;
}

interface CredentialExposureDetectionResult {
  credentials_detected: boolean;
  risk_score: number;                    // 0.0-1.0
  severity: Severity;                    // none|low|medium|high|critical
  confidence: number;                    // 0.0-1.0
  entities: CredentialExposureDetectedEntity[];
  risk_factors: RiskFactor[];
  pattern_match_count: number;
  detected_types: CredentialType[];
  type_counts: Record<string, number>;
  credential_pair_count: number;
  exposure_summary?: ExposureSummary;
}

interface CredentialExposureDetectedEntity {
  credential_type: CredentialType;
  category: string;
  start: number;                         // Position in content
  end: number;                           // Position in content
  confidence: number;                    // 0.0-1.0
  pattern_id?: string;
  severity: Severity;
  is_credential_pair: boolean;
  has_username: boolean;
  has_password: boolean;
  redacted_preview?: string;             // e.g., "user****:pass****"
  context_hint?: string;
}
```

**CRITICAL**: Entity output NEVER contains raw credentials. Only:
- Position information (start/end)
- Redacted previews (first 4 chars + ****)
- Aggregated metadata

---

## DecisionEvent Mapping

Every invocation produces exactly ONE `CredentialExposureDecisionEvent` persisted to `ruvector-service`.

```typescript
interface CredentialExposureDecisionEvent {
  // Identity
  agent_id: 'credential-exposure-detection-agent';
  agent_version: string;
  decision_type: 'credential_exposure_detection';

  // Content (HASHED, never raw)
  inputs_hash: string;                   // SHA-256 of input content

  // Results (sanitized)
  outputs: {
    credentials_detected: boolean;
    risk_score: number;
    severity: Severity;
    confidence: number;
    pattern_match_count: number;
    detected_types: string[];
    entity_count: number;
    type_counts: Record<string, number>;
    credential_pair_count: number;
    exposure_summary?: ExposureSummary;
  };

  // Execution metadata
  confidence: number;
  constraints_applied: PolicyReference[];
  execution_ref: string;                 // UUID
  timestamp: string;                     // ISO 8601 UTC
  duration_ms: number;

  // Telemetry (no credentials)
  telemetry?: {
    content_length: number;
    content_source: string;
    session_id?: string;
    caller_id?: string;
    threshold_used?: number;
    types_checked?: string[];
    detection_flags?: {
      password_patterns: boolean;
      username_patterns: boolean;
      auth_headers: boolean;
      credential_pairs: boolean;
    };
  };
}
```

### Data NOT Persisted

The following are **NEVER** stored in DecisionEvents:

- ❌ Raw credentials (usernames, passwords)
- ❌ Raw content text
- ❌ Unredacted previews
- ❌ Authentication tokens
- ❌ Connection strings
- ❌ API keys

---

## CLI Contract

### Installation

```bash
npm install @llm-shield/credential-exposure-detection-agent
```

### Invocation Modes

#### Test Mode
Run detection and display results:
```bash
npx credential-exposure-detection test "username=admin password=secret123"
npx credential-exposure-detection test --file input.txt
```

#### Simulate Mode
Run detection without persistence:
```bash
npx credential-exposure-detection simulate "content to analyze"
npx credential-exposure-detection simulate --file input.txt
```

#### Inspect Mode
View agent configuration:
```bash
npx credential-exposure-detection inspect
npx credential-exposure-detection inspect --patterns
```

### CLI Options

| Option | Short | Description |
|--------|-------|-------------|
| `--format <fmt>` | `-f` | Output format: json, text, table |
| `--verbose` | `-v` | Verbose output |
| `--sensitivity <n>` | `-s` | Detection sensitivity (0.0-1.0) |
| `--patterns` | `-p` | Show available patterns |
| `--file <path>` | | Read content from file |
| `--help` | `-h` | Show help |

### Example Output (JSON)

```json
{
  "agent": {
    "agent_id": "credential-exposure-detection-agent",
    "agent_version": "1.0.0",
    "classification": "DETECTION_ONLY",
    "decision_type": "credential_exposure_detection"
  },
  "result": {
    "credentials_detected": true,
    "risk_score": 0.85,
    "severity": "critical",
    "confidence": 0.95,
    "entities": [
      {
        "credential_type": "username_password",
        "start": 0,
        "end": 35,
        "confidence": 0.95,
        "severity": "critical",
        "is_credential_pair": true,
        "redacted_preview": "admi****:secr****"
      }
    ],
    "detected_types": ["username_password"],
    "credential_pair_count": 1
  },
  "duration_ms": 2.5
}
```

---

## Invocation Sources

This agent may be invoked by:

| Source | Method |
|--------|--------|
| LLM-Edge-Agent | HTTP POST to Edge Function |
| LLM-Core | Internal agent call |
| agentics-cli | CLI invocation |

This agent **NEVER** invokes other agents.

---

## Explicit Non-Responsibilities

This agent **MUST NOT**:

1. ❌ **Modify content** - Detection only, no redaction/sanitization
2. ❌ **Block or allow** - No enforcement decisions
3. ❌ **Orchestrate workflows** - No coordination with other agents
4. ❌ **Trigger retries** - No retry logic
5. ❌ **Trigger alerts** - No incident escalation
6. ❌ **Modify policies** - Read-only policy access
7. ❌ **Modify routing** - No routing logic changes
8. ❌ **Modify thresholds dynamically** - Use provided inputs only
9. ❌ **Connect to databases** - Only via ruvector-service
10. ❌ **Execute SQL** - All persistence via HTTP client
11. ❌ **Store raw credentials** - Only hashes and metadata

---

## Failure Modes

### Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `INVALID_INPUT` | Input validation failed | 400 |
| `VALIDATION_FAILED` | Schema validation error | 400 |
| `TIMEOUT` | Detection timeout exceeded | 408 |
| `INTERNAL_ERROR` | Unexpected error | 500 |
| `CONFIGURATION_ERROR` | Invalid configuration | 500 |
| `PERSISTENCE_ERROR` | ruvector-service failure | 500 |

### Error Response Structure

```typescript
interface AgentError {
  code: AgentErrorCode;
  message: string;
  agent?: AgentIdentity;
  execution_ref?: string;
  timestamp: string;
  details?: Record<string, unknown>;
}
```

### Failure Handling

1. **Input validation failure** → Return INVALID_INPUT immediately
2. **Detection error** → Return INTERNAL_ERROR with sanitized message
3. **Persistence failure** → Log error, continue (non-blocking)
4. **Telemetry failure** → Log error, continue (non-blocking)

---

## Confidence Semantics

Confidence scores indicate detection reliability:

| Range | Interpretation |
|-------|----------------|
| 0.90-1.00 | Very high confidence - definite credential |
| 0.75-0.89 | High confidence - likely credential |
| 0.60-0.74 | Medium confidence - possible credential |
| 0.40-0.59 | Low confidence - uncertain |
| 0.00-0.39 | Very low confidence - likely false positive |

Confidence is calculated based on:
- Pattern specificity (more specific = higher confidence)
- Sensitivity configuration
- Context indicators
- Credential pair detection (pairs increase confidence)

---

## Constraints Applied Semantics

`constraints_applied` references policies that were evaluated:

```typescript
interface PolicyReference {
  policy_id: string;
  policy_version?: string;
  rule_ids?: string[];
}
```

Example:
```json
{
  "constraints_applied": [
    {
      "policy_id": "credential-detection-policy",
      "policy_version": "1.0",
      "rule_ids": ["detect-db-credentials", "detect-api-keys"]
    }
  ]
}
```

---

## Versioning Rules

1. **Major version** (X.0.0): Breaking changes to input/output schemas
2. **Minor version** (1.X.0): New detection patterns, new optional fields
3. **Patch version** (1.0.X): Bug fixes, performance improvements

Version compatibility:
- DecisionEvents include `agent_version` for version tracking
- Schema changes require new decision_type if breaking
- Backward compatibility maintained within major version

---

## Detection Categories

| Category | Severity | Description |
|----------|----------|-------------|
| `username_password` | critical | Username + password pairs |
| `basic_auth` | critical | Basic Auth headers |
| `bearer_token` | high | Bearer tokens |
| `database_credential` | critical | DB connection credentials |
| `api_credential` | high | API keys and secrets |
| `oauth_credential` | high | OAuth client credentials |
| `ssh_credential` | critical | SSH passwords/keys |
| `ftp_credential` | high | FTP/SFTP credentials |
| `smtp_credential` | high | Email server credentials |
| `ldap_credential` | critical | LDAP/AD credentials |
| `service_account` | critical | Service account credentials |
| `admin_credential` | critical | Admin/root credentials |
| `hardcoded_credential` | high | Hardcoded in code |
| `environment_credential` | high | Environment variables |
| `generic_credential` | medium | Generic patterns |

---

## Deployment

### Google Cloud Edge Function

```yaml
name: credential-exposure-detection
runtime: nodejs20
entrypoint: handler
memory: 256MB
timeout: 30s
maxInstances: 100
environment:
  RUVECTOR_ENDPOINT: https://ruvector-service.example.com
  LLM_OBSERVATORY_ENDPOINT: https://observatory.example.com
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `RUVECTOR_ENDPOINT` | Yes | ruvector-service URL |
| `RUVECTOR_API_KEY` | No | API key for ruvector-service |
| `RUVECTOR_TIMEOUT` | No | Request timeout (ms), default: 5000 |
| `LLM_OBSERVATORY_ENDPOINT` | No | Telemetry endpoint |
| `LLM_OBSERVATORY_API_KEY` | No | Telemetry API key |

---

## Smoke Test Commands

```bash
# Basic detection test
npx credential-exposure-detection test "password=secret123"

# Full credential pair test
npx credential-exposure-detection test 'username=admin password=secret'

# Database URL test
npx credential-exposure-detection test 'postgres://user:pass@localhost/db'

# Auth header test
npx credential-exposure-detection test 'Authorization: Basic dXNlcjpwYXNz'

# Inspect patterns
npx credential-exposure-detection inspect --patterns

# Simulate (no persistence)
npx credential-exposure-detection simulate "test content"
```

---

## Verification Checklist

- [ ] Agent imports schemas from @llm-shield/agentics-contracts
- [ ] All inputs validated against CredentialExposureDetectionInput schema
- [ ] All outputs conform to CredentialExposureDetectionAgentOutput schema
- [ ] Exactly ONE DecisionEvent emitted per invocation
- [ ] DecisionEvent persisted to ruvector-service
- [ ] Raw credentials NEVER appear in DecisionEvent
- [ ] Telemetry compatible with LLM-Observatory
- [ ] CLI invokable with test/simulate/inspect modes
- [ ] Deployable as Google Cloud Edge Function
- [ ] Stateless execution (no persistent state)
- [ ] Deterministic output for same input
- [ ] No orchestration logic
- [ ] No retry logic
- [ ] No incident escalation
- [ ] No direct database connections
