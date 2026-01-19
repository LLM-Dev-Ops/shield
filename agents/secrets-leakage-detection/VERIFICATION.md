# Secrets Leakage Detection Agent - Verification Checklist

## Pre-Deployment Verification

### 1. Contract Compliance

- [ ] Agent imports schemas from `@llm-shield/agentics-contracts`
- [ ] Input validated against `SecretsLeakageDetectionInput`
- [ ] Output validated against `AgentOutput`
- [ ] Error responses match `AgentError` schema
- [ ] DecisionEvent matches `DecisionEvent` schema

### 2. Classification Compliance

- [ ] Classification is `DETECTION_ONLY`
- [ ] Decision type is `secret_detection`
- [ ] Agent does NOT modify content
- [ ] Agent does NOT enforce decisions (BLOCK/ALLOW/SANITIZE)
- [ ] Agent does NOT redact content

### 3. Persistence Compliance

- [ ] DecisionEvent emitted to ruvector-service (not SQL directly)
- [ ] inputs_hash is SHA-256 (not raw content)
- [ ] No raw secrets in persisted data
- [ ] No matched text excerpts in persisted data
- [ ] No PII in persisted data
- [ ] Telemetry contains no sensitive data

### 4. Non-Responsibility Compliance

- [ ] Agent does NOT orchestrate workflows
- [ ] Agent does NOT perform retries
- [ ] Agent does NOT trigger alerts
- [ ] Agent does NOT modify policies
- [ ] Agent does NOT escalate incidents
- [ ] Agent does NOT invoke other agents
- [ ] Agent does NOT connect to SQL databases

### 5. CLI Functionality

- [ ] `test` mode works with `--content`
- [ ] `simulate` mode works with configuration options
- [ ] `inspect` mode retrieves DecisionEvent by execution_ref
- [ ] `--format json` outputs valid JSON
- [ ] `--format text` outputs human-readable text
- [ ] `--format table` outputs markdown table
- [ ] `--verbose` adds detailed output

### 6. Edge Function Deployment

- [ ] Handler exports default fetch function
- [ ] Handler responds to POST requests only
- [ ] Handler returns 405 for non-POST methods
- [ ] Handler returns 400 for invalid JSON
- [ ] Handler returns 200 for successful detection
- [ ] Handler returns 400 for validation errors
- [ ] Response headers include Content-Type: application/json

### 7. Telemetry Compliance

- [ ] `detection_started` event emitted
- [ ] `detection_completed` event emitted
- [ ] `detection_error` event emitted on failure
- [ ] Events include execution_ref for correlation
- [ ] Events include agent_id and agent_version
- [ ] Events are LLM-Observatory compatible
- [ ] No sensitive data in telemetry payloads

## Smoke Tests

### Test 1: AWS Credentials Detection

```bash
shield-agent secrets-leakage-detection test \
  --content "AKIAIOSFODNN7EXAMPLE" \
  --format json
```

**Expected:**
- `threats_detected: true`
- `detected_categories: ["aws_credentials"]`
- `severity: "critical"`
- `confidence: >= 0.95`

### Test 2: GitHub Token Detection

```bash
shield-agent secrets-leakage-detection test \
  --content "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  --format json
```

**Expected:**
- `threats_detected: true`
- `detected_categories: ["github_token"]`
- `severity: "high"`

### Test 3: Private Key Detection

```bash
shield-agent secrets-leakage-detection test \
  --content "-----BEGIN RSA PRIVATE KEY-----" \
  --format json
```

**Expected:**
- `threats_detected: true`
- `detected_categories: ["private_key"]`
- `severity: "critical"`

### Test 4: Entropy-Based Detection

```bash
shield-agent secrets-leakage-detection test \
  --content "token=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9" \
  --entropy-detection true \
  --format json
```

**Expected:**
- `threats_detected: true`
- Entity with `entropy_based: true`

### Test 5: No Secrets (Clean Input)

```bash
shield-agent secrets-leakage-detection test \
  --content "Hello, this is a normal message without secrets" \
  --format json
```

**Expected:**
- `threats_detected: false`
- `entity_count: 0`
- `severity: "none"`

### Test 6: Category Filtering

```bash
shield-agent secrets-leakage-detection test \
  --content "AKIAIOSFODNN7EXAMPLE and ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  --categories aws_credentials \
  --format json
```

**Expected:**
- `threats_detected: true`
- `detected_categories: ["aws_credentials"]`
- GitHub token NOT detected (filtered out)

### Test 7: Sensitivity Adjustment

```bash
# Low sensitivity
shield-agent secrets-leakage-detection test \
  --content "secret=abc123" \
  --sensitivity 0.3 \
  --format json

# High sensitivity
shield-agent secrets-leakage-detection test \
  --content "secret=abc123" \
  --sensitivity 0.9 \
  --format json
```

**Expected:**
- Higher sensitivity = higher confidence scores

## Integration Tests

### Test 8: ruvector-service Persistence

```bash
# Run simulate mode (persists to ruvector)
shield-agent secrets-leakage-detection simulate \
  --content "sk_live_EXAMPLE_TEST_KEY_12345678" \
  --format json

# Capture execution_ref from output, then:
shield-agent secrets-leakage-detection inspect \
  --execution-ref <captured_uuid> \
  --format json
```

**Expected:**
- DecisionEvent retrieved successfully
- `inputs_hash` is SHA-256 (not raw content)
- No secret values in retrieved data

### Test 9: Edge Function HTTP Test

```bash
curl -X POST http://localhost:8080/secrets-leakage-detection \
  -H "Content-Type: application/json" \
  -d '{
    "content": "api_key=sk_live_EXAMPLE_TEST_KEY_00",
    "context": {
      "execution_ref": "123e4567-e89b-12d3-a456-426614174000",
      "timestamp": "2024-01-01T00:00:00Z",
      "content_source": "user_input"
    }
  }'
```

**Expected:**
- HTTP 200
- Valid AgentOutput JSON

## Security Verification

### Verify No Secret Persistence

1. Run detection on known secret
2. Query ruvector-service for the DecisionEvent
3. Verify raw secret does NOT appear in:
   - `inputs_hash` (should be SHA-256)
   - `outputs`
   - `telemetry`
   - Any other field

### Verify No Secret Logging

1. Set `NODE_ENV=development`
2. Run detection on known secret
3. Verify console output does NOT contain raw secrets
4. Verify only redacted previews appear (if any)

## Performance Baseline

| Metric | Target | Actual |
|--------|--------|--------|
| Cold start | < 100ms | |
| Detection (100 chars) | < 10ms | |
| Detection (10K chars) | < 100ms | |
| Detection (100K chars) | < 500ms | |
| Memory usage | < 64MB | |

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Developer | | | |
| Security Review | | | |
| QA | | | |
| Platform Lead | | | |
