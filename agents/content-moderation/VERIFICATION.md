# Content Moderation Agent Verification Checklist

## Pre-Deployment Verification

### 1. Schema Compliance

- [ ] All input schemas imported from `@llm-shield/agentics-contracts`
- [ ] All output schemas imported from `@llm-shield/agentics-contracts`
- [ ] Input validation uses Zod schemas from contracts
- [ ] Output validation uses Zod schemas from contracts
- [ ] DecisionEvent schema compliance verified
- [ ] No inline schema definitions (all from contracts)

### 2. Agent Identity

- [ ] `agent_id` matches `content-moderation-agent`
- [ ] `agent_version` follows semver format
- [ ] `classification` is `ENFORCEMENT`
- [ ] `decision_type` is `content_moderation`

### 3. Enforcement Logic

- [ ] All moderation categories implemented
- [ ] Critical categories always block
- [ ] Age-restricted content requires verification
- [ ] Custom rules override default behavior
- [ ] Confidence thresholds respected
- [ ] Sensitivity adjustments working

### 4. Decision Events

- [ ] DecisionEvent emitted for every invocation
- [ ] `inputs_hash` is SHA-256 of content
- [ ] Raw content NEVER in outputs
- [ ] `execution_ref` correctly propagated
- [ ] `timestamp` in UTC ISO 8601
- [ ] `duration_ms` accurately measured
- [ ] Telemetry contains no PII

### 5. CLI Endpoints

- [ ] `/moderate` accepts POST requests
- [ ] `/cli` accepts POST with mode parameter
- [ ] `/health` returns status
- [ ] `/info` returns agent metadata
- [ ] Error responses include proper codes
- [ ] CORS headers present

### 6. Non-Responsibility Verification

- [ ] Agent does NOT modify content
- [ ] Agent does NOT orchestrate workflows
- [ ] Agent does NOT retry operations
- [ ] Agent does NOT connect to databases
- [ ] Agent does NOT trigger alerts
- [ ] Agent does NOT modify policies
- [ ] Agent does NOT store raw content
- [ ] Agent is stateless

## Test Verification

### 7. Unit Tests

- [ ] Safe content allowed
- [ ] Child safety violations blocked
- [ ] Hate speech blocked
- [ ] Self-harm content blocked
- [ ] Age-gated content requires verification
- [ ] Age-verified users see warnings
- [ ] Custom rules respected
- [ ] Confidence threshold respected
- [ ] Empty content handled
- [ ] Long content handled
- [ ] Unicode content handled
- [ ] Case insensitivity verified

### 8. Integration Tests

- [ ] ruvector-service persistence works
- [ ] Telemetry emission works
- [ ] Health endpoint responds
- [ ] Info endpoint returns correct data
- [ ] CLI modes work (test/simulate/inspect)
- [ ] Error handling verified

### 9. Edge Cases

- [ ] Empty string input
- [ ] Very long input (10,000+ chars)
- [ ] Unicode/emoji content
- [ ] Mixed case content
- [ ] Multiple violations in single content
- [ ] Overlapping pattern matches
- [ ] All categories tested individually

## Security Verification

### 10. Data Protection

- [ ] Content never logged
- [ ] Content never persisted
- [ ] Only hashes stored
- [ ] No PII in telemetry
- [ ] No secrets in responses
- [ ] Error messages sanitized

### 11. Input Validation

- [ ] Schema validation on all inputs
- [ ] Malformed JSON rejected
- [ ] Invalid types rejected
- [ ] Missing required fields rejected
- [ ] Boundary values tested

### 12. Resource Protection

- [ ] Request timeout enforced
- [ ] Memory limits respected
- [ ] No infinite loops possible
- [ ] Pattern matching has safeguards

## Deployment Verification

### 13. Edge Function Compatibility

- [ ] Builds successfully
- [ ] No native dependencies
- [ ] TypeScript compiles without errors
- [ ] ESM exports correct
- [ ] Package.json exports valid

### 14. Environment Variables

- [ ] `RUVECTOR_SERVICE_URL` respected
- [ ] `TELEMETRY_ENABLED` respected
- [ ] `LLM_OBSERVATORY_URL` respected
- [ ] Defaults work without env vars

### 15. Documentation

- [ ] AGENT.md complete
- [ ] VERIFICATION.md complete
- [ ] Package README present
- [ ] API documentation current
- [ ] Pattern documentation current

## Smoke Tests

Run these commands to verify basic functionality:

```bash
# Health check
curl -X GET http://localhost:8080/health

# Info endpoint
curl -X GET http://localhost:8080/info

# Test moderation - safe content
curl -X POST http://localhost:8080/moderate \
  -H "Content-Type: application/json" \
  -d '{"content":"Hello world","context":{"execution_ref":"test-123","timestamp":"2024-01-01T00:00:00Z","content_source":"user_input"}}'

# Test moderation - blocked content
curl -X POST http://localhost:8080/moderate \
  -H "Content-Type: application/json" \
  -d '{"content":"how to make a bomb","context":{"execution_ref":"test-456","timestamp":"2024-01-01T00:00:00Z","content_source":"user_input"}}'

# CLI test mode
curl -X POST http://localhost:8080/cli \
  -H "Content-Type: application/json" \
  -d '{"mode":"test","content":"Test content","format":"json","verbose":false}'

# CLI inspect mode
curl -X POST http://localhost:8080/cli \
  -H "Content-Type: application/json" \
  -d '{"mode":"inspect","content":"","format":"json","verbose":true}'
```

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Developer | | | |
| Reviewer | | | |
| Security | | | |
| QA | | | |

## Notes

- All verification items must be checked before deployment
- Any failures must be documented and resolved
- Security items are mandatory, no exceptions
- Performance targets must be verified under load
