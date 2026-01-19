# Toxicity Detection Agent

**Classification:** `DETECTION_ONLY`
**Decision Type:** `toxicity_detection`
**Agent ID:** `toxicity-detection-agent`
**Version:** `1.0.0`

Detects abusive, hateful, or toxic language in model outputs, prompts, and tool payloads.

## Purpose

This agent analyzes text content to identify toxic language across multiple categories:

- **toxic** - General toxic language
- **severe_toxic** - Strong profanity and slurs
- **obscene** - Vulgar and explicit content
- **threat** - Violence and intimidation
- **insult** - Personal attacks and degradation
- **identity_hate** - Discrimination and bigotry

## Installation

```bash
npm install @llm-shield/toxicity-detection
```

## Usage

### Programmatic API

```typescript
import { ToxicityDetectionAgent } from '@llm-shield/toxicity-detection';

const agent = new ToxicityDetectionAgent();

const output = await agent.detect({
  content: 'Text to analyze',
  context: {
    execution_ref: 'uuid-here',
    timestamp: new Date().toISOString(),
    content_source: 'user_input',
  },
  sensitivity: 0.5,  // 0.0 - 1.0
  threshold: 0.7,    // 0.0 - 1.0
});

console.log(output.result.toxicity_detected);
console.log(output.result.detected_categories);
console.log(output.result.risk_score);
```

### CLI

```bash
# Test mode
shield-agent toxicity-detection test --content "You are an idiot"

# Simulate mode with custom settings
shield-agent toxicity-detection simulate \
  --content "I hate you" \
  --sensitivity 0.8 \
  --threshold 0.6 \
  --categories threat,insult

# Inspect previous execution
shield-agent toxicity-detection inspect --execution-ref <uuid>
```

### HTTP Handler (Edge Function)

```typescript
import { createHandler } from '@llm-shield/toxicity-detection/handler';

const handler = createHandler();

// Deploy as Google Cloud Edge Function
export default handler;
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `sensitivity` | number | 0.5 | Detection sensitivity (0.0 - 1.0) |
| `threshold` | number | 0.7 | Minimum score to flag as toxic (0.0 - 1.0) |
| `detect_categories` | string[] | all | Categories to detect |

## Output Schema

```typescript
interface ToxicityDetectionResult {
  toxicity_detected: boolean;
  risk_score: number;          // 0.0 - 1.0
  severity: Severity;          // none, low, medium, high, critical
  confidence: number;          // 0.0 - 1.0
  entities: ToxicityDetectedEntity[];
  risk_factors: RiskFactor[];
  pattern_match_count: number;
  detected_categories: ToxicityCategory[];
  category_counts: Record<string, number>;
}
```

## Non-Responsibilities

This agent **DOES NOT**:

- Modify, sanitize, or redact content
- Block or allow content
- Orchestrate workflows
- Trigger retries or escalations
- Connect directly to databases
- Store toxic content (only hashes and counts)

## Architecture

```
Input Content
     │
     ▼
┌─────────────────┐
│  Pattern Match  │  Pattern-based detection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Confidence     │  Calculate confidence scores
│  Scoring        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Risk Score     │  Aggregate risk assessment
│  Calculation    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  DecisionEvent  │  Persist to ruvector-service
│  Emission       │
└─────────────────┘
```

## Persistence

All persistence is handled through ruvector-service. The agent:

- **Persists:** Content hash (SHA-256), detection metadata, category counts
- **Never persists:** Raw content, actual toxic text, matched phrases

## Performance

| Metric | Target |
|--------|--------|
| Latency p50 | < 5ms |
| Latency p99 | < 20ms |
| Memory usage | < 50MB |
| False positive rate | < 3% |
| True positive rate | > 95% |

## License

MIT
