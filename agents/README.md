# LLM-Shield Agents

This directory contains agent implementations for the LLM-Shield security platform.

## Architecture

All agents in this directory:

1. **Execute as Google Cloud Edge Functions** - Deployed as part of the unified LLM-Shield GCP service
2. **Are stateless at runtime** - No local persistence
3. **Persist via ruvector-service** - All decisions persisted through API calls, never direct SQL
4. **Import schemas from agentics-contracts** - Ensures contract compliance

## Available Agents

| Agent | Classification | Decision Type | Description |
|-------|----------------|---------------|-------------|
| `prompt-injection-detection` | DETECTION_ONLY | `prompt_injection_detection` | Detects prompt injection attempts |

## Agent Classifications

- **DETECTION_ONLY** - Detects threats, does not modify content
- **REDACTION** - Detects and sanitizes/redacts content
- **ENFORCEMENT** - Full enforcement: BLOCK / ALLOW / SANITIZE

## Directory Structure

```
agents/
├── contracts/                    # agentics-contracts schemas
│   ├── index.ts                 # All schema definitions
│   ├── package.json             # Package configuration
│   └── tsconfig.json            # TypeScript configuration
│
├── prompt-injection-detection/   # Prompt Injection Detection Agent
│   ├── src/
│   │   ├── agent.ts             # Main agent implementation
│   │   ├── handler.ts           # Edge Function handler
│   │   ├── patterns.ts          # Detection patterns
│   │   ├── ruvector-client.ts   # ruvector-service client
│   │   ├── telemetry.ts         # Telemetry emitter
│   │   ├── cli.ts               # CLI interface
│   │   └── index.ts             # Package exports
│   ├── tests/
│   │   └── agent.test.ts        # Unit tests
│   ├── AGENT.md                 # Agent contract documentation
│   ├── VERIFICATION.md          # Verification checklist
│   ├── package.json             # Package configuration
│   └── tsconfig.json            # TypeScript configuration
│
└── README.md                     # This file
```

## Creating a New Agent

1. Create agent directory: `agents/<agent-name>/`
2. Define contract in `AGENT.md` following the template
3. Implement agent using schemas from `@llm-shield/agentics-contracts`
4. Create Edge Function handler
5. Add CLI support
6. Write tests
7. Complete verification checklist

## Agent Requirements

Every LLM-Shield agent MUST:

1. Import schemas exclusively from `@llm-shield/agentics-contracts`
2. Validate all inputs and outputs against contracts
3. Emit telemetry compatible with LLM-Observatory
4. Emit exactly ONE DecisionEvent to ruvector-service per invocation
5. Expose a CLI-invokable endpoint (test / inspect / simulate)
6. Be deployable as a Google Edge Function
7. Return deterministic, machine-readable output

## DecisionEvent Schema

Every agent must emit a DecisionEvent with:

```typescript
{
  agent_id: string;           // Agent identifier
  agent_version: string;      // Semantic version
  decision_type: string;      // Type of decision
  inputs_hash: string;        // SHA-256 hash of input (NOT raw content)
  outputs: object;            // Sanitized outputs
  confidence: number;         // Detection confidence (0-1)
  constraints_applied: [];    // Policy references
  execution_ref: string;      // UUID for tracing
  timestamp: string;          // UTC ISO 8601
  duration_ms: number;        // Execution time
}
```

## CLI Usage

All agents support standard CLI commands:

```bash
# Test mode - execute detection
npx shield-agent <agent-name> test --content "..."

# Simulate mode - no persistence
npx shield-agent <agent-name> simulate --content "..."

# Inspect mode - agent information
npx shield-agent <agent-name> inspect --verbose

# Help
npx shield-agent <agent-name> help
```

## Development

```bash
# Install dependencies
cd agents/prompt-injection-detection
npm install

# Build
npm run build

# Run tests
npm test

# Type check
npm run typecheck
```

## Integration

Agents can be invoked by:

- **LLM-Edge-Agent bundles** - Via HTTP POST to `/detect`
- **LLM-Core bundles** - Via HTTP POST to `/detect`
- **CLI** - Via `shield-agent` command
- **Direct HTTP** - Via Edge Function URL

Agents NEVER invoke:

- Other agents
- External services (except ruvector-service)
- Databases directly
