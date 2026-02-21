/**
 * @module secrets-leakage-detection/cli
 * @description CLI commands for Secrets Leakage Detection Agent
 *
 * Supports three modes:
 * - test: Validate agent functionality with sample input
 * - simulate: Run detection with custom configuration
 * - inspect: Retrieve detection result by execution reference
 */

import { randomUUID } from 'crypto';
import { handleDetection } from './handler.js';
import { RuVectorClient, createClientFromEnv } from './ruvector-client.js';
import {
  CliMode,
  CliInvocation,
  SecretsLeakageDetectionInput,
  type SecretTypeCategory,
} from '@llm-shield/agentics-contracts';

/**
 * CLI argument parser result
 */
interface ParsedArgs {
  mode: CliMode;
  content?: string;
  executionRef?: string;
  sensitivity?: number;
  categories?: SecretTypeCategory[];
  entropyDetection?: boolean;
  entropyThreshold?: number;
  format: 'json' | 'text' | 'table';
  verbose: boolean;
}

/**
 * Parse CLI arguments
 */
function parseArgs(args: string[]): ParsedArgs {
  const result: ParsedArgs = {
    mode: 'test',
    format: 'json',
    verbose: false,
  };

  let i = 0;
  while (i < args.length) {
    const arg = args[i];

    if (arg === 'test' || arg === 'simulate' || arg === 'inspect') {
      result.mode = arg as CliMode;
    } else if (arg === '--content' && i + 1 < args.length) {
      result.content = args[++i];
    } else if (arg === '--execution-ref' && i + 1 < args.length) {
      result.executionRef = args[++i];
    } else if (arg === '--sensitivity' && i + 1 < args.length) {
      result.sensitivity = parseFloat(args[++i]);
    } else if (arg === '--categories' && i + 1 < args.length) {
      result.categories = args[++i].split(',') as SecretTypeCategory[];
    } else if (arg === '--entropy-detection') {
      const next = args[i + 1];
      if (next === 'true' || next === 'false') {
        result.entropyDetection = next === 'true';
        i++;
      } else {
        result.entropyDetection = true;
      }
    } else if (arg === '--entropy-threshold' && i + 1 < args.length) {
      result.entropyThreshold = parseFloat(args[++i]);
    } else if (arg === '--format' && i + 1 < args.length) {
      result.format = args[++i] as 'json' | 'text' | 'table';
    } else if (arg === '--verbose' || arg === '-v') {
      result.verbose = true;
    }

    i++;
  }

  return result;
}

/**
 * Format output as text
 */
function formatAsText(result: unknown, verbose: boolean): string {
  const output = result as Record<string, unknown>;

  if ('code' in output) {
    return `Error: ${output.code}\n${output.message}`;
  }

  const agent = output.agent as { agent_id: string; agent_version: string };
  const detection = output.result as Record<string, unknown>;
  const lines: string[] = [];

  lines.push(`Agent: ${agent.agent_id} v${agent.agent_version}`);
  lines.push(`Threats Detected: ${detection.threats_detected ? 'YES' : 'NO'}`);
  lines.push(`Risk Score: ${(detection.risk_score as number).toFixed(3)}`);
  lines.push(`Severity: ${detection.severity}`);
  lines.push(`Confidence: ${(detection.confidence as number).toFixed(3)}`);
  lines.push(`Entities Found: ${detection.pattern_match_count}`);

  const categories = detection.detected_categories as string[];
  if (categories.length > 0) {
    lines.push(`Categories: ${categories.join(', ')}`);
  }

  if (verbose) {
    lines.push(`Duration: ${(output.duration_ms as number).toFixed(2)}ms`);

    const entities = detection.entities as Array<Record<string, unknown>>;
    if (entities.length > 0) {
      lines.push('\nDetected Entities:');
      for (const entity of entities) {
        lines.push(
          `  - [${entity.severity}] ${entity.secret_type} at ${entity.start}-${entity.end} (${(entity.confidence as number).toFixed(2)} confidence)${entity.entropy_based ? ' [entropy]' : ''}`
        );
        if (entity.redacted_preview) {
          lines.push(`    Preview: ${entity.redacted_preview}`);
        }
      }
    }

    const factors = detection.risk_factors as Array<Record<string, unknown>>;
    if (factors.length > 0) {
      lines.push('\nRisk Factors:');
      for (const factor of factors) {
        lines.push(`  - ${factor.description} (${factor.severity})`);
      }
    }
  }

  return lines.join('\n');
}

/**
 * Format output as table
 */
function formatAsTable(result: unknown): string {
  const output = result as Record<string, unknown>;

  if ('code' in output) {
    return `| Error | ${output.code} | ${output.message} |`;
  }

  const detection = output.result as Record<string, unknown>;
  const entities = detection.entities as Array<Record<string, unknown>>;

  const lines: string[] = [];
  lines.push('| Type | Severity | Confidence | Preview |');
  lines.push('|------|----------|------------|---------|');

  for (const entity of entities) {
    lines.push(
      `| ${entity.secret_type} | ${entity.severity} | ${(entity.confidence as number).toFixed(2)} | ${entity.redacted_preview || 'N/A'} |`
    );
  }

  if (entities.length === 0) {
    lines.push('| No secrets detected | - | - | - |');
  }

  return lines.join('\n');
}

/**
 * Run test mode
 */
async function runTest(args: ParsedArgs): Promise<string> {
  if (!args.content) {
    throw new Error('--content is required for test mode');
  }

  const input: SecretsLeakageDetectionInput = {
    content: args.content,
    context: {
      execution_ref: randomUUID(),
      timestamp: new Date().toISOString(),
      content_source: 'user_input',
    },
    sensitivity: args.sensitivity ?? 0.5,
    ...(args.categories !== undefined && { detect_categories: args.categories }),
    entropy_detection: args.entropyDetection ?? true,
    entropy_threshold: args.entropyThreshold ?? 4.5,
  };

  const result = await handleDetection(input, { skipPersistence: true });

  if (args.format === 'json') {
    return JSON.stringify(result, null, 2);
  } else if (args.format === 'table') {
    return formatAsTable(result);
  } else {
    return formatAsText(result, args.verbose);
  }
}

/**
 * Run simulate mode
 */
async function runSimulate(args: ParsedArgs): Promise<string> {
  if (!args.content) {
    throw new Error('--content is required for simulate mode');
  }

  const input: SecretsLeakageDetectionInput = {
    content: args.content,
    context: {
      execution_ref: randomUUID(),
      timestamp: new Date().toISOString(),
      content_source: 'user_input',
    },
    sensitivity: args.sensitivity ?? 0.5,
    detect_categories: args.categories,
    entropy_detection: args.entropyDetection ?? true,
    entropy_threshold: args.entropyThreshold ?? 4.5,
  };

  // Simulate mode persists to ruvector-service
  const result = await handleDetection(input);

  if (args.format === 'json') {
    return JSON.stringify(result, null, 2);
  } else if (args.format === 'table') {
    return formatAsTable(result);
  } else {
    return formatAsText(result, args.verbose);
  }
}

/**
 * Run inspect mode
 */
async function runInspect(args: ParsedArgs): Promise<string> {
  if (!args.executionRef) {
    throw new Error('--execution-ref is required for inspect mode');
  }

  const client = createClientFromEnv();
  const event = await client.getDecisionEvent(args.executionRef);

  if (!event) {
    return JSON.stringify({
      error: 'DecisionEvent not found',
      execution_ref: args.executionRef,
    }, null, 2);
  }

  if (args.format === 'json') {
    return JSON.stringify(event, null, 2);
  } else {
    const lines: string[] = [];
    lines.push(`Execution Ref: ${event.execution_ref}`);
    lines.push(`Agent: ${event.agent_id} v${event.agent_version}`);
    lines.push(`Decision Type: ${event.decision_type}`);
    lines.push(`Timestamp: ${event.timestamp}`);
    lines.push(`Duration: ${event.duration_ms}ms`);
    lines.push(`Threats Detected: ${event.outputs.threats_detected}`);
    lines.push(`Risk Score: ${event.outputs.risk_score.toFixed(3)}`);
    lines.push(`Severity: ${event.outputs.severity}`);
    lines.push(`Entity Count: ${event.outputs.entity_count}`);
    lines.push(`Categories: ${event.outputs.detected_categories.join(', ') || 'none'}`);
    return lines.join('\n');
  }
}

/**
 * Main CLI entry point
 */
export async function main(args: string[]): Promise<void> {
  try {
    const parsed = parseArgs(args);

    let output: string;

    switch (parsed.mode) {
      case 'test':
        output = await runTest(parsed);
        break;
      case 'simulate':
        output = await runSimulate(parsed);
        break;
      case 'inspect':
        output = await runInspect(parsed);
        break;
      default:
        throw new Error(`Unknown mode: ${parsed.mode}`);
    }

    console.log(output);
  } catch (error) {
    console.error('Error:', error instanceof Error ? error.message : error);
    process.exit(1);
  }
}

/**
 * CLI invocation handler (for agentics-cli integration)
 */
export async function handleCliInvocation(
  invocation: CliInvocation
): Promise<string> {
  const args: string[] = [invocation.mode];

  if (invocation.content) {
    args.push('--content', invocation.content);
  }

  if (invocation.config) {
    if (invocation.config.execution_ref) {
      args.push('--execution-ref', String(invocation.config.execution_ref));
    }
    if (invocation.config.sensitivity !== undefined) {
      args.push('--sensitivity', String(invocation.config.sensitivity));
    }
    if (invocation.config.categories) {
      args.push('--categories', String(invocation.config.categories));
    }
  }

  args.push('--format', invocation.format);

  if (invocation.verbose) {
    args.push('--verbose');
  }

  const parsed = parseArgs(args);

  switch (parsed.mode) {
    case 'test':
      return runTest(parsed);
    case 'simulate':
      return runSimulate(parsed);
    case 'inspect':
      return runInspect(parsed);
    default:
      throw new Error(`Unknown mode: ${parsed.mode}`);
  }
}

// Run if executed directly
if (typeof require !== 'undefined' && require.main === module) {
  main(process.argv.slice(2));
}
