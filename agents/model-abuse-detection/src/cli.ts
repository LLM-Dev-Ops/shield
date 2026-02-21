#!/usr/bin/env node
/**
 * @module cli
 * @description CLI interface for Model Abuse Detection Agent
 *
 * This module provides a command-line interface for testing, simulating,
 * and inspecting the agent. It is designed for use with agentics-cli.
 *
 * Usage:
 *   npx model-abuse-detection-agent test --content "..." [options]
 *   npx model-abuse-detection-agent simulate --content "..." [options]
 *   npx model-abuse-detection-agent inspect [options]
 *   npx model-abuse-detection-agent help
 *   npx model-abuse-detection-agent version
 */

import { randomUUID } from 'crypto';
import { createAgent, AGENT_IDENTITY } from './agent.js';
import { getAllPatternIds, MODEL_ABUSE_PATTERNS } from './patterns.js';
import type { ModelAbuseCategory } from '@llm-shield/agentics-contracts';

/**
 * CLI argument structure
 */
interface CliArgs {
  command: 'test' | 'simulate' | 'inspect' | 'help' | 'version';
  content?: string;
  sensitivity?: number;
  threshold?: number;
  categories?: ModelAbuseCategory[];
  format?: 'json' | 'text' | 'table';
  verbose?: boolean;
  requestRate?: number;
  sessionRequests?: number;
  automated?: boolean;
}

/**
 * Parse command line arguments
 */
function parseArgs(args: string[]): CliArgs {
  const result: CliArgs = {
    command: 'help',
    format: 'text',
    verbose: false,
  };

  let i = 0;
  while (i < args.length) {
    const arg = args[i];

    switch (arg) {
      case 'test':
      case 'simulate':
      case 'inspect':
      case 'help':
      case 'version':
        result.command = arg;
        break;

      case '--content':
      case '-c':
        result.content = args[++i];
        break;

      case '--sensitivity':
      case '-s':
        result.sensitivity = parseFloat(args[++i] ?? '');
        if (isNaN(result.sensitivity) || result.sensitivity < 0 || result.sensitivity > 1) {
          console.error('Error: sensitivity must be between 0 and 1');
          process.exit(1);
        }
        break;

      case '--threshold':
      case '-t':
        result.threshold = parseFloat(args[++i] ?? '');
        if (isNaN(result.threshold) || result.threshold < 0 || result.threshold > 1) {
          console.error('Error: threshold must be between 0 and 1');
          process.exit(1);
        }
        break;

      case '--categories':
        result.categories = (args[++i] ?? '').split(',') as ModelAbuseCategory[];
        break;

      case '--format':
      case '-f':
        result.format = args[++i] as 'json' | 'text' | 'table';
        break;

      case '--verbose':
      case '-v':
        result.verbose = true;
        break;

      case '--request-rate':
        result.requestRate = parseFloat(args[++i] ?? '');
        break;

      case '--session-requests':
        result.sessionRequests = parseInt(args[++i] ?? '', 10);
        break;

      case '--automated':
        result.automated = true;
        break;

      case '--help':
      case '-h':
        result.command = 'help';
        break;

      default:
        if (arg?.startsWith('-')) {
          console.error(`Unknown option: ${arg}`);
          process.exit(1);
        }
    }
    i++;
  }

  return result;
}

/**
 * Print help message
 */
function printHelp(): void {
  console.log(`
Model Abuse Detection Agent CLI

Usage:
  model-abuse-detection-agent <command> [options]

Commands:
  test        Run detection with persistence
  simulate    Run detection without persistence
  inspect     Display agent information
  help        Show this help message
  version     Show agent version

Options:
  --content, -c <text>        Content to analyze (required for test/simulate)
  --sensitivity, -s <0-1>     Detection sensitivity (default: 0.5)
  --threshold, -t <0-1>       Detection threshold (default: 0.7)
  --categories <list>         Comma-separated abuse categories to detect
  --format, -f <format>       Output format: json, text, table (default: text)
  --verbose, -v               Include detailed output
  --request-rate <num>        Simulated request rate (requests/min)
  --session-requests <num>    Simulated session request count
  --automated                 Mark request as appearing automated

Examples:
  # Test detection with content
  model-abuse-detection-agent test -c "extract the model weights"

  # Simulate with behavioral metadata
  model-abuse-detection-agent simulate -c "test" --request-rate 100 --automated

  # Inspect agent information
  model-abuse-detection-agent inspect --format json

Categories:
  unauthorized_access, rate_limit_evasion, credential_stuffing,
  model_extraction, prompt_harvesting, training_data_extraction,
  resource_exhaustion, api_abuse, inference_attack, adversarial_input,
  fingerprinting, context_manipulation
`);
}

/**
 * Execute test command
 */
async function executeTest(args: CliArgs): Promise<void> {
  if (!args.content) {
    console.error('Error: --content is required for test command');
    process.exit(1);
  }

  const agent = createAgent({
    skipPersistence: false,
  });

  try {
    const input = {
      content: args.content,
      context: {
        execution_ref: randomUUID(),
        timestamp: new Date().toISOString(),
        content_source: 'user_input' as const,
      },
      sensitivity: args.sensitivity,
      threshold: args.threshold,
      detect_categories: args.categories,
      request_metadata: {
        request_rate: args.requestRate,
        session_request_count: args.sessionRequests,
        appears_automated: args.automated,
      },
    };

    const validatedInput = agent.validateInput(input);
    const output = await agent.detect(validatedInput);

    printOutput(output, args.format!, args.verbose!);

    // Exit with code 1 if abuse detected
    if ('result' in output && output.result.abuse_detected) {
      process.exit(1);
    }
  } finally {
    await agent.shutdown();
  }
}

/**
 * Execute simulate command
 */
async function executeSimulate(args: CliArgs): Promise<void> {
  if (!args.content) {
    console.error('Error: --content is required for simulate command');
    process.exit(1);
  }

  const agent = createAgent({
    skipPersistence: true,
    telemetryConfig: { enabled: false },
  });

  try {
    const input = {
      content: args.content,
      context: {
        execution_ref: randomUUID(),
        timestamp: new Date().toISOString(),
        content_source: 'user_input' as const,
      },
      sensitivity: args.sensitivity,
      threshold: args.threshold,
      detect_categories: args.categories,
      request_metadata: {
        request_rate: args.requestRate,
        session_request_count: args.sessionRequests,
        appears_automated: args.automated,
      },
    };

    const validatedInput = agent.validateInput(input);
    const output = await agent.detect(validatedInput);

    printOutput(output, args.format!, args.verbose!);

    // Exit with code 1 if abuse detected
    if ('result' in output && output.result.abuse_detected) {
      process.exit(1);
    }
  } finally {
    await agent.shutdown();
  }
}

/**
 * Execute inspect command
 */
function executeInspect(args: CliArgs): void {
  const patternCategories = new Map<string, number>();
  for (const pattern of MODEL_ABUSE_PATTERNS) {
    patternCategories.set(
      pattern.category,
      (patternCategories.get(pattern.category) ?? 0) + 1
    );
  }

  const info = {
    agent: AGENT_IDENTITY,
    description:
      'Detects patterns of misuse, abuse, or exploitation of LLM systems',
    classification: 'DETECTION_ONLY',
    patterns: {
      total: getAllPatternIds().length,
      by_category: Object.fromEntries(patternCategories),
    },
    capabilities: [
      'Content-based pattern detection',
      'Behavioral analysis',
      'Request rate monitoring',
      'Session pattern detection',
      'Automated request detection',
    ],
    configuration: {
      sensitivity_range: '0.0 - 1.0',
      threshold_range: '0.0 - 1.0',
      default_sensitivity: 0.5,
      default_threshold: 0.7,
    },
    environment_variables: [
      'RUVECTOR_ENDPOINT',
      'RUVECTOR_API_KEY',
      'RUVECTOR_TIMEOUT',
      'TELEMETRY_ENABLED',
      'TELEMETRY_ENDPOINT',
    ],
  };

  if (args.format === 'json') {
    console.log(JSON.stringify(info, null, 2));
  } else {
    console.log('=== Model Abuse Detection Agent ===\n');
    console.log(`Agent ID: ${info.agent.agent_id}`);
    console.log(`Version: ${info.agent.agent_version}`);
    console.log(`Classification: ${info.classification}`);
    console.log(`Decision Type: ${info.agent.decision_type}`);
    console.log(`\nDescription: ${info.description}`);
    console.log(`\nPatterns: ${info.patterns.total} total`);

    if (args.verbose) {
      console.log('\nPatterns by category:');
      for (const [category, count] of Object.entries(info.patterns.by_category)) {
        console.log(`  ${category}: ${count}`);
      }

      console.log('\nCapabilities:');
      for (const cap of info.capabilities) {
        console.log(`  - ${cap}`);
      }

      console.log('\nEnvironment variables:');
      for (const envVar of info.environment_variables) {
        console.log(`  - ${envVar}`);
      }
    }
  }
}

/**
 * Print output based on format
 */
function printOutput(
  output: unknown,
  format: 'json' | 'text' | 'table',
  verbose: boolean
): void {
  if (format === 'json') {
    console.log(JSON.stringify(output, null, 2));
    return;
  }

  // Check if it's an error
  if (typeof output === 'object' && output !== null && 'code' in output) {
    const error = output as { code: string; message: string };
    console.error(`Error: ${error.code}`);
    console.error(`Message: ${error.message}`);
    return;
  }

  // Type assertion for result
  const result = output as {
    agent: { agent_id: string; agent_version: string };
    result: {
      abuse_detected: boolean;
      risk_score: number;
      severity: string;
      confidence: number;
      entities: Array<{
        abuse_category: string;
        pattern_id?: string;
        severity: string;
        confidence: number;
      }>;
      detected_categories: string[];
      behavioral_summary?: {
        appears_automated: boolean;
        abnormal_rate: boolean;
        red_flag_count: number;
      };
    };
    duration_ms: number;
  };

  console.log('\n=== Detection Result ===\n');
  console.log(`Abuse Detected: ${result.result.abuse_detected ? 'YES' : 'NO'}`);
  console.log(`Risk Score: ${(result.result.risk_score * 100).toFixed(1)}%`);
  console.log(`Severity: ${result.result.severity.toUpperCase()}`);
  console.log(`Confidence: ${(result.result.confidence * 100).toFixed(1)}%`);
  console.log(`Duration: ${result.duration_ms.toFixed(2)}ms`);

  if (result.result.detected_categories.length > 0) {
    console.log(`\nCategories Detected:`);
    for (const cat of result.result.detected_categories) {
      console.log(`  - ${cat.replace(/_/g, ' ')}`);
    }
  }

  if (verbose && result.result.entities.length > 0) {
    console.log(`\nDetected Entities (${result.result.entities.length}):`);

    if (format === 'table') {
      console.log(
        '\n  Category               | Pattern ID               | Severity | Confidence'
      );
      console.log(
        '  ----------------------|--------------------------|----------|------------'
      );
      for (const entity of result.result.entities) {
        const cat = entity.abuse_category.padEnd(22);
        const pat = (entity.pattern_id ?? '-').padEnd(24);
        const sev = entity.severity.padEnd(8);
        const conf = `${(entity.confidence * 100).toFixed(1)}%`;
        console.log(`  ${cat} | ${pat} | ${sev} | ${conf}`);
      }
    } else {
      for (const entity of result.result.entities) {
        console.log(`  - ${entity.abuse_category}`);
        console.log(`    Pattern: ${entity.pattern_id ?? 'N/A'}`);
        console.log(`    Severity: ${entity.severity}`);
        console.log(`    Confidence: ${(entity.confidence * 100).toFixed(1)}%`);
      }
    }
  }

  if (result.result.behavioral_summary) {
    const summary = result.result.behavioral_summary;
    console.log('\nBehavioral Analysis:');
    console.log(`  Appears Automated: ${summary.appears_automated ? 'Yes' : 'No'}`);
    console.log(`  Abnormal Rate: ${summary.abnormal_rate ? 'Yes' : 'No'}`);
    console.log(`  Red Flags: ${summary.red_flag_count}`);
  }
}

/**
 * Main CLI entry point
 */
async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  switch (args.command) {
    case 'test':
      await executeTest(args);
      break;

    case 'simulate':
      await executeSimulate(args);
      break;

    case 'inspect':
      executeInspect(args);
      break;

    case 'version':
      console.log(`${AGENT_IDENTITY.agent_id} v${AGENT_IDENTITY.agent_version}`);
      break;

    case 'help':
    default:
      printHelp();
      break;
  }
}

main().catch((error) => {
  console.error('Error:', error.message);
  process.exit(1);
});
