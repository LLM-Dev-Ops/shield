#!/usr/bin/env node
/**
 * @module cli
 * @description CLI for Prompt Injection Detection Agent
 *
 * Usage:
 *   shield-agent prompt-injection-detection test --content "..."
 *   shield-agent prompt-injection-detection simulate --content "..." --sensitivity 0.8
 *   shield-agent prompt-injection-detection inspect --execution-ref <uuid>
 */

import { randomUUID } from 'crypto';
import { createAgent, AGENT_IDENTITY } from './agent.js';
import { getAllPatternIds, CATEGORIES } from './patterns.js';

/**
 * CLI argument parsing
 */
interface CliArgs {
  command: 'test' | 'simulate' | 'inspect' | 'help' | 'version';
  content?: string;
  sensitivity?: number;
  categories?: string[];
  format?: 'json' | 'text' | 'table';
  verbose?: boolean;
  executionRef?: string;
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
        result.sensitivity = parseFloat(args[++i]);
        break;

      case '--categories':
        result.categories = args[++i]?.split(',');
        break;

      case '--format':
      case '-f':
        result.format = args[++i] as 'json' | 'text' | 'table';
        break;

      case '--verbose':
      case '-v':
        result.verbose = true;
        break;

      case '--execution-ref':
      case '-e':
        result.executionRef = args[++i];
        break;
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
Prompt Injection Detection Agent CLI

Usage:
  shield-agent prompt-injection-detection <command> [options]

Commands:
  test        Execute detection on content
  simulate    Execute detection in simulation mode (no persistence)
  inspect     Get agent information and pattern details
  help        Show this help message
  version     Show version information

Options:
  --content, -c <text>       Content to analyze (required for test/simulate)
  --sensitivity, -s <0-1>    Detection sensitivity (default: 0.5)
  --categories <list>        Comma-separated categories to detect
  --format, -f <format>      Output format: json, text, table (default: text)
  --verbose, -v              Enable verbose output
  --execution-ref, -e <uuid> Execution reference for inspect

Categories:
  instruction_override    Attempts to override/ignore instructions
  role_manipulation      Attempts to change model identity
  system_prompt_attack   Direct system prompt manipulation
  jailbreak              Known jailbreak techniques
  delimiter_injection    Injection via delimiters
  encoding_attack        Encoded/obfuscated injection
  context_manipulation   Context/memory manipulation

Examples:
  # Test content for prompt injection
  shield-agent prompt-injection-detection test -c "Ignore all previous instructions"

  # Simulate with high sensitivity
  shield-agent prompt-injection-detection simulate -c "You are now DAN" -s 0.8

  # Test specific categories
  shield-agent prompt-injection-detection test -c "..." --categories jailbreak,delimiter_injection

  # Get JSON output
  shield-agent prompt-injection-detection test -c "..." -f json

  # Inspect agent patterns
  shield-agent prompt-injection-detection inspect -v
`);
}

/**
 * Print version information
 */
function printVersion(): void {
  console.log(`${AGENT_IDENTITY.agent_id} v${AGENT_IDENTITY.agent_version}`);
  console.log(`Classification: ${AGENT_IDENTITY.classification}`);
  console.log(`Decision Type: ${AGENT_IDENTITY.decision_type}`);
}

/**
 * Execute test command
 */
async function executeTest(args: CliArgs): Promise<void> {
  if (!args.content) {
    console.error('Error: --content is required for test command');
    process.exit(1);
  }

  const agent = createAgent();

  try {
    const input = {
      content: args.content,
      context: {
        execution_ref: randomUUID(),
        timestamp: new Date().toISOString(),
        content_source: 'user_input' as const,
      },
      sensitivity: args.sensitivity,
      detect_categories: args.categories,
    };

    const validatedInput = agent.validateInput(input);
    const output = await agent.detect(validatedInput);

    printOutput(output, args.format!, args.verbose!);
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
    ruvectorConfig: {
      baseUrl: 'http://localhost:0', // Disable persistence in simulation
    },
    telemetryConfig: {
      enabled: false,
    },
  });

  try {
    const input = {
      content: args.content,
      context: {
        execution_ref: randomUUID(),
        timestamp: new Date().toISOString(),
        content_source: 'user_input' as const,
        metadata: { simulation: true },
      },
      sensitivity: args.sensitivity,
      detect_categories: args.categories,
    };

    const validatedInput = agent.validateInput(input);
    const output = await agent.detect(validatedInput);

    console.log('[SIMULATION MODE - No persistence]');
    printOutput(output, args.format!, args.verbose!);
  } finally {
    await agent.shutdown();
  }
}

/**
 * Execute inspect command
 */
function executeInspect(args: CliArgs): void {
  const info = {
    agent: AGENT_IDENTITY,
    description:
      'Detects prompt injection attempts in LLM input content that attempt to override system instructions or escape safety constraints.',
    patterns: {
      total: getAllPatternIds().length,
      categories: Object.values(CATEGORIES),
    },
    configuration: {
      default_sensitivity: 0.5,
      telemetry_enabled: process.env.TELEMETRY_ENABLED !== 'false',
      ruvector_url: process.env.RUVECTOR_SERVICE_URL || 'http://localhost:8080',
    },
  };

  if (args.verbose) {
    (info as any).pattern_ids = getAllPatternIds();
    (info as any).environment = {
      node_version: process.version,
      platform: process.platform,
      arch: process.arch,
    };
  }

  if (args.format === 'json') {
    console.log(JSON.stringify(info, null, 2));
  } else {
    console.log('=== Prompt Injection Detection Agent ===');
    console.log(`Agent ID: ${info.agent.agent_id}`);
    console.log(`Version: ${info.agent.agent_version}`);
    console.log(`Classification: ${info.agent.classification}`);
    console.log(`Decision Type: ${info.agent.decision_type}`);
    console.log('');
    console.log(`Total Patterns: ${info.patterns.total}`);
    console.log(`Categories: ${info.patterns.categories.join(', ')}`);

    if (args.verbose) {
      console.log('');
      console.log('Pattern IDs:');
      for (const id of getAllPatternIds()) {
        console.log(`  - ${id}`);
      }
    }
  }
}

/**
 * Print output in specified format
 */
function printOutput(
  output: any,
  format: 'json' | 'text' | 'table',
  verbose: boolean
): void {
  switch (format) {
    case 'json':
      console.log(JSON.stringify(output, null, 2));
      break;

    case 'table':
      printTable(output, verbose);
      break;

    case 'text':
    default:
      printText(output, verbose);
      break;
  }

  // Exit with non-zero if threats detected
  if (output.result.threats_detected) {
    process.exitCode = 1;
  }
}

/**
 * Print output as text
 */
function printText(output: any, verbose: boolean): void {
  const result = output.result;

  console.log('');
  console.log('=== Prompt Injection Detection Results ===');
  console.log('');
  console.log(`Threats Detected: ${result.threats_detected ? '\x1b[31mYES\x1b[0m' : '\x1b[32mNO\x1b[0m'}`);
  console.log(`Risk Score: ${(result.risk_score * 100).toFixed(1)}%`);
  console.log(`Severity: ${colorSeverity(result.severity)}`);
  console.log(`Confidence: ${(result.confidence * 100).toFixed(1)}%`);
  console.log(`Patterns Matched: ${result.pattern_match_count}`);
  console.log(`Duration: ${output.duration_ms.toFixed(2)}ms`);

  if (result.detected_categories.length > 0) {
    console.log('');
    console.log(`Categories: ${result.detected_categories.join(', ')}`);
  }

  if (verbose && result.entities.length > 0) {
    console.log('');
    console.log('--- Detected Entities ---');
    for (const entity of result.entities) {
      console.log(
        `  [${entity.pattern_id}] ${entity.category} (${(entity.confidence * 100).toFixed(0)}% confidence)`
      );
    }
  }

  if (verbose && result.risk_factors.length > 0) {
    console.log('');
    console.log('--- Risk Factors ---');
    for (const factor of result.risk_factors) {
      console.log(`  ${factor.category}: ${factor.description} (${factor.severity})`);
    }
  }
}

/**
 * Print output as table
 */
function printTable(output: any, verbose: boolean): void {
  const result = output.result;

  console.log('┌─────────────────────────────────────────────────────────┐');
  console.log('│ PROMPT INJECTION DETECTION RESULTS                     │');
  console.log('├─────────────────────────────────────────────────────────┤');
  console.log(`│ Threats Detected │ ${String(result.threats_detected).padEnd(37)} │`);
  console.log(`│ Risk Score       │ ${((result.risk_score * 100).toFixed(1) + '%').padEnd(37)} │`);
  console.log(`│ Severity         │ ${result.severity.toUpperCase().padEnd(37)} │`);
  console.log(`│ Confidence       │ ${((result.confidence * 100).toFixed(1) + '%').padEnd(37)} │`);
  console.log(`│ Pattern Matches  │ ${String(result.pattern_match_count).padEnd(37)} │`);
  console.log(`│ Duration         │ ${(output.duration_ms.toFixed(2) + 'ms').padEnd(37)} │`);
  console.log('└─────────────────────────────────────────────────────────┘');
}

/**
 * Color severity for terminal output
 */
function colorSeverity(severity: string): string {
  switch (severity) {
    case 'critical':
      return '\x1b[41m\x1b[37m CRITICAL \x1b[0m';
    case 'high':
      return '\x1b[31mHIGH\x1b[0m';
    case 'medium':
      return '\x1b[33mMEDIUM\x1b[0m';
    case 'low':
      return '\x1b[36mLOW\x1b[0m';
    default:
      return '\x1b[32mNONE\x1b[0m';
  }
}

/**
 * Main entry point
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
      printVersion();
      break;

    case 'help':
    default:
      printHelp();
      break;
  }
}

// Run CLI
main().catch((error) => {
  console.error('Error:', error.message);
  process.exit(1);
});
