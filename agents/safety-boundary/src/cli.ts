#!/usr/bin/env node
/**
 * @module cli
 * @description CLI interface for Safety Boundary Agent
 *
 * Usage:
 *   npx ts-node src/cli.ts test "content to test"
 *   npx ts-node src/cli.ts simulate "content to simulate"
 *   npx ts-node src/cli.ts inspect
 */

import { randomUUID } from 'crypto';
import {
  SafetyBoundaryAgent,
  createAgent,
  AGENT_IDENTITY,
} from './agent.js';
import {
  SAFETY_PATTERNS,
  SAFETY_CATEGORIES,
  getPatternCountByCategory,
} from './patterns.js';

/**
 * CLI mode type
 */
type CliMode = 'test' | 'simulate' | 'inspect';

/**
 * CLI options
 */
interface CliOptions {
  mode: CliMode;
  content: string;
  sensitivity?: number;
  categories?: string[];
  defaultAction?: 'BLOCK' | 'ALLOW';
  verbose?: boolean;
  format?: 'json' | 'text' | 'table';
}

/**
 * Parse command line arguments
 */
function parseArgs(args: string[]): CliOptions {
  const mode = (args[0] || 'test') as CliMode;
  const content = args[1] || '';

  const options: CliOptions = {
    mode,
    content,
    verbose: args.includes('--verbose') || args.includes('-v'),
    format: 'text',
  };

  // Parse format
  const formatIdx = args.findIndex((a) => a === '--format' || a === '-f');
  if (formatIdx !== -1 && args[formatIdx + 1]) {
    options.format = args[formatIdx + 1] as 'json' | 'text' | 'table';
  }

  // Parse sensitivity
  const sensitivityIdx = args.findIndex((a) => a === '--sensitivity' || a === '-s');
  if (sensitivityIdx !== -1 && args[sensitivityIdx + 1]) {
    options.sensitivity = parseFloat(args[sensitivityIdx + 1]!);
  }

  // Parse default action
  const actionIdx = args.findIndex((a) => a === '--action' || a === '-a');
  if (actionIdx !== -1 && args[actionIdx + 1]) {
    options.defaultAction = args[actionIdx + 1]!.toUpperCase() as 'BLOCK' | 'ALLOW';
  }

  // Parse categories
  const categoriesIdx = args.findIndex((a) => a === '--categories' || a === '-c');
  if (categoriesIdx !== -1 && args[categoriesIdx + 1]) {
    options.categories = args[categoriesIdx + 1]!.split(',');
  }

  return options;
}

/**
 * Execute test mode
 */
async function executeTest(
  agent: SafetyBoundaryAgent,
  options: CliOptions
): Promise<void> {
  const input = {
    content: options.content,
    context: {
      execution_ref: randomUUID(),
      timestamp: new Date().toISOString(),
      content_source: 'user_input' as const,
    },
    sensitivity: options.sensitivity ?? 0.7,
    enforce_categories: options.categories,
    default_action: options.defaultAction ?? 'BLOCK',
  };

  const validatedInput = agent.validateInput(input);
  const output = await agent.enforce(validatedInput);

  printOutput(output, options.format ?? 'text', options.verbose ?? false);
}

/**
 * Execute simulate mode
 */
async function executeSimulate(
  agent: SafetyBoundaryAgent,
  options: CliOptions
): Promise<void> {
  const input = {
    content: options.content,
    context: {
      execution_ref: randomUUID(),
      timestamp: new Date().toISOString(),
      content_source: 'user_input' as const,
      metadata: { simulation: true },
    },
    sensitivity: options.sensitivity ?? 0.7,
    enforce_categories: options.categories,
    default_action: options.defaultAction ?? 'BLOCK',
  };

  const validatedInput = agent.validateInput(input);
  const output = await agent.enforce(validatedInput);

  console.log('[SIMULATION MODE - No persistence]');
  console.log('');
  printOutput(output, options.format ?? 'text', options.verbose ?? false);
}

/**
 * Execute inspect mode
 */
function executeInspect(options: CliOptions): void {
  const inspectData = {
    agent: AGENT_IDENTITY,
    patterns: {
      total: SAFETY_PATTERNS.length,
      by_category: getPatternCountByCategory(),
    },
    categories: SAFETY_CATEGORIES,
    configuration: {
      default_sensitivity: 0.7,
      default_action: 'BLOCK',
      min_enforcement_confidence: 0.8,
      telemetry_enabled: process.env.TELEMETRY_ENABLED !== 'false',
      ruvector_url: process.env.RUVECTOR_SERVICE_URL || 'http://localhost:8080',
    },
  };

  if (options.format === 'json') {
    console.log(JSON.stringify(inspectData, null, 2));
  } else {
    console.log('=== Safety Boundary Agent Information ===');
    console.log('');
    console.log(`Agent ID: ${inspectData.agent.agent_id}`);
    console.log(`Version: ${inspectData.agent.agent_version}`);
    console.log(`Classification: ${inspectData.agent.classification}`);
    console.log(`Decision Type: ${inspectData.agent.decision_type}`);
    console.log('');
    console.log('Patterns:');
    console.log(`  Total: ${inspectData.patterns.total}`);
    for (const [category, count] of Object.entries(inspectData.patterns.by_category)) {
      console.log(`  ${category}: ${count}`);
    }
    console.log('');
    console.log('Categories:');
    for (const category of inspectData.categories) {
      console.log(`  - ${category}`);
    }
    console.log('');
    console.log('Configuration:');
    console.log(`  Default Sensitivity: ${inspectData.configuration.default_sensitivity}`);
    console.log(`  Default Action: ${inspectData.configuration.default_action}`);
    console.log(`  Min Enforcement Confidence: ${inspectData.configuration.min_enforcement_confidence}`);
    console.log(`  Telemetry: ${inspectData.configuration.telemetry_enabled ? 'enabled' : 'disabled'}`);
    console.log(`  RuVector URL: ${inspectData.configuration.ruvector_url}`);
  }
}

/**
 * Print output in specified format
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

  const result = output as { result: Record<string, unknown>; duration_ms: number };

  if (format === 'table') {
    const allowed = result.result.allowed as boolean;
    const decisionEmoji = allowed ? '✓' : '✗';
    const decisionText = allowed ? 'ALLOWED' : 'BLOCKED';

    console.log('┌─────────────────────────────────────────────────────────┐');
    console.log('│ SAFETY BOUNDARY ENFORCEMENT RESULTS                    │');
    console.log('├─────────────────────────────────────────────────────────┤');
    console.log(`│ Decision         │ ${(decisionEmoji + ' ' + decisionText).padEnd(37)} │`);
    console.log(`│ Action           │ ${String(result.result.action).padEnd(37)} │`);
    console.log(`│ Violations       │ ${String((result.result.violations as unknown[]).length).padEnd(37)} │`);
    console.log(`│ Risk Score       │ ${(((result.result.risk_score as number) * 100).toFixed(1) + '%').padEnd(37)} │`);
    console.log(`│ Severity         │ ${String(result.result.severity).toUpperCase().padEnd(37)} │`);
    console.log(`│ Confidence       │ ${(((result.result.confidence as number) * 100).toFixed(1) + '%').padEnd(37)} │`);
    console.log(`│ Duration         │ ${(result.duration_ms.toFixed(2) + 'ms').padEnd(37)} │`);
    console.log('└─────────────────────────────────────────────────────────┘');
    return;
  }

  // Text format
  const allowed = result.result.allowed as boolean;
  console.log('=== Safety Boundary Enforcement Results ===');
  console.log('');
  console.log(`Decision: ${allowed ? 'ALLOWED' : 'BLOCKED'}`);
  console.log(`Action: ${result.result.action}`);
  console.log(`Violations Detected: ${result.result.violations_detected ? 'YES' : 'NO'}`);
  console.log(`Risk Score: ${((result.result.risk_score as number) * 100).toFixed(1)}%`);
  console.log(`Severity: ${String(result.result.severity).toUpperCase()}`);
  console.log(`Confidence: ${((result.result.confidence as number) * 100).toFixed(1)}%`);
  console.log(`Pattern Matches: ${result.result.pattern_match_count}`);
  console.log(`Duration: ${result.duration_ms.toFixed(2)}ms`);
  console.log('');
  console.log(`Reason: ${result.result.decision_reason}`);

  const violations = result.result.violations as Array<{
    pattern_id: string;
    category: string;
    description: string;
    confidence: number;
    severity: string;
  }>;

  if (verbose && violations.length > 0) {
    console.log('');
    console.log('--- Violations ---');
    for (const violation of violations) {
      console.log(
        `  [${violation.pattern_id}] ${violation.category} - ${violation.description}`
      );
      console.log(
        `    Confidence: ${(violation.confidence * 100).toFixed(0)}%, Severity: ${violation.severity}`
      );
    }
  }
}

/**
 * Print usage information
 */
function printUsage(): void {
  console.log(`
Safety Boundary Agent CLI

Usage:
  npx ts-node src/cli.ts <mode> [content] [options]

Modes:
  test      Execute enforcement with persistence
  simulate  Execute enforcement without persistence
  inspect   Display agent information

Options:
  -s, --sensitivity <value>    Set sensitivity (0.0-1.0, default: 0.7)
  -a, --action <BLOCK|ALLOW>   Set default action (default: BLOCK)
  -c, --categories <list>      Comma-separated categories to check
  -f, --format <format>        Output format: json, text, table (default: text)
  -v, --verbose                Enable verbose output
  -h, --help                   Show this help message

Examples:
  npx ts-node src/cli.ts test "Test content here"
  npx ts-node src/cli.ts test "Content" -s 0.9 -a BLOCK -v
  npx ts-node src/cli.ts simulate "Content" -f json
  npx ts-node src/cli.ts inspect -f json
`);
}

/**
 * Main entry point
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes('-h') || args.includes('--help')) {
    printUsage();
    process.exit(0);
  }

  const options = parseArgs(args);

  if (!['test', 'simulate', 'inspect'].includes(options.mode)) {
    console.error(`Unknown mode: ${options.mode}`);
    printUsage();
    process.exit(1);
  }

  if (options.mode !== 'inspect' && !options.content) {
    console.error('Content is required for test and simulate modes');
    printUsage();
    process.exit(1);
  }

  const agent = createAgent();

  try {
    switch (options.mode) {
      case 'test':
        await executeTest(agent, options);
        break;
      case 'simulate':
        await executeSimulate(agent, options);
        break;
      case 'inspect':
        executeInspect(options);
        break;
    }
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  } finally {
    await agent.shutdown();
  }
}

// Run if executed directly
main().catch(console.error);
