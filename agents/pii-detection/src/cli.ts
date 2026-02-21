#!/usr/bin/env node
/**
 * PII Detection Agent CLI
 *
 * Provides command-line interface for testing, simulating, and inspecting
 * PII detection results.
 *
 * Usage:
 *   shield-agent pii-detection test --content "john@example.com"
 *   shield-agent pii-detection simulate --content "SSN: 123-45-6789"
 *   shield-agent pii-detection inspect --execution-ref <uuid>
 *
 * @module pii-detection-agent/cli
 */

import { PIIDetectionAgent } from './agent.js';
import { AGENT_IDENTITY, type PIIType, type PIICountry } from './types.js';
import { v4 as uuidv4 } from 'uuid';

/**
 * CLI output formats
 */
type OutputFormat = 'json' | 'text' | 'table';

/**
 * CLI modes
 */
type CliMode = 'test' | 'simulate' | 'inspect';

/**
 * CLI options
 */
interface CliOptions {
  mode: CliMode;
  content?: string;
  executionRef?: string;
  format: OutputFormat;
  verbose: boolean;
  sensitivity?: number;
  types?: PIIType[];
  countries?: PIICountry[];
}

/**
 * Parse command line arguments
 */
function parseArgs(args: string[]): CliOptions {
  const options: CliOptions = {
    mode: 'test',
    format: 'json',
    verbose: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case 'test':
      case 'simulate':
      case 'inspect':
        options.mode = arg;
        break;

      case '--content':
      case '-c':
        options.content = args[++i];
        break;

      case '--execution-ref':
      case '-e':
        options.executionRef = args[++i];
        break;

      case '--format':
      case '-f':
        options.format = args[++i] as OutputFormat;
        break;

      case '--verbose':
      case '-v':
        options.verbose = true;
        break;

      case '--sensitivity':
      case '-s':
        options.sensitivity = parseFloat(args[++i]);
        break;

      case '--types':
      case '-t':
        options.types = args[++i].split(',') as PIIType[];
        break;

      case '--countries':
        options.countries = args[++i].split(',') as PIICountry[];
        break;

      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
    }
  }

  return options;
}

/**
 * Print help message
 */
function printHelp(): void {
  console.log(`
PII Detection Agent CLI

Usage:
  shield-agent pii-detection <mode> [options]

Modes:
  test        Run PII detection on content
  simulate    Simulate detection with custom settings
  inspect     Inspect a previous execution

Options:
  --content, -c <text>       Content to analyze
  --execution-ref, -e <uuid> Execution reference (for inspect mode)
  --format, -f <format>      Output format: json, text, table (default: json)
  --verbose, -v              Verbose output
  --sensitivity, -s <num>    Detection sensitivity 0.0-1.0 (default: 0.5)
  --types, -t <types>        Comma-separated PII types to detect
  --countries <codes>        Comma-separated country codes (US, UK, CA, AU, EU)
  --help, -h                 Show this help message

Examples:
  shield-agent pii-detection test --content "john@example.com"
  shield-agent pii-detection simulate --content "SSN: 123-45-6789" -s 0.8
  shield-agent pii-detection inspect --execution-ref abc123

PII Types:
  email, phone, ssn, credit_card, ip_address, passport,
  drivers_license, date_of_birth, address, name
`);
}

/**
 * Run test mode
 */
async function runTest(options: CliOptions): Promise<void> {
  if (!options.content) {
    console.error('Error: --content is required for test mode');
    process.exit(1);
  }

  const agent = new PIIDetectionAgent({
    persistEvents: false, // Don't persist in test mode
    emitTelemetry: false, // Don't emit telemetry in test mode
  });

  const input = {
    content: options.content,
    context: {
      execution_ref: uuidv4(),
      timestamp: new Date().toISOString(),
      content_source: 'user_input' as const,
    },
    sensitivity: options.sensitivity ?? 0.5,
    detect_types: options.types,
    countries: options.countries,
  };

  const output = await agent.detect(input);
  formatOutput(output, options);
}

/**
 * Run simulate mode
 */
async function runSimulate(options: CliOptions): Promise<void> {
  if (!options.content) {
    console.error('Error: --content is required for simulate mode');
    process.exit(1);
  }

  const agent = new PIIDetectionAgent({
    persistEvents: false, // Don't persist in simulate mode
    emitTelemetry: false, // Don't emit telemetry in simulate mode
  });

  const input = {
    content: options.content,
    context: {
      execution_ref: uuidv4(),
      timestamp: new Date().toISOString(),
      content_source: 'user_input' as const,
    },
    sensitivity: options.sensitivity ?? 0.5,
    detect_types: options.types,
    countries: options.countries,
  };

  if (options.verbose) {
    console.log('Simulation Configuration:');
    console.log(`  Sensitivity: ${input.sensitivity}`);
    console.log(`  Types: ${input.detect_types?.join(', ') || 'all'}`);
    console.log(`  Countries: ${input.countries?.join(', ') || 'US'}`);
    console.log('');
  }

  const output = await agent.detect(input);
  formatOutput(output, options);
}

/**
 * Run inspect mode
 */
async function runInspect(options: CliOptions): Promise<void> {
  if (!options.executionRef) {
    console.error('Error: --execution-ref is required for inspect mode');
    process.exit(1);
  }

  // In a real implementation, this would query ruvector-service
  console.log(`Inspecting execution: ${options.executionRef}`);
  console.log('');
  console.log('Note: Inspect mode requires connection to ruvector-service.');
  console.log('This feature is not available in local CLI mode.');
  console.log('');
  console.log('Use the LLM-Shield API or ruvector-service client to inspect executions.');
}

/**
 * Format and print output
 */
function formatOutput(output: unknown, options: CliOptions): void {
  switch (options.format) {
    case 'json':
      console.log(JSON.stringify(output, null, 2));
      break;

    case 'text':
      formatTextOutput(output as Record<string, unknown>, options);
      break;

    case 'table':
      formatTableOutput(output as Record<string, unknown>, options);
      break;
  }
}

/**
 * Format output as text
 */
function formatTextOutput(output: Record<string, unknown>, options: CliOptions): void {
  const result = output.result as Record<string, unknown>;

  console.log('PII Detection Results');
  console.log('=====================');
  console.log('');
  console.log(`PII Detected: ${result.pii_detected ? 'Yes' : 'No'}`);
  console.log(`Risk Score: ${result.risk_score}`);
  console.log(`Severity: ${result.severity}`);
  console.log(`Confidence: ${result.confidence}`);
  console.log(`Entities Found: ${(result.entities as unknown[]).length}`);
  console.log(`Duration: ${output.duration_ms}ms`);

  if (options.verbose && (result.entities as unknown[]).length > 0) {
    console.log('');
    console.log('Detected Entities:');
    for (const entity of result.entities as Record<string, unknown>[]) {
      console.log(`  - Type: ${entity.pii_type}`);
      console.log(`    Position: ${entity.start}-${entity.end}`);
      console.log(`    Confidence: ${entity.confidence}`);
      console.log(`    Severity: ${entity.severity}`);
      console.log('');
    }
  }

  if (options.verbose && (result.detected_types as unknown[]).length > 0) {
    console.log('');
    console.log('Type Counts:');
    const typeCounts = result.type_counts as Record<string, number>;
    for (const [type, count] of Object.entries(typeCounts)) {
      console.log(`  ${type}: ${count}`);
    }
  }
}

/**
 * Format output as table
 */
function formatTableOutput(output: Record<string, unknown>, options: CliOptions): void {
  const result = output.result as Record<string, unknown>;
  const entities = result.entities as Record<string, unknown>[];

  if (entities.length === 0) {
    console.log('No PII detected.');
    return;
  }

  // Header
  console.log('');
  console.log('| Type            | Start | End   | Confidence | Severity |');
  console.log('|-----------------|-------|-------|------------|----------|');

  // Rows
  for (const entity of entities) {
    const type = String(entity.pii_type).padEnd(15);
    const start = String(entity.start).padStart(5);
    const end = String(entity.end).padStart(5);
    const confidence = String(entity.confidence).padStart(10);
    const severity = String(entity.severity).padEnd(8);

    console.log(`| ${type} | ${start} | ${end} | ${confidence} | ${severity} |`);
  }

  console.log('');
  console.log(`Total: ${entities.length} entities detected`);
  console.log(`Risk Score: ${result.risk_score} | Severity: ${result.severity}`);
}

/**
 * Main entry point
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    printHelp();
    process.exit(0);
  }

  const options = parseArgs(args);

  try {
    switch (options.mode) {
      case 'test':
        await runTest(options);
        break;
      case 'simulate':
        await runSimulate(options);
        break;
      case 'inspect':
        await runInspect(options);
        break;
    }
  } catch (error) {
    console.error('Error:', (error as Error).message);
    if (options.verbose) {
      console.error(error);
    }
    process.exit(1);
  }
}

// Run if executed directly
main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});

export { parseArgs, runTest, runSimulate, runInspect };
