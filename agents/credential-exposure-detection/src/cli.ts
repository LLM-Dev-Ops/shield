#!/usr/bin/env node
/**
 * @module credential-exposure-detection/cli
 * @description CLI invocation for Credential Exposure Detection Agent
 *
 * Supports three modes:
 * - test: Run detection on input content and display results
 * - simulate: Simulate detection without persistence
 * - inspect: Inspect agent configuration and patterns
 *
 * Usage:
 *   npx credential-exposure-detection test "content with password=secret123"
 *   npx credential-exposure-detection simulate < input.txt
 *   npx credential-exposure-detection inspect --patterns
 */

import { randomUUID } from 'crypto';
import { handleDetection } from './handler.js';
import { createNoOpClient } from './ruvector-client.js';
import { NoOpTelemetryEmitter } from './telemetry.js';
import {
  CREDENTIAL_PATTERNS,
  getPairPatterns,
  getPasswordOnlyPatterns,
  getAuthHeaderPatterns,
} from './patterns.js';
import type { CredentialExposureDetectionInput } from '@llm-shield/agentics-contracts';

/**
 * CLI invocation modes
 */
type CliMode = 'test' | 'simulate' | 'inspect';

/**
 * CLI options
 */
interface CliOptions {
  mode: CliMode;
  content?: string;
  format?: 'json' | 'text' | 'table';
  verbose?: boolean;
  sensitivity?: number;
  patterns?: boolean;
  file?: string;
}

/**
 * Parse command line arguments
 */
function parseArgs(args: string[]): CliOptions {
  const options: CliOptions = {
    mode: 'test',
    format: 'json',
    verbose: false,
    sensitivity: 0.5,
    patterns: false,
  };

  let i = 0;
  while (i < args.length) {
    const arg = args[i];

    switch (arg) {
      case 'test':
      case 'simulate':
      case 'inspect':
        options.mode = arg;
        break;
      case '--format':
      case '-f':
        options.format = args[++i] as 'json' | 'text' | 'table';
        break;
      case '--verbose':
      case '-v':
        options.verbose = true;
        break;
      case '--sensitivity':
      case '-s':
        options.sensitivity = parseFloat(args[++i]);
        break;
      case '--patterns':
      case '-p':
        options.patterns = true;
        break;
      case '--file':
        options.file = args[++i];
        break;
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
        break;
      default:
        if (!arg.startsWith('-')) {
          options.content = arg;
        }
    }
    i++;
  }

  return options;
}

/**
 * Print help message
 */
function printHelp(): void {
  console.log(`
Credential Exposure Detection Agent CLI

Usage:
  credential-exposure-detection <mode> [options] [content]

Modes:
  test        Run detection on content and display results
  simulate    Run detection without persistence
  inspect     Inspect agent configuration and patterns

Options:
  -f, --format <format>    Output format: json, text, table (default: json)
  -v, --verbose            Verbose output
  -s, --sensitivity <n>    Detection sensitivity 0.0-1.0 (default: 0.5)
  -p, --patterns           Show available patterns (inspect mode)
  --file <path>            Read content from file
  -h, --help               Show this help message

Examples:
  credential-exposure-detection test "username=admin password=secret123"
  credential-exposure-detection simulate --file input.txt
  credential-exposure-detection inspect --patterns
`);
}

/**
 * Read content from stdin if available
 */
async function readStdin(): Promise<string | undefined> {
  if (process.stdin.isTTY) {
    return undefined;
  }

  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf-8');
}

/**
 * Read content from file
 */
async function readFile(path: string): Promise<string> {
  const fs = await import('fs/promises');
  return await fs.readFile(path, 'utf-8');
}

/**
 * Format output for display
 */
function formatOutput(result: unknown, format: 'json' | 'text' | 'table'): string {
  if (format === 'json') {
    return JSON.stringify(result, null, 2);
  }

  if (format === 'text') {
    const r = result as {
      result: {
        credentials_detected: boolean;
        risk_score: number;
        severity: string;
        pattern_match_count: number;
        detected_types: string[];
        credential_pair_count: number;
        entities: Array<{
          credential_type: string;
          start: number;
          end: number;
          confidence: number;
          redacted_preview?: string;
        }>;
      };
      duration_ms: number;
    };

    let output = '';
    output += `Credentials Detected: ${r.result.credentials_detected ? 'YES' : 'NO'}\n`;
    output += `Risk Score: ${(r.result.risk_score * 100).toFixed(1)}%\n`;
    output += `Severity: ${r.result.severity.toUpperCase()}\n`;
    output += `Patterns Matched: ${r.result.pattern_match_count}\n`;
    output += `Credential Pairs: ${r.result.credential_pair_count}\n`;
    output += `Duration: ${r.duration_ms.toFixed(2)}ms\n`;

    if (r.result.detected_types.length > 0) {
      output += `\nDetected Types:\n`;
      for (const type of r.result.detected_types) {
        output += `  - ${type}\n`;
      }
    }

    if (r.result.entities.length > 0) {
      output += `\nEntities:\n`;
      for (const entity of r.result.entities) {
        output += `  [${entity.credential_type}] pos ${entity.start}-${entity.end} `;
        output += `(confidence: ${(entity.confidence * 100).toFixed(1)}%)`;
        if (entity.redacted_preview) {
          output += ` preview: ${entity.redacted_preview}`;
        }
        output += '\n';
      }
    }

    return output;
  }

  // Table format
  const r = result as {
    result: {
      entities: Array<{
        credential_type: string;
        start: number;
        end: number;
        confidence: number;
        severity: string;
        is_credential_pair: boolean;
        redacted_preview?: string;
      }>;
    };
  };

  if (r.result.entities.length === 0) {
    return 'No credentials detected.';
  }

  const headers = ['Type', 'Start', 'End', 'Confidence', 'Severity', 'Pair', 'Preview'];
  const rows = r.result.entities.map((e) => [
    e.credential_type,
    String(e.start),
    String(e.end),
    `${(e.confidence * 100).toFixed(1)}%`,
    e.severity,
    e.is_credential_pair ? 'Yes' : 'No',
    e.redacted_preview || '-',
  ]);

  // Calculate column widths
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => r[i].length))
  );

  // Build table
  let table = '';
  table += headers.map((h, i) => h.padEnd(widths[i])).join(' | ') + '\n';
  table += widths.map((w) => '-'.repeat(w)).join('-+-') + '\n';
  for (const row of rows) {
    table += row.map((c, i) => c.padEnd(widths[i])).join(' | ') + '\n';
  }

  return table;
}

/**
 * Handle inspect mode
 */
function handleInspect(options: CliOptions): void {
  if (options.patterns) {
    console.log('Available Credential Detection Patterns:\n');

    console.log('=== Credential Pair Patterns ===');
    for (const pattern of getPairPatterns()) {
      console.log(`  ${pattern.pattern_id}`);
      console.log(`    Category: ${pattern.category}`);
      console.log(`    Severity: ${pattern.severity}`);
      console.log(`    Confidence: ${(pattern.confidence * 100).toFixed(0)}%`);
      console.log(`    ${pattern.description}\n`);
    }

    console.log('=== Password Patterns ===');
    for (const pattern of getPasswordOnlyPatterns()) {
      console.log(`  ${pattern.pattern_id}`);
      console.log(`    Category: ${pattern.category}`);
      console.log(`    Severity: ${pattern.severity}`);
      console.log(`    ${pattern.description}\n`);
    }

    console.log('=== Auth Header Patterns ===');
    for (const pattern of getAuthHeaderPatterns()) {
      console.log(`  ${pattern.pattern_id}`);
      console.log(`    Category: ${pattern.category}`);
      console.log(`    Severity: ${pattern.severity}`);
      console.log(`    ${pattern.description}\n`);
    }

    console.log(`\nTotal Patterns: ${CREDENTIAL_PATTERNS.length}`);
    return;
  }

  // Default inspect output
  console.log('Credential Exposure Detection Agent');
  console.log('===================================');
  console.log('Agent ID: credential-exposure-detection-agent');
  console.log('Version: 1.0.0');
  console.log('Classification: DETECTION_ONLY');
  console.log('Decision Type: credential_exposure_detection');
  console.log('Deployment: Google Cloud Edge Function');
  console.log(`\nTotal Patterns: ${CREDENTIAL_PATTERNS.length}`);
  console.log(`  - Pair Patterns: ${getPairPatterns().length}`);
  console.log(`  - Password Patterns: ${getPasswordOnlyPatterns().length}`);
  console.log(`  - Auth Header Patterns: ${getAuthHeaderPatterns().length}`);
  console.log('\nUse --patterns to see all available patterns');
}

/**
 * Handle CLI invocation
 */
export async function handleCliInvocation(options: CliOptions): Promise<void> {
  if (options.mode === 'inspect') {
    handleInspect(options);
    return;
  }

  // Get content
  let content = options.content;

  if (options.file) {
    content = await readFile(options.file);
  } else if (!content) {
    content = await readStdin();
  }

  if (!content) {
    console.error('Error: No content provided. Use --file, pipe input, or provide as argument.');
    process.exit(1);
  }

  // Build input
  const input: CredentialExposureDetectionInput = {
    content,
    context: {
      execution_ref: randomUUID(),
      timestamp: new Date().toISOString(),
      content_source: 'user_input',
    },
    sensitivity: options.sensitivity ?? 0.5,
  };

  // Run detection
  const isSimulate = options.mode === 'simulate';
  const result = await handleDetection(input, {
    skipPersistence: isSimulate,
    ruvectorClient: isSimulate ? createNoOpClient() : undefined,
    telemetryEmitter: isSimulate ? new NoOpTelemetryEmitter() : undefined,
  });

  // Check for error
  if ('code' in result) {
    console.error('Error:', result.message);
    if (options.verbose && result.details) {
      console.error('Details:', JSON.stringify(result.details, null, 2));
    }
    process.exit(1);
  }

  // Output result
  console.log(formatOutput(result, options.format ?? 'json'));
}

/**
 * Main entry point
 */
export async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    printHelp();
    process.exit(0);
  }

  const options = parseArgs(args);

  try {
    await handleCliInvocation(options);
  } catch (error) {
    console.error('Error:', error instanceof Error ? error.message : 'Unknown error');
    process.exit(1);
  }
}

// Run if executed directly
const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch(console.error);
}
