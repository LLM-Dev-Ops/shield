/**
 * @module cli
 * @description CLI interface for Content Moderation Agent
 *
 * Provides test, simulate, and inspect commands for agent invocation.
 */

import { randomUUID } from 'crypto';
import { createAgent, AGENT_IDENTITY } from './agent.js';
import { MODERATION_PATTERNS, getPatternCountByCategory, MODERATION_CATEGORIES } from './patterns.js';
import type { ContentModerationCategory, ModerationAction } from '@llm-shield/agentics-contracts';

/**
 * CLI options interface
 */
export interface CliOptions {
  /** Content to analyze */
  content: string;
  /** CLI mode */
  mode: 'test' | 'simulate' | 'inspect';
  /** Output format */
  format?: 'json' | 'text' | 'table';
  /** Verbose output */
  verbose?: boolean;
  /** Sensitivity level (0.0 - 1.0) */
  sensitivity?: number;
  /** Categories to check */
  categories?: ContentModerationCategory[];
  /** Default action */
  defaultAction?: ModerationAction;
  /** Whether user age is verified */
  ageVerified?: boolean;
}

/**
 * CLI result interface
 */
export interface CliResult {
  success: boolean;
  output: unknown;
  format: string;
}

/**
 * Execute CLI command
 */
export async function executeCli(options: CliOptions): Promise<CliResult> {
  const format = options.format ?? 'json';

  switch (options.mode) {
    case 'test':
      return executeTest(options, format);

    case 'simulate':
      return executeSimulate(options, format);

    case 'inspect':
      return executeInspect(options, format);

    default:
      return {
        success: false,
        output: { error: `Unknown mode: ${options.mode}` },
        format,
      };
  }
}

/**
 * Execute test mode
 */
async function executeTest(
  options: CliOptions,
  format: string
): Promise<CliResult> {
  const agent = createAgent();

  try {
    const input = {
      content: options.content,
      context: {
        execution_ref: randomUUID(),
        timestamp: new Date().toISOString(),
        content_source: 'user_input' as const,
      },
      sensitivity: options.sensitivity ?? 0.7,
      moderate_categories: options.categories,
      default_action: options.defaultAction ?? 'BLOCK',
      user_age_verified: options.ageVerified ?? false,
    };

    const validatedInput = agent.validateInput(input);
    const output = await agent.moderate(validatedInput);

    return {
      success: true,
      output: formatOutput(output, format, options.verbose ?? false),
      format,
    };
  } catch (error) {
    return {
      success: false,
      output: {
        error: error instanceof Error ? error.message : String(error),
      },
      format,
    };
  } finally {
    await agent.shutdown();
  }
}

/**
 * Execute simulate mode
 */
async function executeSimulate(
  options: CliOptions,
  format: string
): Promise<CliResult> {
  const agent = createAgent();

  try {
    const input = {
      content: options.content,
      context: {
        execution_ref: randomUUID(),
        timestamp: new Date().toISOString(),
        content_source: 'user_input' as const,
        metadata: { simulation: true },
      },
      sensitivity: options.sensitivity ?? 0.7,
      moderate_categories: options.categories,
      default_action: options.defaultAction ?? 'BLOCK',
      user_age_verified: options.ageVerified ?? false,
    };

    const validatedInput = agent.validateInput(input);
    const output = await agent.moderate(validatedInput);

    return {
      success: true,
      output: {
        simulation: true,
        result: formatOutput(output, format, options.verbose ?? false),
      },
      format,
    };
  } catch (error) {
    return {
      success: false,
      output: {
        error: error instanceof Error ? error.message : String(error),
      },
      format,
    };
  } finally {
    await agent.shutdown();
  }
}

/**
 * Execute inspect mode
 */
function executeInspect(
  options: CliOptions,
  format: string
): CliResult {
  const inspectData = {
    agent: AGENT_IDENTITY,
    patterns: {
      total: MODERATION_PATTERNS.length,
      by_category: getPatternCountByCategory(),
    },
    categories: MODERATION_CATEGORIES,
    configuration: {
      default_sensitivity: 0.7,
      default_action: 'BLOCK',
      min_moderation_confidence: 0.8,
    },
    invocation: {
      content_preview:
        options.content.substring(0, 50) +
        (options.content.length > 50 ? '...' : ''),
      options: {
        sensitivity: options.sensitivity,
        categories: options.categories,
        defaultAction: options.defaultAction,
        ageVerified: options.ageVerified,
      },
    },
  };

  return {
    success: true,
    output: inspectData,
    format,
  };
}

/**
 * Format output based on format preference
 */
function formatOutput(
  data: unknown,
  format: string,
  verbose: boolean
): unknown {
  if (format === 'json') {
    return data;
  }

  // For text and table formats, return structured data
  // that can be further processed by the caller
  return {
    data,
    format,
    verbose,
  };
}

/**
 * Print CLI help
 */
export function printHelp(): void {
  console.log(`
Content Moderation Agent CLI

Usage:
  content-moderation <mode> [options]

Modes:
  test      - Execute moderation on content
  simulate  - Execute moderation in simulation mode (no persistence)
  inspect   - Inspect agent configuration and patterns

Options:
  --content, -c      Content to analyze (required)
  --format, -f       Output format: json, text, table (default: json)
  --verbose, -v      Enable verbose output
  --sensitivity, -s  Detection sensitivity 0.0-1.0 (default: 0.7)
  --categories       Categories to check (comma-separated)
  --default-action   Default action: ALLOW, BLOCK, FLAG, WARN, AGE_GATE
  --age-verified     Mark user as age-verified

Examples:
  # Test content moderation
  content-moderation test -c "Sample content to moderate"

  # Simulate with verbose output
  content-moderation simulate -c "Content" -v -f text

  # Inspect agent configuration
  content-moderation inspect -c "" -f json
`);
}

/**
 * Parse command line arguments
 */
export function parseArgs(args: string[]): CliOptions | null {
  if (args.length < 2) {
    printHelp();
    return null;
  }

  const mode = args[0] as 'test' | 'simulate' | 'inspect';
  if (!['test', 'simulate', 'inspect'].includes(mode)) {
    console.error(`Unknown mode: ${mode}`);
    printHelp();
    return null;
  }

  let content = '';
  let format: 'json' | 'text' | 'table' = 'json';
  let verbose = false;
  let sensitivity: number | undefined;
  let categories: ContentModerationCategory[] | undefined;
  let defaultAction: ModerationAction | undefined;
  let ageVerified = false;

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case '--content':
      case '-c':
        content = args[++i] || '';
        break;
      case '--format':
      case '-f':
        format = (args[++i] as 'json' | 'text' | 'table') || 'json';
        break;
      case '--verbose':
      case '-v':
        verbose = true;
        break;
      case '--sensitivity':
      case '-s':
        sensitivity = parseFloat(args[++i] || '0.7');
        break;
      case '--categories':
        categories = (args[++i] || '').split(',') as ContentModerationCategory[];
        break;
      case '--default-action':
        defaultAction = args[++i] as ModerationAction;
        break;
      case '--age-verified':
        ageVerified = true;
        break;
    }
  }

  return {
    mode,
    content,
    format,
    verbose,
    sensitivity,
    categories,
    defaultAction,
    ageVerified,
  };
}
