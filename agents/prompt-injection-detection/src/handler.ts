/**
 * @module handler
 * @description Google Cloud Edge Function handler for Prompt Injection Detection Agent
 *
 * This handler is deployed as part of the LLM-Shield unified GCP service.
 * It provides HTTP endpoints for agent invocation.
 */

import { randomUUID } from 'crypto';
import {
  type AgentOutput,
  type AgentError,
  type CliInvocation,
  CliInvocation as CliInvocationSchema,
  AgentError as AgentErrorSchema,
} from '@llm-shield/agentics-contracts';
import {
  PromptInjectionDetectionAgent,
  createAgent,
  AGENT_IDENTITY,
} from './agent.js';

/**
 * HTTP Request interface (Edge Function compatible)
 */
export interface EdgeRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: unknown;
  json(): Promise<unknown>;
}

/**
 * HTTP Response interface (Edge Function compatible)
 */
export interface EdgeResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

/**
 * Create JSON response helper
 */
function jsonResponse(body: unknown, status = 200): EdgeResponse {
  return {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-Agent-ID': AGENT_IDENTITY.agent_id,
      'X-Agent-Version': AGENT_IDENTITY.agent_version,
    },
    body,
  };
}

/**
 * Create error response helper
 */
function errorResponse(
  code: AgentError['code'],
  message: string,
  status: number,
  details?: Record<string, unknown>
): EdgeResponse {
  const error: AgentError = {
    code,
    message,
    agent: AGENT_IDENTITY,
    timestamp: new Date().toISOString(),
    details,
  };

  return jsonResponse(error, status);
}

/**
 * Edge Function handler
 *
 * Endpoints:
 * - POST /detect - Execute detection on content
 * - POST /cli - CLI invocation (test/simulate/inspect)
 * - GET /health - Health check
 * - GET /info - Agent information
 */
export async function handler(request: EdgeRequest): Promise<EdgeResponse> {
  const url = new URL(request.url, 'http://localhost');
  const path = url.pathname;

  try {
    // Route based on path
    switch (true) {
      case path === '/detect' && request.method === 'POST':
        return await handleDetect(request);

      case path === '/cli' && request.method === 'POST':
        return await handleCli(request);

      case path === '/health' && request.method === 'GET':
        return handleHealth();

      case path === '/info' && request.method === 'GET':
        return handleInfo();

      default:
        return errorResponse(
          'INVALID_INPUT',
          `Unknown endpoint: ${request.method} ${path}`,
          404
        );
    }
  } catch (error) {
    // Handle validation errors from agent
    if (isAgentError(error)) {
      return jsonResponse(error, 400);
    }

    // Handle unexpected errors
    console.error('[Handler] Unexpected error:', error);
    return errorResponse(
      'INTERNAL_ERROR',
      error instanceof Error ? error.message : 'Unknown error',
      500
    );
  }
}

/**
 * Handle detection request
 */
async function handleDetect(request: EdgeRequest): Promise<EdgeResponse> {
  const agent = createAgent();

  try {
    // Parse and validate input
    const rawInput = await request.json();
    const input = agent.validateInput(rawInput);

    // Execute detection
    const output = await agent.detect(input);

    return jsonResponse(output, 200);
  } finally {
    await agent.shutdown();
  }
}

/**
 * Handle CLI invocation
 */
async function handleCli(request: EdgeRequest): Promise<EdgeResponse> {
  const rawInput = await request.json();
  const parseResult = CliInvocationSchema.safeParse(rawInput);

  if (!parseResult.success) {
    return errorResponse(
      'VALIDATION_FAILED',
      'Invalid CLI invocation',
      400,
      { errors: parseResult.error.errors }
    );
  }

  const cli = parseResult.data;
  const agent = createAgent();

  try {
    switch (cli.mode) {
      case 'test':
        return await handleCliTest(agent, cli);

      case 'simulate':
        return await handleCliSimulate(agent, cli);

      case 'inspect':
        return handleCliInspect(cli);

      default:
        return errorResponse('INVALID_INPUT', `Unknown CLI mode: ${cli.mode}`, 400);
    }
  } finally {
    await agent.shutdown();
  }
}

/**
 * Handle CLI test mode
 */
async function handleCliTest(
  agent: PromptInjectionDetectionAgent,
  cli: CliInvocation
): Promise<EdgeResponse> {
  const input = {
    content: cli.content,
    context: {
      execution_ref: randomUUID(),
      timestamp: new Date().toISOString(),
      content_source: 'user_input' as const,
    },
    sensitivity: (cli.config?.sensitivity as number) ?? 0.5,
    detect_categories: cli.config?.categories as string[] | undefined,
  };

  const validatedInput = agent.validateInput(input);
  const output = await agent.detect(validatedInput);

  return formatCliOutput(output, cli.format, cli.verbose);
}

/**
 * Handle CLI simulate mode
 */
async function handleCliSimulate(
  agent: PromptInjectionDetectionAgent,
  cli: CliInvocation
): Promise<EdgeResponse> {
  // Simulate mode - same as test but marks as simulation
  const input = {
    content: cli.content,
    context: {
      execution_ref: randomUUID(),
      timestamp: new Date().toISOString(),
      content_source: 'user_input' as const,
      metadata: { simulation: true },
    },
    sensitivity: (cli.config?.sensitivity as number) ?? 0.5,
    detect_categories: cli.config?.categories as string[] | undefined,
  };

  const validatedInput = agent.validateInput(input);
  const output = await agent.detect(validatedInput);

  return formatCliOutput(output, cli.format, cli.verbose);
}

/**
 * Handle CLI inspect mode
 */
function handleCliInspect(cli: CliInvocation): EdgeResponse {
  // Inspect mode returns agent metadata and configuration
  const inspectData = {
    agent: AGENT_IDENTITY,
    patterns: {
      total: 57, // Number of patterns in patterns.ts
      categories: [
        'instruction_override',
        'role_manipulation',
        'system_prompt_attack',
        'jailbreak',
        'delimiter_injection',
        'encoding_attack',
        'context_manipulation',
      ],
    },
    configuration: {
      default_sensitivity: 0.5,
      telemetry_enabled: process.env.TELEMETRY_ENABLED !== 'false',
      ruvector_url: process.env.RUVECTOR_SERVICE_URL || 'http://localhost:8080',
    },
    invocation: {
      content_preview: cli.content.substring(0, 50) + (cli.content.length > 50 ? '...' : ''),
      config: cli.config,
    },
  };

  return formatCliOutput(inspectData, cli.format, cli.verbose);
}

/**
 * Format CLI output based on format preference
 */
function formatCliOutput(
  data: unknown,
  format: 'json' | 'text' | 'table',
  verbose: boolean
): EdgeResponse {
  switch (format) {
    case 'json':
      return jsonResponse(data);

    case 'text':
      return jsonResponse({
        format: 'text',
        output: formatAsText(data, verbose),
      });

    case 'table':
      return jsonResponse({
        format: 'table',
        output: formatAsTable(data, verbose),
      });

    default:
      return jsonResponse(data);
  }
}

/**
 * Format output as human-readable text
 */
function formatAsText(data: unknown, verbose: boolean): string {
  const output = data as AgentOutput;

  if (!output.result) {
    return JSON.stringify(data, null, 2);
  }

  const lines: string[] = [
    `=== Prompt Injection Detection Results ===`,
    ``,
    `Threats Detected: ${output.result.threats_detected ? 'YES' : 'NO'}`,
    `Risk Score: ${(output.result.risk_score * 100).toFixed(1)}%`,
    `Severity: ${output.result.severity.toUpperCase()}`,
    `Confidence: ${(output.result.confidence * 100).toFixed(1)}%`,
    `Patterns Matched: ${output.result.pattern_match_count}`,
    `Duration: ${output.duration_ms.toFixed(2)}ms`,
  ];

  if (output.result.detected_categories.length > 0) {
    lines.push(``, `Categories: ${output.result.detected_categories.join(', ')}`);
  }

  if (verbose && output.result.entities.length > 0) {
    lines.push(``, `--- Detected Entities ---`);
    for (const entity of output.result.entities) {
      lines.push(
        `  [${entity.pattern_id}] ${entity.category} (${(entity.confidence * 100).toFixed(0)}% confidence)`
      );
    }
  }

  if (verbose && output.result.risk_factors.length > 0) {
    lines.push(``, `--- Risk Factors ---`);
    for (const factor of output.result.risk_factors) {
      lines.push(
        `  ${factor.category}: ${factor.description} (${factor.severity})`
      );
    }
  }

  return lines.join('\n');
}

/**
 * Format output as table
 */
function formatAsTable(data: unknown, verbose: boolean): string {
  const output = data as AgentOutput;

  if (!output.result) {
    return JSON.stringify(data, null, 2);
  }

  const lines: string[] = [
    `┌─────────────────────────────────────────────────────────┐`,
    `│ PROMPT INJECTION DETECTION RESULTS                     │`,
    `├─────────────────────────────────────────────────────────┤`,
    `│ Threats Detected │ ${String(output.result.threats_detected).padEnd(37)} │`,
    `│ Risk Score       │ ${((output.result.risk_score * 100).toFixed(1) + '%').padEnd(37)} │`,
    `│ Severity         │ ${output.result.severity.toUpperCase().padEnd(37)} │`,
    `│ Confidence       │ ${((output.result.confidence * 100).toFixed(1) + '%').padEnd(37)} │`,
    `│ Pattern Matches  │ ${String(output.result.pattern_match_count).padEnd(37)} │`,
    `│ Duration         │ ${(output.duration_ms.toFixed(2) + 'ms').padEnd(37)} │`,
    `└─────────────────────────────────────────────────────────┘`,
  ];

  return lines.join('\n');
}

/**
 * Handle health check
 */
function handleHealth(): EdgeResponse {
  return jsonResponse({
    status: 'healthy',
    agent: AGENT_IDENTITY.agent_id,
    version: AGENT_IDENTITY.agent_version,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Handle info request
 */
function handleInfo(): EdgeResponse {
  return jsonResponse({
    agent: AGENT_IDENTITY,
    classification: 'DETECTION_ONLY',
    description:
      'Detects prompt injection attempts in LLM input content that attempt to override system instructions or escape safety constraints.',
    endpoints: [
      { path: '/detect', method: 'POST', description: 'Execute detection' },
      { path: '/cli', method: 'POST', description: 'CLI invocation' },
      { path: '/health', method: 'GET', description: 'Health check' },
      { path: '/info', method: 'GET', description: 'Agent information' },
    ],
    categories: [
      'instruction_override',
      'role_manipulation',
      'system_prompt_attack',
      'jailbreak',
      'delimiter_injection',
      'encoding_attack',
      'context_manipulation',
    ],
  });
}

/**
 * Type guard for AgentError
 */
function isAgentError(error: unknown): error is AgentError {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    'message' in error
  );
}

/**
 * Export for Google Cloud Functions
 */
export const promptInjectionDetection = handler;
