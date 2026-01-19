/**
 * Data Redaction Agent - Main Entry Point
 *
 * This is the main handler for the Data Redaction Agent.
 * It can be deployed as a Google Cloud Edge Function.
 *
 * Classification: REDACTION
 * Decision Type: data_redaction
 *
 * This agent:
 * - Detects PII, secrets, and credentials
 * - Redacts detected sensitive data
 * - Returns sanitized content
 * - Emits DecisionEvents to ruvector-service
 * - Emits telemetry to LLM-Observatory
 *
 * This agent does NOT:
 * - Orchestrate workflows
 * - Trigger retries
 * - Modify policies
 * - Connect to databases directly
 * - Store raw sensitive data
 */

import { z } from 'zod';
import {
  DataRedactionAgentInput,
  DataRedactionAgentOutput,
  AgentError,
  type DataRedactionResult,
  type RedactedEntity,
  type AgentIdentity,
  type PolicyReference,
  type InvocationContext,
} from '../../../contracts/index.js';
import { Redactor, hashContent, type RedactionConfig, type RedactionResult } from './redactor.js';
import { RuvectorClient, createRuvectorClient, type DecisionEventPayload } from './ruvector-client.js';
import { TelemetryEmitter, createTelemetryEmitter, type RedactionTelemetry } from './telemetry.js';

// =============================================================================
// AGENT CONSTANTS
// =============================================================================

export const AGENT_ID = 'data-redaction-agent';
export const AGENT_VERSION = '1.0.0';
export const AGENT_CLASSIFICATION = 'REDACTION' as const;
export const DECISION_TYPE = 'data_redaction' as const;

const AGENT_IDENTITY: AgentIdentity = {
  agent_id: AGENT_ID,
  agent_version: AGENT_VERSION,
  classification: AGENT_CLASSIFICATION,
  decision_type: DECISION_TYPE,
};

// =============================================================================
// INTERFACES
// =============================================================================

export interface AgentConfig {
  /** ruvector-service client configuration */
  ruvectorClient?: RuvectorClient;
  /** Telemetry emitter configuration */
  telemetryEmitter?: TelemetryEmitter;
  /** Skip persistence (for testing) */
  skipPersistence?: boolean;
  /** Skip telemetry (for testing) */
  skipTelemetry?: boolean;
}

export type DataRedactionInput = z.infer<typeof DataRedactionAgentInput>;
export type DataRedactionOutput = z.infer<typeof DataRedactionAgentOutput>;
export type AgentErrorOutput = z.infer<typeof AgentError>;

// =============================================================================
// MAIN AGENT CLASS
// =============================================================================

/**
 * Data Redaction Agent
 *
 * Detects and redacts sensitive data (PII, secrets, credentials) from content.
 */
export class DataRedactionAgent {
  private ruvectorClient: RuvectorClient;
  private telemetryEmitter: TelemetryEmitter;
  private skipPersistence: boolean;
  private skipTelemetry: boolean;

  constructor(config: AgentConfig = {}) {
    this.ruvectorClient = config.ruvectorClient || createRuvectorClient();
    this.telemetryEmitter = config.telemetryEmitter || createTelemetryEmitter();
    this.skipPersistence = config.skipPersistence || false;
    this.skipTelemetry = config.skipTelemetry || false;
  }

  /**
   * Process a redaction request
   *
   * @param input - The validated input
   * @returns Redaction result (with sanitized content)
   */
  async process(input: DataRedactionInput): Promise<DataRedactionOutput | AgentErrorOutput> {
    const startTime = performance.now();
    const spanId = this.telemetryEmitter.startSpan(input.context.execution_ref, 'redaction');

    try {
      // Validate input
      const validatedInput = this.validateInput(input);

      // Build redaction config
      const redactionConfig = this.buildRedactionConfig(validatedInput);

      // Perform redaction
      const redactor = new Redactor(redactionConfig);
      const result = redactor.redact(validatedInput.content);

      // Calculate duration
      const durationMs = performance.now() - startTime;

      // Build output
      const output = this.buildOutput(result, durationMs);

      // Persist decision event (async, non-blocking)
      const persistResult = await this.persistDecisionEvent(
        validatedInput,
        result,
        durationMs
      );

      // Emit telemetry
      await this.emitTelemetry(validatedInput, result, durationMs, persistResult.success);

      // End span
      this.telemetryEmitter.endSpan(spanId, 'ok', {
        'redaction.count': result.redactionCount,
        'detection.severity': result.severity,
      });

      return output;
    } catch (error) {
      const durationMs = performance.now() - startTime;

      // End span with error
      this.telemetryEmitter.endSpan(spanId, 'error');

      // Return error response
      return this.buildErrorResponse(error, input.context, durationMs);
    }
  }

  /**
   * Validate input against schema
   */
  private validateInput(input: DataRedactionInput): DataRedactionInput {
    const result = DataRedactionAgentInput.safeParse(input);
    if (!result.success) {
      throw new ValidationError('Input validation failed', result.error.issues);
    }
    return result.data;
  }

  /**
   * Build redaction configuration from input
   */
  private buildRedactionConfig(input: DataRedactionInput): RedactionConfig {
    return {
      sensitivity: input.sensitivity ?? 0.7,
      strategy: input.redaction_strategy ?? 'mask',
      piiTypes: input.pii_types,
      secretTypes: input.secret_types,
      detectPii: input.detect_pii ?? true,
      detectSecrets: input.detect_secrets ?? true,
      detectCredentials: input.detect_credentials ?? true,
      minConfidence: input.min_confidence_threshold ?? 0.8,
      returnRedactedContent: input.return_redacted_content ?? true,
      customPlaceholder: input.custom_placeholder,
      partialMaskChars: input.partial_mask_chars ?? 4,
    };
  }

  /**
   * Build agent output from redaction result
   */
  private buildOutput(result: RedactionResult, durationMs: number): DataRedactionOutput {
    const redactedEntities: RedactedEntity[] = result.redactedEntities.map(entity => ({
      entity_type: entity.entityType,
      category: entity.category,
      original_start: entity.originalStart,
      original_end: entity.originalEnd,
      redacted_start: entity.redactedStart,
      redacted_end: entity.redactedEnd,
      confidence: entity.confidence,
      severity: entity.severity,
      pattern_id: entity.patternId,
      strategy_applied: entity.strategyApplied,
      original_length: entity.originalLength,
      redacted_placeholder: entity.redactedPlaceholder,
    }));

    const dataRedactionResult: DataRedactionResult = {
      data_redacted: result.dataRedacted,
      redaction_count: result.redactionCount,
      original_risk_score: result.originalRiskScore,
      severity: result.severity,
      confidence: result.confidence,
      redacted_entities: redactedEntities,
      redacted_content: result.redactedContent,
      detected_categories: result.detectedCategories,
      category_counts: result.categoryCounts,
      severity_counts: result.severityCounts,
    };

    return {
      agent: AGENT_IDENTITY,
      result: dataRedactionResult,
      duration_ms: durationMs,
      cached: false,
    };
  }

  /**
   * Persist decision event to ruvector-service
   */
  private async persistDecisionEvent(
    input: DataRedactionInput,
    result: RedactionResult,
    durationMs: number
  ): Promise<{ success: boolean; error?: string }> {
    if (this.skipPersistence) {
      return { success: true };
    }

    // Compute hashes (NEVER persist raw content)
    const inputsHash = hashContent(input.content);
    const outputsHash = result.redactedContent
      ? hashContent(result.redactedContent)
      : hashContent('');

    const payload: DecisionEventPayload = {
      agentId: AGENT_ID,
      agentVersion: AGENT_VERSION,
      decisionType: DECISION_TYPE,
      inputsHash,
      outputsHash,
      outputs: {
        dataRedacted: result.dataRedacted,
        redactionCount: result.redactionCount,
        originalRiskScore: result.originalRiskScore,
        severity: result.severity,
        confidence: result.confidence,
        detectedCategories: result.detectedCategories,
        categoryCounts: result.categoryCounts,
        severityCounts: result.severityCounts,
        entityTypeCounts: result.entityTypeCounts,
      },
      confidence: result.confidence,
      constraintsApplied: input.context.policies || [],
      executionRef: input.context.execution_ref,
      timestamp: input.context.timestamp,
      durationMs,
      telemetry: {
        originalContentLength: input.content.length,
        redactedContentLength: result.redactedContent?.length || 0,
        contentSource: input.context.content_source,
        sessionId: input.context.session_id,
        callerId: input.context.caller_id,
        redactionStrategy: input.redaction_strategy || 'mask',
      },
    };

    const persistResult = await this.ruvectorClient.persistDecisionEvent(payload);
    return { success: persistResult.success, error: persistResult.error };
  }

  /**
   * Emit telemetry to LLM-Observatory
   */
  private async emitTelemetry(
    input: DataRedactionInput,
    result: RedactionResult,
    durationMs: number,
    persistenceSuccess: boolean
  ): Promise<void> {
    if (this.skipTelemetry) return;

    const telemetry: RedactionTelemetry = {
      agentId: AGENT_ID,
      agentVersion: AGENT_VERSION,
      decisionType: DECISION_TYPE,
      executionRef: input.context.execution_ref,
      contentSource: input.context.content_source,
      originalContentLength: input.content.length,
      redactedContentLength: result.redactedContent?.length || 0,
      dataRedacted: result.dataRedacted,
      redactionCount: result.redactionCount,
      detectedCategories: result.detectedCategories,
      severity: result.severity,
      confidence: result.confidence,
      riskScore: result.originalRiskScore,
      redactionStrategy: input.redaction_strategy || 'mask',
      durationMs,
      timestamp: input.context.timestamp,
      sessionId: input.context.session_id,
      callerId: input.context.caller_id,
      persistenceSuccess,
    };

    await this.telemetryEmitter.emitRedactionTelemetry(telemetry);

    // Emit metrics
    this.telemetryEmitter.emitMetric('redaction_count', result.redactionCount, 'count');
    this.telemetryEmitter.emitMetric('duration_ms', durationMs, 'ms');
    this.telemetryEmitter.emitMetric('risk_score', result.originalRiskScore, 'score');
  }

  /**
   * Build error response
   */
  private buildErrorResponse(
    error: unknown,
    context: InvocationContext,
    durationMs: number
  ): AgentErrorOutput {
    const isValidationError = error instanceof ValidationError;
    const isTimeoutError = error instanceof Error && error.message.includes('timeout');

    const errorCode = isValidationError
      ? 'INVALID_INPUT'
      : isTimeoutError
      ? 'TIMEOUT'
      : 'INTERNAL_ERROR';

    const errorMessage = error instanceof Error ? error.message : 'Unknown error';

    // Emit error telemetry
    this.telemetryEmitter.emitErrorTelemetry(
      context.execution_ref,
      errorCode,
      errorMessage
    );

    return {
      code: errorCode,
      message: errorMessage,
      agent: AGENT_IDENTITY,
      execution_ref: context.execution_ref,
      timestamp: new Date().toISOString(),
      details: isValidationError
        ? { validation_issues: (error as ValidationError).issues }
        : undefined,
    };
  }
}

// =============================================================================
// VALIDATION ERROR
// =============================================================================

class ValidationError extends Error {
  issues: unknown[];

  constructor(message: string, issues: unknown[]) {
    super(message);
    this.name = 'ValidationError';
    this.issues = issues;
  }
}

// =============================================================================
// EDGE FUNCTION HANDLER
// =============================================================================

/**
 * GCP Edge Function handler
 *
 * This is the entry point for the Google Cloud Edge Function deployment.
 */
export async function handleRequest(request: Request): Promise<Response> {
  // CORS headers
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };

  // Handle preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // Only allow POST
  if (request.method !== 'POST') {
    return new Response(
      JSON.stringify({ error: 'Method not allowed' }),
      {
        status: 405,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );
  }

  try {
    // Parse request body
    const body = await request.json();

    // Create agent and process
    const agent = new DataRedactionAgent();
    const result = await agent.process(body);

    // Check if error
    const isError = 'code' in result;

    return new Response(
      JSON.stringify(result),
      {
        status: isError ? 400 : 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';

    return new Response(
      JSON.stringify({
        code: 'INTERNAL_ERROR',
        message: errorMessage,
        timestamp: new Date().toISOString(),
      }),
      {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );
  }
}

// =============================================================================
// CLI HANDLER
// =============================================================================

/**
 * CLI handler for test/simulate/inspect modes
 */
export async function handleCli(
  mode: 'test' | 'simulate' | 'inspect',
  options: {
    content?: string;
    executionRef?: string;
    strategy?: string;
    sensitivity?: number;
    piiTypes?: string[];
    secretTypes?: string[];
    format?: 'json' | 'text' | 'table';
    verbose?: boolean;
  }
): Promise<string> {
  const agent = new DataRedactionAgent({
    skipPersistence: mode === 'test',
    skipTelemetry: mode === 'test',
  });

  switch (mode) {
    case 'test':
    case 'simulate': {
      if (!options.content) {
        throw new Error('Content is required for test/simulate mode');
      }

      const input: DataRedactionInput = {
        content: options.content,
        context: {
          execution_ref: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
        sensitivity: options.sensitivity,
        redaction_strategy: options.strategy as any,
        pii_types: options.piiTypes as any,
        secret_types: options.secretTypes as any,
      };

      const result = await agent.process(input);

      if (options.format === 'json') {
        return JSON.stringify(result, null, 2);
      } else {
        return formatTextOutput(result, options.verbose);
      }
    }

    case 'inspect': {
      if (!options.executionRef) {
        throw new Error('Execution reference is required for inspect mode');
      }
      // In a real implementation, this would query ruvector-service
      return JSON.stringify({
        message: 'Inspect mode requires ruvector-service query',
        execution_ref: options.executionRef,
      }, null, 2);
    }

    default:
      throw new Error(`Unknown mode: ${mode}`);
  }
}

/**
 * Format output as text
 */
function formatTextOutput(result: DataRedactionOutput | AgentErrorOutput, verbose?: boolean): string {
  if ('code' in result) {
    return `Error: ${result.code} - ${result.message}`;
  }

  const lines: string[] = [
    '🔒 Data Redaction Result',
    '─'.repeat(40),
    `Data Redacted: ${result.result.data_redacted ? 'Yes' : 'No'}`,
    `Redaction Count: ${result.result.redaction_count}`,
    `Severity: ${result.result.severity.toUpperCase()}`,
    `Risk Score: ${(result.result.original_risk_score * 100).toFixed(1)}%`,
    `Confidence: ${(result.result.confidence * 100).toFixed(1)}%`,
    `Duration: ${result.duration_ms.toFixed(2)}ms`,
  ];

  if (result.result.detected_categories.length > 0) {
    lines.push(`Categories: ${result.result.detected_categories.join(', ')}`);
  }

  if (verbose && result.result.redacted_entities.length > 0) {
    lines.push('', 'Redacted Entities:');
    for (const entity of result.result.redacted_entities) {
      lines.push(`  - ${entity.entity_type} (${entity.category}): ${entity.redacted_placeholder}`);
    }
  }

  if (result.result.redacted_content) {
    lines.push('', 'Redacted Content:', result.result.redacted_content);
  }

  return lines.join('\n');
}

// =============================================================================
// EXPORTS
// =============================================================================

export {
  Redactor,
  RuvectorClient,
  TelemetryEmitter,
  createRuvectorClient,
  createTelemetryEmitter,
  hashContent,
};

export type {
  RedactionConfig,
  RedactionResult,
  RedactionTelemetry,
  DecisionEventPayload,
};
