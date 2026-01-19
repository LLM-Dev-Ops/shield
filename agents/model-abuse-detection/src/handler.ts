/**
 * @module handler
 * @description Google Cloud Edge Function handler for Model Abuse Detection Agent
 *
 * This module implements the HTTP handler for the agent, designed to be deployed
 * as a Google Cloud Edge Function. It is stateless and deterministic.
 */

import { createHash } from 'crypto';
import {
  ModelAbuseDetectionInput,
  ModelAbuseDetectionAgentOutput,
  ModelAbuseDetectionDecisionEvent,
  ModelAbuseDetectionResult,
  AgentError,
  AgentIdentity,
  type ModelAbuseCategory,
  type Severity,
  type PolicyReference,
} from '@llm-shield/agentics-contracts';
import { createDetector, type BehavioralSummary } from './detector.js';
import {
  RuVectorClient,
  createClientFromEnv,
  createNoOpClient,
} from './ruvector-client.js';
import {
  TelemetryEmitter,
  createTelemetryEmitterFromEnv,
  emitDetectionStarted,
  emitDetectionCompleted,
  emitDetectionError,
  emitBehavioralAnalysisCompleted,
} from './telemetry.js';

/**
 * Agent identity constant
 */
export const AGENT_IDENTITY: AgentIdentity = {
  agent_id: 'model-abuse-detection-agent',
  agent_version: '1.0.0',
  classification: 'DETECTION_ONLY',
  decision_type: 'model_abuse_detection',
};

/**
 * Handler configuration
 */
export interface HandlerConfig {
  /** RuVector client (optional, created from env if not provided) */
  ruvectorClient?: RuVectorClient;
  /** Telemetry emitter (optional, created from env if not provided) */
  telemetryEmitter?: TelemetryEmitter;
  /** Skip persistence (for simulation mode) */
  skipPersistence?: boolean;
  /** Skip telemetry */
  skipTelemetry?: boolean;
}

/**
 * Hash content for persistence (never store raw content)
 */
function hashContent(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Categorize request rate into buckets (for anonymized telemetry)
 */
function categorizeRequestRate(rate?: number): string | undefined {
  if (rate === undefined) return undefined;
  if (rate < 10) return 'low';
  if (rate < 30) return 'medium';
  if (rate < 60) return 'high';
  return 'extreme';
}

/**
 * Categorize session requests into buckets (for anonymized telemetry)
 */
function categorizeSessionRequests(count?: number): string | undefined {
  if (count === undefined) return undefined;
  if (count < 10) return 'few';
  if (count < 50) return 'some';
  if (count < 100) return 'many';
  return 'excessive';
}

/**
 * Build DecisionEvent for persistence
 */
function buildDecisionEvent(
  input: ReturnType<typeof ModelAbuseDetectionInput.parse>,
  result: ModelAbuseDetectionResult,
  durationMs: number
): ModelAbuseDetectionDecisionEvent {
  const event: ModelAbuseDetectionDecisionEvent = {
    agent_id: 'model-abuse-detection-agent',
    agent_version: AGENT_IDENTITY.agent_version,
    decision_type: 'model_abuse_detection',
    inputs_hash: hashContent(input.content),
    outputs: {
      abuse_detected: result.abuse_detected,
      risk_score: result.risk_score,
      severity: result.severity,
      confidence: result.confidence,
      pattern_match_count: result.pattern_match_count,
      detected_categories: result.detected_categories,
      entity_count: result.entities.length,
      category_counts: result.category_counts,
      behavioral_summary: result.behavioral_summary
        ? {
            appears_automated: result.behavioral_summary.appears_automated,
            abnormal_rate: result.behavioral_summary.abnormal_rate,
            matches_abuse_signature: result.behavioral_summary.matches_abuse_signature,
            red_flag_count: result.behavioral_summary.red_flag_count,
          }
        : undefined,
    },
    confidence: result.confidence,
    constraints_applied: input.context.policies || [],
    execution_ref: input.context.execution_ref,
    timestamp: input.context.timestamp,
    duration_ms: durationMs,
    telemetry: {
      content_length: input.content.length,
      content_source: input.context.content_source,
      session_id: input.context.session_id,
      caller_id: input.context.caller_id,
      threshold_used: input.threshold,
      categories_checked: input.detect_categories,
      request_rate_bucket: categorizeRequestRate(input.request_metadata?.request_rate),
      session_request_bucket: categorizeSessionRequests(
        input.request_metadata?.session_request_count
      ),
    },
  };

  return event;
}

/**
 * Handle detection request
 *
 * This is the main entry point for the agent. It:
 * 1. Validates input against schema
 * 2. Performs detection
 * 3. Persists decision event to ruvector-service
 * 4. Emits telemetry
 * 5. Returns result
 */
export async function handleDetection(
  rawInput: unknown,
  config: HandlerConfig = {}
): Promise<ModelAbuseDetectionAgentOutput | AgentError> {
  const startTime = performance.now();

  // Initialize clients
  const ruvectorClient =
    config.ruvectorClient ||
    (config.skipPersistence ? createNoOpClient() : createClientFromEnv());
  const telemetryEmitter =
    config.telemetryEmitter ||
    (config.skipTelemetry ? { emit: () => {}, flush: async () => {}, shutdown: async () => {} } : createTelemetryEmitterFromEnv());

  // Validate input
  const parseResult = ModelAbuseDetectionInput.safeParse(rawInput);

  if (!parseResult.success) {
    const error: AgentError = {
      code: 'INVALID_INPUT',
      message: 'Input validation failed',
      agent: AGENT_IDENTITY,
      timestamp: new Date().toISOString(),
      details: {
        errors: parseResult.error.errors.map((e) => ({
          path: e.path.join('.'),
          message: e.message,
        })),
      },
    };

    return error;
  }

  const input = parseResult.data;

  // Emit detection started telemetry
  emitDetectionStarted(
    telemetryEmitter as TelemetryEmitter,
    input.context.execution_ref,
    input.content.length,
    input.context.content_source
  );

  try {
    // Create detector and run detection
    const detector = createDetector();

    const { entities, riskFactors, behavioralSummary } = detector.detect(
      input.content,
      {
        sensitivity: input.sensitivity ?? 0.5,
        threshold: input.threshold ?? 0.7,
        categories: input.detect_categories,
      },
      input.request_metadata
        ? {
            requestRate: input.request_metadata.request_rate,
            clientIpHash: input.request_metadata.client_ip_hash,
            userAgentHash: input.request_metadata.user_agent_hash,
            sessionRequestCount: input.request_metadata.session_request_count,
            sessionTokenUsage: input.request_metadata.session_token_usage,
            appearsAutomated: input.request_metadata.appears_automated,
            apiEndpoint: input.request_metadata.api_endpoint,
            requestTimestamp: input.request_metadata.request_timestamp,
          }
        : undefined,
      input.historical_context
        ? {
            previousRequestCount: input.historical_context.previous_request_count,
            previousViolationCount: input.historical_context.previous_violation_count,
            sessionDurationSeconds: input.historical_context.session_duration_seconds,
          }
        : undefined
    );

    // Calculate aggregated metrics
    const riskScore = detector.calculateRiskScore(entities, behavioralSummary);
    const maxSeverity = detector.getMaxSeverity(entities);
    const overallConfidence = detector.calculateOverallConfidence(entities);
    const detectedCategories = detector.getDetectedCategories(entities);
    const categoryCounts = detector.getCategoryCounts(entities);

    // Build result
    const result: ModelAbuseDetectionResult = {
      abuse_detected: entities.length > 0,
      risk_score: riskScore,
      severity: maxSeverity,
      confidence: overallConfidence,
      entities,
      risk_factors: riskFactors,
      pattern_match_count: entities.length,
      detected_categories: detectedCategories,
      category_counts: categoryCounts,
      behavioral_summary: behavioralSummary,
    };

    const durationMs = performance.now() - startTime;

    // Persist decision event
    const decisionEvent = buildDecisionEvent(input, result, durationMs);
    await ruvectorClient.persistDecisionEvent(decisionEvent);

    // Emit telemetry
    emitDetectionCompleted(
      telemetryEmitter as TelemetryEmitter,
      input.context.execution_ref,
      durationMs,
      result.abuse_detected,
      entities.length,
      detectedCategories,
      riskScore
    );

    emitBehavioralAnalysisCompleted(
      telemetryEmitter as TelemetryEmitter,
      input.context.execution_ref,
      behavioralSummary.appearsAutomated,
      behavioralSummary.abnormalRate,
      behavioralSummary.redFlagCount
    );

    // Build output
    const output: ModelAbuseDetectionAgentOutput = {
      agent: AGENT_IDENTITY,
      result,
      duration_ms: Math.round(durationMs * 100) / 100,
      cached: false,
    };

    return output;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';

    emitDetectionError(
      telemetryEmitter as TelemetryEmitter,
      input.context.execution_ref,
      'INTERNAL_ERROR',
      errorMessage
    );

    const agentError: AgentError = {
      code: 'INTERNAL_ERROR',
      message: errorMessage,
      agent: AGENT_IDENTITY,
      execution_ref: input.context.execution_ref,
      timestamp: new Date().toISOString(),
    };

    return agentError;
  }
}

/**
 * Google Cloud Edge Function export
 *
 * This is the entry point for the Edge Function.
 * It handles HTTP requests and returns responses.
 */
export default {
  async fetch(request: Request): Promise<Response> {
    // Only accept POST requests
    if (request.method !== 'POST') {
      return new Response(
        JSON.stringify({
          code: 'INVALID_INPUT',
          message: 'Method not allowed. Use POST.',
          timestamp: new Date().toISOString(),
        }),
        {
          status: 405,
          headers: {
            'Content-Type': 'application/json',
            Allow: 'POST',
          },
        }
      );
    }

    try {
      const body = await request.json();
      const result = await handleDetection(body);

      // Check if result is an error
      const isError = 'code' in result;

      return new Response(JSON.stringify(result), {
        status: isError ? (result as AgentError).code === 'INVALID_INPUT' ? 400 : 500 : 200,
        headers: {
          'Content-Type': 'application/json',
          'X-Agent-ID': AGENT_IDENTITY.agent_id,
          'X-Agent-Version': AGENT_IDENTITY.agent_version,
        },
      });
    } catch (error) {
      return new Response(
        JSON.stringify({
          code: 'INVALID_INPUT',
          message: 'Invalid JSON body',
          timestamp: new Date().toISOString(),
        }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }
  },
};
