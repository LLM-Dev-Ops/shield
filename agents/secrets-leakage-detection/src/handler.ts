/**
 * @module secrets-leakage-detection/handler
 * @description Edge Function handler for Secrets Leakage Detection Agent
 *
 * Deployment: Google Cloud Edge Function
 * Classification: DETECTION-ONLY
 * Decision Type: secret_detection
 *
 * This agent:
 * - Inspects prompts, model outputs, and tool calls
 * - Detects secret patterns using regex and entropy analysis
 * - Calculates confidence scores
 * - Emits DecisionEvents to ruvector-service
 *
 * This agent MUST NOT:
 * - Modify, sanitize, or redact content
 * - Orchestrate workflows
 * - Trigger retries or alerts
 * - Modify policies
 * - Connect directly to databases
 * - Store raw secrets
 */

import { createHash } from 'crypto';
import {
  SecretsLeakageDetectionInput,
  AgentOutput,
  AgentError,
  DecisionEvent,
  AgentIdentity,
  DetectionResult,
  DetectedSecretEntity,
  RiskFactor,
  Severity,
  type SecretTypeCategory,
} from '../../contracts/index.js';
import {
  SECRET_PATTERNS,
  getPatternsByCategory,
  createCustomPattern,
  type SecretPattern,
} from './patterns.js';
import { findEntropySecrets, calculateEntropy } from './entropy.js';
import {
  RuVectorClient,
  createClientFromEnv,
  createNoOpClient,
} from './ruvector-client.js';
import {
  TelemetryEmitter,
  createTelemetryEmitter,
  emitDetectionStarted,
  emitDetectionCompleted,
  emitDetectionError,
} from './telemetry.js';

/**
 * Agent identity constants
 */
const AGENT_IDENTITY: AgentIdentity = {
  agent_id: 'secrets-leakage-detection-agent',
  agent_version: '1.0.0',
  classification: 'DETECTION_ONLY',
  decision_type: 'secret_detection',
};

/**
 * Severity weights for risk score calculation
 */
const SEVERITY_WEIGHTS: Record<Severity, number> = {
  none: 0,
  low: 0.2,
  medium: 0.4,
  high: 0.7,
  critical: 1.0,
};

/**
 * Handler configuration
 */
export interface HandlerConfig {
  /** ruvector-service client */
  ruvectorClient?: RuVectorClient;
  /** Telemetry emitter */
  telemetryEmitter?: TelemetryEmitter;
  /** Skip persistence (for testing) */
  skipPersistence?: boolean;
}

/**
 * Create SHA-256 hash of content
 * Used for inputs_hash in DecisionEvent (never raw content)
 */
function hashContent(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Create redacted preview of a secret
 * Shows first 4 and last 4 chars with **** in middle
 */
function redactSecret(secret: string): string {
  if (secret.length <= 8) {
    return '****';
  }
  return `${secret.substring(0, 4)}****${secret.substring(secret.length - 4)}`;
}

/**
 * Calculate overall severity from detected entities
 */
function calculateOverallSeverity(entities: DetectedSecretEntity[]): Severity {
  if (entities.length === 0) {
    return 'none';
  }

  const severityOrder: Severity[] = ['none', 'low', 'medium', 'high', 'critical'];
  let maxIndex = 0;

  for (const entity of entities) {
    const index = severityOrder.indexOf(entity.severity);
    if (index > maxIndex) {
      maxIndex = index;
    }
  }

  return severityOrder[maxIndex];
}

/**
 * Calculate risk score from entities
 */
function calculateRiskScore(entities: DetectedSecretEntity[]): number {
  if (entities.length === 0) {
    return 0;
  }

  let totalWeight = 0;
  for (const entity of entities) {
    totalWeight += SEVERITY_WEIGHTS[entity.severity] * entity.confidence;
  }

  // Normalize to 0-1 range with diminishing returns for multiple findings
  return Math.min(1, 1 - Math.exp(-totalWeight));
}

/**
 * Calculate overall confidence from entities
 */
function calculateOverallConfidence(entities: DetectedSecretEntity[]): number {
  if (entities.length === 0) {
    return 1.0; // High confidence that no secrets found
  }

  // Use highest confidence among detected entities
  return Math.max(...entities.map((e) => e.confidence));
}

/**
 * Run pattern-based detection
 */
function detectPatternSecrets(
  content: string,
  patterns: SecretPattern[],
  sensitivity: number
): DetectedSecretEntity[] {
  const entities: DetectedSecretEntity[] = [];
  const seen = new Set<string>();

  for (const pattern of patterns) {
    // Reset regex state
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const matchedText = match[0];
      const key = `${pattern.pattern_id}:${match.index}`;

      if (seen.has(key)) {
        continue;
      }
      seen.add(key);

      // Adjust confidence based on sensitivity
      const adjustedConfidence = pattern.confidence * (0.5 + sensitivity * 0.5);

      entities.push({
        entity_type: 'secret',
        category: pattern.category,
        start: match.index,
        end: match.index + matchedText.length,
        confidence: Math.min(1, adjustedConfidence),
        pattern_id: pattern.pattern_id,
        severity: pattern.severity,
        secret_type: pattern.category as SecretTypeCategory,
        entropy_based: false,
        redacted_preview: redactSecret(matchedText),
      });
    }
  }

  return entities;
}

/**
 * Run entropy-based detection
 */
function detectEntropySecrets(
  content: string,
  threshold: number,
  sensitivity: number
): DetectedSecretEntity[] {
  const candidates = findEntropySecrets(content, threshold);
  const entities: DetectedSecretEntity[] = [];

  for (const candidate of candidates) {
    // Base confidence on how much entropy exceeds threshold
    const entropyExcess = (candidate.entropy - threshold) / (8 - threshold);
    const baseConfidence = 0.5 + entropyExcess * 0.4;
    const adjustedConfidence = baseConfidence * (0.5 + sensitivity * 0.5);

    entities.push({
      entity_type: 'secret',
      category: 'generic_secret',
      start: candidate.start,
      end: candidate.end,
      confidence: Math.min(1, adjustedConfidence),
      pattern_id: 'entropy-detection',
      severity: 'medium',
      secret_type: 'generic_secret',
      entropy_based: true,
      entropy_value: candidate.entropy,
      redacted_preview: redactSecret(candidate.value),
    });
  }

  return entities;
}

/**
 * Build risk factors from detected entities
 */
function buildRiskFactors(
  entities: DetectedSecretEntity[]
): RiskFactor[] {
  const categoryMap = new Map<string, DetectedSecretEntity[]>();

  // Group by category
  for (const entity of entities) {
    const list = categoryMap.get(entity.category) || [];
    list.push(entity);
    categoryMap.set(entity.category, list);
  }

  const factors: RiskFactor[] = [];

  for (const [category, categoryEntities] of categoryMap) {
    const maxSeverity = calculateOverallSeverity(categoryEntities);
    const avgConfidence =
      categoryEntities.reduce((sum, e) => sum + e.confidence, 0) /
      categoryEntities.length;

    factors.push({
      factor_id: `secret-${category}`,
      category: 'credential_exposure',
      description: `Detected ${categoryEntities.length} ${category.replace(/_/g, ' ')} exposure(s)`,
      severity: maxSeverity,
      score_contribution: SEVERITY_WEIGHTS[maxSeverity] * avgConfidence,
      confidence: avgConfidence,
    });
  }

  return factors;
}

/**
 * Build DecisionEvent for persistence
 *
 * CRITICAL: This must NOT contain raw secrets
 */
function buildDecisionEvent(
  input: SecretsLeakageDetectionInput,
  result: DetectionResult,
  durationMs: number
): DecisionEvent {
  return {
    agent_id: AGENT_IDENTITY.agent_id,
    agent_version: AGENT_IDENTITY.agent_version,
    decision_type: AGENT_IDENTITY.decision_type,
    inputs_hash: hashContent(input.content),
    outputs: {
      threats_detected: result.threats_detected,
      risk_score: result.risk_score,
      severity: result.severity,
      confidence: result.confidence,
      pattern_match_count: result.pattern_match_count,
      detected_categories: result.detected_categories,
      entity_count: result.entities.length,
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
    },
  };
}

/**
 * Main detection handler
 *
 * This is the Edge Function entry point.
 */
export async function handleDetection(
  rawInput: unknown,
  config: HandlerConfig = {}
): Promise<AgentOutput | AgentError> {
  const startTime = performance.now();

  // Initialize clients
  const ruvectorClient =
    config.ruvectorClient ||
    (config.skipPersistence ? createNoOpClient() : createClientFromEnv());
  const telemetryEmitter =
    config.telemetryEmitter || createTelemetryEmitter();

  // Validate input
  const parseResult = SecretsLeakageDetectionInput.safeParse(rawInput);

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

  // Emit telemetry
  emitDetectionStarted(
    telemetryEmitter,
    input.context.execution_ref,
    input.content.length,
    input.context.content_source
  );

  try {
    // Get patterns based on configuration
    const patterns = getPatternsByCategory(input.detect_categories);

    // Add custom patterns if provided
    if (input.custom_patterns) {
      for (const [patternId, regexStr] of Object.entries(input.custom_patterns)) {
        const customPattern = createCustomPattern(patternId, regexStr);
        if (customPattern) {
          patterns.push(customPattern);
        }
      }
    }

    // Run pattern detection
    const patternEntities = detectPatternSecrets(
      input.content,
      patterns,
      input.sensitivity ?? 0.5
    );

    // Run entropy detection if enabled
    let entropyEntities: DetectedSecretEntity[] = [];
    if (input.entropy_detection !== false) {
      entropyEntities = detectEntropySecrets(
        input.content,
        input.entropy_threshold ?? 4.5,
        input.sensitivity ?? 0.5
      );
    }

    // Merge entities (pattern detection takes precedence)
    const allEntities = [...patternEntities];

    // Add entropy entities that don't overlap with pattern entities
    for (const entropyEntity of entropyEntities) {
      const overlaps = patternEntities.some(
        (pe) =>
          (entropyEntity.start >= pe.start && entropyEntity.start < pe.end) ||
          (entropyEntity.end > pe.start && entropyEntity.end <= pe.end)
      );

      if (!overlaps) {
        allEntities.push(entropyEntity);
      }
    }

    // Build result
    const detectedCategories = [...new Set(allEntities.map((e) => e.category))];
    const riskFactors = buildRiskFactors(allEntities);

    const result: DetectionResult = {
      threats_detected: allEntities.length > 0,
      risk_score: calculateRiskScore(allEntities),
      severity: calculateOverallSeverity(allEntities),
      confidence: calculateOverallConfidence(allEntities),
      entities: allEntities,
      risk_factors: riskFactors,
      pattern_match_count: allEntities.length,
      detected_categories: detectedCategories,
    };

    const durationMs = performance.now() - startTime;

    // Persist decision event
    const decisionEvent = buildDecisionEvent(input, result, durationMs);
    await ruvectorClient.persistDecisionEvent(decisionEvent);

    // Emit completion telemetry
    emitDetectionCompleted(
      telemetryEmitter,
      input.context.execution_ref,
      durationMs,
      result.threats_detected,
      allEntities.length,
      detectedCategories
    );

    // Return output
    const output: AgentOutput = {
      agent: AGENT_IDENTITY,
      result,
      duration_ms: durationMs,
      cached: false,
    };

    return output;
  } catch (error) {
    const durationMs = performance.now() - startTime;

    emitDetectionError(
      telemetryEmitter,
      input.context.execution_ref,
      'INTERNAL_ERROR',
      error instanceof Error ? error.message : 'Unknown error'
    );

    return {
      code: 'INTERNAL_ERROR',
      message: error instanceof Error ? error.message : 'Unknown error',
      agent: AGENT_IDENTITY,
      execution_ref: input.context.execution_ref,
      timestamp: new Date().toISOString(),
    };
  }
}

/**
 * Edge Function export
 *
 * Compatible with Google Cloud Functions, Cloudflare Workers, Vercel Edge
 */
export default {
  async fetch(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return new Response(
        JSON.stringify({ error: 'Method not allowed' }),
        {
          status: 405,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    try {
      const body = await request.json();
      const result = await handleDetection(body);

      const isError = 'code' in result;

      return new Response(JSON.stringify(result), {
        status: isError ? 400 : 200,
        headers: { 'Content-Type': 'application/json' },
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
