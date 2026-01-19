/**
 * @module credential-exposure-detection/handler
 * @description Edge Function handler for Credential Exposure Detection Agent
 *
 * Deployment: Google Cloud Edge Function
 * Classification: DETECTION-ONLY
 * Decision Type: credential_exposure_detection
 *
 * This agent:
 * - Inspects prompts, model outputs, and tool calls
 * - Detects credential patterns (usernames, passwords, auth headers)
 * - Calculates confidence scores
 * - Emits DecisionEvents to ruvector-service
 *
 * This agent MUST NOT:
 * - Modify, sanitize, or redact content
 * - Orchestrate workflows
 * - Trigger retries or alerts
 * - Modify policies
 * - Connect directly to databases
 * - Store raw credentials
 */

import { createHash } from 'crypto';
import {
  CredentialExposureDetectionInput,
  CredentialExposureDetectionResult,
  CredentialExposureDetectionAgentOutput,
  CredentialExposureDecisionEvent,
  CredentialExposureDetectedEntity,
  AgentIdentity,
  RiskFactor,
  Severity,
  type CredentialType,
  type AgentError,
} from '../../contracts/index.js';
import {
  CREDENTIAL_PATTERNS,
  getPatternsByCategory,
  getPairPatterns,
  getPasswordOnlyPatterns,
  getAuthHeaderPatterns,
  createCustomPattern,
  type CredentialPattern,
} from './patterns.js';
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
  agent_id: 'credential-exposure-detection-agent',
  agent_version: '1.0.0',
  classification: 'DETECTION_ONLY',
  decision_type: 'credential_exposure_detection',
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
 * Create redacted preview of a credential
 * Shows first 4 chars with **** (never reveals full credential)
 */
function redactCredential(value: string, type: 'username' | 'password'): string {
  if (value.length <= 4) {
    return type === 'password' ? '****' : value.charAt(0) + '***';
  }
  if (type === 'password') {
    return value.substring(0, 2) + '****';
  }
  return value.substring(0, 4) + '****';
}

/**
 * Calculate overall severity from detected entities
 */
function calculateOverallSeverity(entities: CredentialExposureDetectedEntity[]): Severity {
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
function calculateRiskScore(entities: CredentialExposureDetectedEntity[]): number {
  if (entities.length === 0) {
    return 0;
  }

  let totalWeight = 0;
  for (const entity of entities) {
    // Credential pairs are more risky
    const pairMultiplier = entity.is_credential_pair ? 1.5 : 1.0;
    totalWeight += SEVERITY_WEIGHTS[entity.severity] * entity.confidence * pairMultiplier;
  }

  // Normalize to 0-1 range with diminishing returns for multiple findings
  return Math.min(1, 1 - Math.exp(-totalWeight));
}

/**
 * Calculate overall confidence from entities
 */
function calculateOverallConfidence(entities: CredentialExposureDetectedEntity[]): number {
  if (entities.length === 0) {
    return 1.0; // High confidence that no credentials found
  }

  // Use highest confidence among detected entities
  return Math.max(...entities.map((e) => e.confidence));
}

/**
 * Run credential detection with patterns
 */
function detectCredentials(
  content: string,
  patterns: CredentialPattern[],
  sensitivity: number,
  minPasswordLength: number
): CredentialExposureDetectedEntity[] {
  const entities: CredentialExposureDetectedEntity[] = [];
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

      // For password patterns, check minimum length
      if (pattern.detects_password && !pattern.is_pair) {
        // Extract the captured group (password value) if available
        const capturedValue = match[1] || matchedText;
        if (capturedValue.length < minPasswordLength) {
          continue; // Skip short passwords
        }
      }

      // Adjust confidence based on sensitivity
      const adjustedConfidence = pattern.confidence * (0.5 + sensitivity * 0.5);

      // Create redacted preview
      let redactedPreview: string | undefined;
      if (pattern.is_pair && match[1] && match[2]) {
        redactedPreview = `${redactCredential(match[1], 'username')}:${redactCredential(match[2], 'password')}`;
      } else if (pattern.detects_password && match[1]) {
        redactedPreview = redactCredential(match[1], 'password');
      } else if (pattern.detects_username && match[1]) {
        redactedPreview = redactCredential(match[1], 'username');
      }

      entities.push({
        credential_type: pattern.category,
        category: pattern.category,
        start: match.index,
        end: match.index + matchedText.length,
        confidence: Math.min(1, adjustedConfidence),
        pattern_id: pattern.pattern_id,
        severity: pattern.severity,
        is_credential_pair: pattern.is_pair,
        has_username: pattern.detects_username,
        has_password: pattern.detects_password,
        redacted_preview: redactedPreview,
        context_hint: pattern.context_hint,
      });
    }
  }

  return entities;
}

/**
 * Build risk factors from detected entities
 */
function buildRiskFactors(
  entities: CredentialExposureDetectedEntity[]
): RiskFactor[] {
  const categoryMap = new Map<string, CredentialExposureDetectedEntity[]>();

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
    const pairCount = categoryEntities.filter((e) => e.is_credential_pair).length;

    let description = `Detected ${categoryEntities.length} ${category.replace(/_/g, ' ')} exposure(s)`;
    if (pairCount > 0) {
      description += ` (${pairCount} complete credential pair(s))`;
    }

    factors.push({
      factor_id: `credential-${category}`,
      category: 'credential_exposure',
      description,
      severity: maxSeverity,
      score_contribution: SEVERITY_WEIGHTS[maxSeverity] * avgConfidence,
      confidence: avgConfidence,
    });
  }

  return factors;
}

/**
 * Build exposure summary from entities
 */
function buildExposureSummary(entities: CredentialExposureDetectedEntity[]): {
  username_exposures: number;
  password_exposures: number;
  auth_header_exposures: number;
  hardcoded_exposures: number;
} {
  let username_exposures = 0;
  let password_exposures = 0;
  let auth_header_exposures = 0;
  let hardcoded_exposures = 0;

  for (const entity of entities) {
    if (entity.has_username) {
      username_exposures++;
    }
    if (entity.has_password) {
      password_exposures++;
    }
    if (entity.category === 'basic_auth' || entity.category === 'bearer_token') {
      auth_header_exposures++;
    }
    if (entity.category === 'hardcoded_credential') {
      hardcoded_exposures++;
    }
  }

  return {
    username_exposures,
    password_exposures,
    auth_header_exposures,
    hardcoded_exposures,
  };
}

/**
 * Build DecisionEvent for persistence
 *
 * CRITICAL: This must NOT contain raw credentials
 */
function buildDecisionEvent(
  input: CredentialExposureDetectionInput,
  result: CredentialExposureDetectionResult,
  durationMs: number
): CredentialExposureDecisionEvent {
  return {
    agent_id: 'credential-exposure-detection-agent',
    agent_version: AGENT_IDENTITY.agent_version,
    decision_type: 'credential_exposure_detection',
    inputs_hash: hashContent(input.content),
    outputs: {
      credentials_detected: result.credentials_detected,
      risk_score: result.risk_score,
      severity: result.severity,
      confidence: result.confidence,
      pattern_match_count: result.pattern_match_count,
      detected_types: result.detected_types,
      entity_count: result.entities.length,
      type_counts: result.type_counts,
      credential_pair_count: result.credential_pair_count,
      exposure_summary: result.exposure_summary,
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
      types_checked: input.detect_types,
      detection_flags: {
        password_patterns: input.detect_password_patterns ?? true,
        username_patterns: input.detect_username_patterns ?? true,
        auth_headers: input.detect_auth_headers ?? true,
        credential_pairs: input.detect_credential_pairs ?? true,
      },
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
): Promise<CredentialExposureDetectionAgentOutput | AgentError> {
  const startTime = performance.now();

  // Initialize clients
  const ruvectorClient =
    config.ruvectorClient ||
    (config.skipPersistence ? createNoOpClient() : createClientFromEnv());
  const telemetryEmitter =
    config.telemetryEmitter || createTelemetryEmitter();

  // Validate input
  const parseResult = CredentialExposureDetectionInput.safeParse(rawInput);

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
    // Build pattern set based on configuration
    let patterns: CredentialPattern[] = [];

    // Add patterns based on detection flags
    if (input.detect_credential_pairs ?? true) {
      patterns.push(...getPairPatterns());
    }
    if (input.detect_password_patterns ?? true) {
      patterns.push(...getPasswordOnlyPatterns());
    }
    if (input.detect_auth_headers ?? true) {
      patterns.push(...getAuthHeaderPatterns());
    }

    // Filter by category if specified
    if (input.detect_types && input.detect_types.length > 0) {
      patterns = patterns.filter((p) => input.detect_types!.includes(p.category));
    }

    // If no patterns selected (e.g., all flags false), use all patterns by category
    if (patterns.length === 0) {
      patterns = getPatternsByCategory(input.detect_types);
    }

    // Add custom patterns if provided
    if (input.custom_patterns) {
      for (const [patternId, regexStr] of Object.entries(input.custom_patterns)) {
        const customPattern = createCustomPattern(patternId, regexStr);
        if (customPattern) {
          patterns.push(customPattern);
        }
      }
    }

    // Run detection
    const entities = detectCredentials(
      input.content,
      patterns,
      input.sensitivity ?? 0.5,
      input.min_password_length ?? 6
    );

    // Build result
    const detectedTypes = [...new Set(entities.map((e) => e.credential_type))] as CredentialType[];
    const riskFactors = buildRiskFactors(entities);
    const exposureSummary = buildExposureSummary(entities);

    // Calculate type counts
    const typeCounts: Record<string, number> = {};
    for (const entity of entities) {
      typeCounts[entity.category] = (typeCounts[entity.category] || 0) + 1;
    }

    // Count credential pairs
    const credentialPairCount = entities.filter((e) => e.is_credential_pair).length;

    const result: CredentialExposureDetectionResult = {
      credentials_detected: entities.length > 0,
      risk_score: calculateRiskScore(entities),
      severity: calculateOverallSeverity(entities),
      confidence: calculateOverallConfidence(entities),
      entities,
      risk_factors: riskFactors,
      pattern_match_count: entities.length,
      detected_types: detectedTypes,
      type_counts: typeCounts,
      credential_pair_count: credentialPairCount,
      exposure_summary: exposureSummary,
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
      result.credentials_detected,
      entities.length,
      detectedTypes,
      result.severity
    );

    // Return output
    const output: CredentialExposureDetectionAgentOutput = {
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
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
      });
    }

    if (request.method !== 'POST') {
      return new Response(
        JSON.stringify({ error: 'Method not allowed' }),
        {
          status: 405,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        }
      );
    }

    try {
      const body = await request.json();
      const result = await handleDetection(body);

      const isError = 'code' in result;

      return new Response(JSON.stringify(result), {
        status: isError ? 400 : 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
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
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        }
      );
    }
  },
};
