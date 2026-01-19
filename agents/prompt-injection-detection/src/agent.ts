/**
 * @module agent
 * @description Prompt Injection Detection Agent implementation
 *
 * Classification: DETECTION_ONLY
 * Decision Type: prompt_injection_detection
 *
 * This agent detects prompt injection attempts in LLM input content.
 * It does NOT modify, sanitize, or block content - detection only.
 */

import { createHash } from 'crypto';
import {
  type AgentIdentity,
  type AgentOutput,
  type DecisionEvent,
  type DetectedEntity,
  type RiskFactor,
  type PromptInjectionDetectionInput,
  type AgentError,
  type Severity,
  PromptInjectionDetectionInput as PromptInjectionDetectionInputSchema,
} from '@llm-shield/agentics-contracts';
import {
  DETECTION_PATTERNS,
  type DetectionPattern,
  type Category,
  CATEGORIES,
  getPatternsForCategories,
} from './patterns.js';
import { RuVectorClient, type RuVectorClientConfig } from './ruvector-client.js';
import { TelemetryEmitter, type TelemetryConfig } from './telemetry.js';

/**
 * Agent identity constant
 */
export const AGENT_IDENTITY: AgentIdentity = {
  agent_id: 'prompt-injection-detection-agent',
  agent_version: '1.0.0',
  classification: 'DETECTION_ONLY',
  decision_type: 'prompt_injection_detection',
};

/**
 * Agent configuration
 */
export interface AgentConfig {
  /** ruvector-service client configuration */
  ruvectorConfig?: Partial<RuVectorClientConfig>;
  /** Telemetry configuration */
  telemetryConfig?: Partial<TelemetryConfig>;
  /** Default sensitivity (0.0 - 1.0) */
  defaultSensitivity?: number;
  /** Enable detailed pattern matching telemetry */
  detailedTelemetry?: boolean;
}

/**
 * Match result from pattern detection
 */
interface PatternMatch {
  pattern: DetectionPattern;
  match: RegExpMatchArray;
  start: number;
  end: number;
}

/**
 * Prompt Injection Detection Agent
 *
 * Responsibilities:
 * - Detect prompt injection patterns in input content
 * - Calculate risk scores and confidence levels
 * - Emit DecisionEvents to ruvector-service
 * - Emit telemetry to LLM-Observatory
 *
 * Non-Responsibilities:
 * - Does NOT modify content
 * - Does NOT block or allow content
 * - Does NOT orchestrate workflows
 * - Does NOT retry operations
 * - Does NOT connect to databases directly
 */
export class PromptInjectionDetectionAgent {
  private readonly ruvectorClient: RuVectorClient;
  private readonly telemetry: TelemetryEmitter;
  private readonly config: Required<AgentConfig>;

  constructor(config: AgentConfig = {}) {
    this.config = {
      ruvectorConfig: config.ruvectorConfig ?? {},
      telemetryConfig: config.telemetryConfig ?? {},
      defaultSensitivity: config.defaultSensitivity ?? 0.5,
      detailedTelemetry: config.detailedTelemetry ?? false,
    };

    this.ruvectorClient = new RuVectorClient(this.config.ruvectorConfig);
    this.telemetry = new TelemetryEmitter(AGENT_IDENTITY, {
      ...this.config.telemetryConfig,
      detailedMetrics: this.config.detailedTelemetry,
    });
  }

  /**
   * Execute detection on input content
   *
   * @param input - Validated input conforming to PromptInjectionDetectionInput schema
   * @returns AgentOutput with detection results
   */
  async detect(input: PromptInjectionDetectionInput): Promise<AgentOutput> {
    const startTime = performance.now();

    // Emit start telemetry
    this.telemetry.emitInvocationStart(
      input.context.execution_ref,
      input.content.length,
      input.context.content_source
    );

    try {
      // Get patterns for requested categories
      const patterns = this.getActivePatterns(input.detect_categories);
      const sensitivity = input.sensitivity ?? this.config.defaultSensitivity;

      // Execute pattern matching
      const matches = this.findMatches(input.content, patterns);

      // Build detection results
      const entities = this.buildEntities(matches, sensitivity);
      const riskFactors = this.buildRiskFactors(matches, sensitivity);

      // Calculate aggregated scores
      const riskScore = this.calculateRiskScore(riskFactors, sensitivity);
      const confidence = this.calculateConfidence(matches, sensitivity);
      const severity = this.determineSeverity(riskScore);
      const detectedCategories = [...new Set(matches.map((m) => m.pattern.category))];

      const durationMs = performance.now() - startTime;

      // Build output
      const output: AgentOutput = {
        agent: AGENT_IDENTITY,
        result: {
          threats_detected: entities.length > 0,
          risk_score: riskScore,
          severity,
          confidence,
          entities,
          risk_factors: riskFactors,
          pattern_match_count: matches.length,
          detected_categories: detectedCategories,
        },
        duration_ms: durationMs,
        cached: false,
      };

      // Persist DecisionEvent
      await this.persistDecisionEvent(input, output, durationMs);

      // Emit completion telemetry
      this.telemetry.emitInvocationComplete(
        input.context.execution_ref,
        durationMs,
        output.result.threats_detected,
        output.result.risk_score,
        output.result.pattern_match_count
      );

      return output;
    } catch (error) {
      const durationMs = performance.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : String(error);

      this.telemetry.emitInvocationError(
        input.context.execution_ref,
        'INTERNAL_ERROR',
        errorMessage
      );

      throw error;
    }
  }

  /**
   * Validate input against schema
   */
  validateInput(input: unknown): PromptInjectionDetectionInput {
    const result = PromptInjectionDetectionInputSchema.safeParse(input);

    if (!result.success) {
      const error: AgentError = {
        code: 'VALIDATION_FAILED',
        message: 'Input validation failed',
        agent: AGENT_IDENTITY,
        timestamp: new Date().toISOString(),
        details: {
          errors: result.error.errors.map((e) => ({
            path: e.path.join('.'),
            message: e.message,
          })),
        },
      };
      throw error;
    }

    return result.data;
  }

  /**
   * Shutdown agent gracefully
   */
  async shutdown(): Promise<void> {
    await this.telemetry.shutdown();
  }

  // ===========================================================================
  // Private Methods
  // ===========================================================================

  private getActivePatterns(categories?: string[]): DetectionPattern[] {
    if (!categories || categories.length === 0) {
      return DETECTION_PATTERNS;
    }

    // Map string categories to Category type
    const validCategories = categories.filter((c) =>
      Object.values(CATEGORIES).includes(c as Category)
    ) as Category[];

    if (validCategories.length === 0) {
      return DETECTION_PATTERNS;
    }

    return getPatternsForCategories(validCategories);
  }

  private findMatches(
    content: string,
    patterns: DetectionPattern[]
  ): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const pattern of patterns) {
      const regex = new RegExp(pattern.pattern, 'gi');
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        matches.push({
          pattern,
          match,
          start: match.index,
          end: match.index + match[0].length,
        });

        // Emit detailed telemetry if enabled
        if (this.config.detailedTelemetry) {
          // Pattern match telemetry is handled by emitter
        }
      }
    }

    return matches;
  }

  private buildEntities(
    matches: PatternMatch[],
    sensitivity: number
  ): DetectedEntity[] {
    return matches.map((m) => ({
      entity_type: 'prompt_injection',
      category: m.pattern.category,
      start: m.start,
      end: m.end,
      confidence: this.adjustConfidence(m.pattern.confidence, sensitivity),
      pattern_id: m.pattern.id,
      severity: this.determineSeverity(m.pattern.severity),
    }));
  }

  private buildRiskFactors(
    matches: PatternMatch[],
    sensitivity: number
  ): RiskFactor[] {
    // Group matches by category
    const byCategory = new Map<string, PatternMatch[]>();
    for (const match of matches) {
      const category = match.pattern.category;
      if (!byCategory.has(category)) {
        byCategory.set(category, []);
      }
      byCategory.get(category)!.push(match);
    }

    // Build risk factors per category
    const factors: RiskFactor[] = [];
    for (const [category, categoryMatches] of byCategory) {
      const maxSeverity = Math.max(...categoryMatches.map((m) => m.pattern.severity));
      const avgConfidence =
        categoryMatches.reduce((sum, m) => sum + m.pattern.confidence, 0) /
        categoryMatches.length;

      factors.push({
        factor_id: `rf-${category}`,
        category,
        description: `Detected ${categoryMatches.length} ${category.replace(/_/g, ' ')} pattern(s)`,
        severity: this.determineSeverity(maxSeverity),
        score_contribution: this.adjustConfidence(maxSeverity, sensitivity),
        confidence: this.adjustConfidence(avgConfidence, sensitivity),
      });
    }

    return factors;
  }

  private calculateRiskScore(
    factors: RiskFactor[],
    sensitivity: number
  ): number {
    if (factors.length === 0) return 0;

    // Weighted average of factor contributions
    const totalContribution = factors.reduce(
      (sum, f) => sum + f.score_contribution * f.confidence,
      0
    );

    // Normalize and apply sensitivity
    const baseScore = Math.min(1, totalContribution / factors.length);
    return Math.min(1, baseScore * (0.5 + sensitivity * 0.5));
  }

  private calculateConfidence(
    matches: PatternMatch[],
    sensitivity: number
  ): number {
    if (matches.length === 0) return 0;

    // Average confidence of all matches, adjusted by sensitivity
    const avgConfidence =
      matches.reduce((sum, m) => sum + m.pattern.confidence, 0) / matches.length;

    // More matches = higher confidence
    const matchBonus = Math.min(0.2, matches.length * 0.02);

    return Math.min(1, this.adjustConfidence(avgConfidence + matchBonus, sensitivity));
  }

  private adjustConfidence(baseConfidence: number, sensitivity: number): number {
    // Higher sensitivity = more aggressive detection
    // sensitivity 0.5 = no adjustment
    // sensitivity 1.0 = +20% confidence
    // sensitivity 0.0 = -20% confidence
    const adjustment = (sensitivity - 0.5) * 0.4;
    return Math.max(0, Math.min(1, baseConfidence + adjustment));
  }

  private determineSeverity(score: number): Severity {
    if (score >= 0.9) return 'critical';
    if (score >= 0.7) return 'high';
    if (score >= 0.4) return 'medium';
    if (score >= 0.1) return 'low';
    return 'none';
  }

  private async persistDecisionEvent(
    input: PromptInjectionDetectionInput,
    output: AgentOutput,
    durationMs: number
  ): Promise<void> {
    // Hash the content - NEVER persist raw content
    const inputsHash = createHash('sha256')
      .update(input.content)
      .digest('hex');

    const event: DecisionEvent = {
      agent_id: AGENT_IDENTITY.agent_id,
      agent_version: AGENT_IDENTITY.agent_version,
      decision_type: AGENT_IDENTITY.decision_type,
      inputs_hash: inputsHash,
      outputs: {
        threats_detected: output.result.threats_detected,
        risk_score: output.result.risk_score,
        severity: output.result.severity,
        confidence: output.result.confidence,
        pattern_match_count: output.result.pattern_match_count,
        detected_categories: output.result.detected_categories,
        entity_count: output.result.entities.length,
      },
      confidence: output.result.confidence,
      constraints_applied: input.context.policies ?? [],
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

    const result = await this.ruvectorClient.persistDecisionEvent(event);

    if (result.success && result.event_id) {
      this.telemetry.emitPersistenceSuccess(
        input.context.execution_ref,
        result.event_id
      );
    } else {
      this.telemetry.emitPersistenceFailure(
        input.context.execution_ref,
        result.error || 'Unknown error'
      );
    }
  }
}

/**
 * Create agent instance with default configuration
 */
export function createAgent(config?: AgentConfig): PromptInjectionDetectionAgent {
  return new PromptInjectionDetectionAgent(config);
}
