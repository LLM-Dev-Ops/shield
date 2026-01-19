/**
 * @module agent
 * @description Content Moderation Enforcement Agent implementation
 *
 * Classification: ENFORCEMENT
 * Decision Type: content_moderation
 *
 * This agent applies moderation policies to classify or block
 * disallowed content categories.
 */

import { createHash } from 'crypto';
import {
  type AgentIdentity,
  type ContentModerationAgentOutput,
  type ContentModerationDecisionEvent,
  type ContentModerationViolation,
  type ContentModerationResult,
  type ContentModerationAgentInput,
  type ContentModerationCategory,
  type ContentModerationRule,
  type RiskFactor,
  type Severity,
  type ModerationAction,
  ContentModerationAgentInput as ContentModerationAgentInputSchema,
} from '@llm-shield/agentics-contracts';
import {
  getPatternsForCategories,
  MODERATION_CATEGORIES,
} from './patterns.js';
import type { ModerationPattern, PatternMatch, ModerationDecision } from './types.js';
import { CATEGORY_METADATA, scoreToSeverity } from './types.js';
import { RuVectorClient, type RuVectorClientConfig } from './ruvector-client.js';
import { TelemetryEmitter, type TelemetryConfig } from './telemetry.js';

/**
 * Agent identity constant
 */
export const AGENT_IDENTITY: AgentIdentity = {
  agent_id: 'content-moderation-agent',
  agent_version: '1.0.0',
  classification: 'ENFORCEMENT',
  decision_type: 'content_moderation',
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
  /** Default moderation action */
  defaultAction?: ModerationAction;
  /** Minimum confidence for moderation */
  minModerationConfidence?: number;
  /** Enable detailed telemetry */
  detailedTelemetry?: boolean;
}

/**
 * Content Moderation Enforcement Agent
 *
 * Responsibilities:
 * - Detect content moderation violations
 * - Evaluate content against moderation policies
 * - Make enforcement decisions (ALLOW/BLOCK/FLAG/WARN/AGE_GATE)
 * - Emit DecisionEvents to ruvector-service
 * - Emit telemetry to LLM-Observatory
 *
 * Non-Responsibilities:
 * - Does NOT modify content (enforcement only)
 * - Does NOT orchestrate workflows
 * - Does NOT retry operations
 * - Does NOT connect to databases directly
 * - Does NOT trigger alerts or incidents
 * - Does NOT modify policies at runtime
 */
export class ContentModerationAgent {
  private readonly ruvectorClient: RuVectorClient;
  private readonly telemetry: TelemetryEmitter;
  private readonly config: Required<AgentConfig>;

  constructor(config: AgentConfig = {}) {
    this.config = {
      ruvectorConfig: config.ruvectorConfig ?? {},
      telemetryConfig: config.telemetryConfig ?? {},
      defaultSensitivity: config.defaultSensitivity ?? 0.7,
      defaultAction: config.defaultAction ?? 'BLOCK',
      minModerationConfidence: config.minModerationConfidence ?? 0.8,
      detailedTelemetry: config.detailedTelemetry ?? false,
    };

    this.ruvectorClient = new RuVectorClient(this.config.ruvectorConfig);
    this.telemetry = new TelemetryEmitter(AGENT_IDENTITY, {
      ...this.config.telemetryConfig,
      detailedMetrics: this.config.detailedTelemetry,
    });
  }

  /**
   * Execute moderation on input content
   *
   * @param input - Validated input conforming to ContentModerationAgentInput schema
   * @returns ContentModerationAgentOutput with moderation results
   */
  async moderate(input: ContentModerationAgentInput): Promise<ContentModerationAgentOutput> {
    const startTime = performance.now();

    // Emit start telemetry
    this.telemetry.emitInvocationStart(
      input.context.execution_ref,
      input.content.length,
      input.context.content_source,
      input.content_type
    );

    try {
      // Get patterns for requested categories
      const categories = input.moderate_categories ?? MODERATION_CATEGORIES;
      const patterns = getPatternsForCategories(categories);
      const sensitivity = input.sensitivity ?? this.config.defaultSensitivity;
      const minConfidence =
        input.min_moderation_confidence ?? this.config.minModerationConfidence;

      // Execute pattern matching
      const matches = this.findMatches(input.content, patterns);

      // Build violations
      const violations = this.buildViolations(matches, sensitivity);

      // Emit detailed violation telemetry
      if (this.config.detailedTelemetry) {
        for (const violation of violations) {
          this.telemetry.emitViolationDetected(
            input.context.execution_ref,
            violation.category,
            violation.pattern_id ?? 'unknown',
            violation.confidence,
            violation.severity,
            violation.recommended_action
          );
        }
      }

      // Build risk factors
      const riskFactors = this.buildRiskFactors(matches, sensitivity);

      // Calculate aggregated scores
      const riskScore = this.calculateRiskScore(riskFactors, sensitivity);
      const confidence = this.calculateConfidence(matches, sensitivity);
      const violatedCategories = [
        ...new Set(violations.map((v) => v.category)),
      ] as ContentModerationCategory[];
      const severity = this.determineSeverity(riskScore, violatedCategories);
      const categoryCounts = this.countByCategory(violations);

      // Make moderation decision
      const decision = this.makeModerationDecision(
        violations,
        input.moderation_rules,
        input.default_action ?? this.config.defaultAction,
        minConfidence,
        confidence,
        input.user_age_verified ?? false
      );

      // Emit moderation decision telemetry
      this.telemetry.emitModerationDecision(
        input.context.execution_ref,
        decision.action,
        decision.reason,
        decision.confidence,
        decision.requiresHumanReview
      );

      const durationMs = performance.now() - startTime;

      // Build result
      const result: ContentModerationResult = {
        allowed: decision.allowed,
        action: decision.action,
        violations_detected: violations.length > 0,
        risk_score: riskScore,
        severity,
        confidence,
        violations,
        violated_categories: violatedCategories,
        pattern_match_count: matches.length,
        category_counts: categoryCounts,
        decision_reason: decision.reason,
        risk_factors: riskFactors,
        requires_human_review: decision.requiresHumanReview,
        content_warning: decision.contentWarning,
      };

      // Build output
      const output: ContentModerationAgentOutput = {
        agent: AGENT_IDENTITY,
        result,
        duration_ms: durationMs,
        cached: false,
      };

      // Persist DecisionEvent
      await this.persistDecisionEvent(input, output, durationMs, categories);

      // Emit completion telemetry
      this.telemetry.emitInvocationComplete(
        input.context.execution_ref,
        durationMs,
        result.allowed,
        result.action,
        result.risk_score,
        violations.length,
        result.requires_human_review
      );

      return output;
    } catch (error) {
      // Duration calculated but not used in error path - intentional
      void (performance.now() - startTime);
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
  validateInput(input: unknown): ContentModerationAgentInput {
    const result = ContentModerationAgentInputSchema.safeParse(input);

    if (!result.success) {
      const error = {
        code: 'VALIDATION_FAILED' as const,
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

  private findMatches(
    content: string,
    patterns: ModerationPattern[]
  ): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const pattern of patterns) {
      const flags = pattern.caseSensitive ? 'g' : 'gi';
      const regex = new RegExp(pattern.pattern, flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        matches.push({
          pattern,
          match,
          start: match.index,
          end: match.index + match[0].length,
        });
      }
    }

    return matches;
  }

  private buildViolations(
    matches: PatternMatch[],
    sensitivity: number
  ): ContentModerationViolation[] {
    return matches.map((m, index) => ({
      violation_id: `v-${index + 1}`,
      category: m.pattern.category,
      start: m.start,
      end: m.end,
      confidence: this.adjustConfidence(m.pattern.confidence, sensitivity),
      severity: scoreToSeverity(m.pattern.severity),
      pattern_id: m.pattern.id,
      description: m.pattern.description,
      recommended_action: m.pattern.recommended_action,
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
      const maxSeverity = Math.max(
        ...categoryMatches.map((m) => m.pattern.severity)
      );
      const avgConfidence =
        categoryMatches.reduce((sum, m) => sum + m.pattern.confidence, 0) /
        categoryMatches.length;

      const meta = CATEGORY_METADATA[category as ContentModerationCategory];

      factors.push({
        factor_id: `rf-${category}`,
        category,
        description: `Detected ${categoryMatches.length} ${meta?.description || category.replace(/_/g, ' ')} violation(s)`,
        severity: scoreToSeverity(maxSeverity),
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
    if (matches.length === 0) return 1; // High confidence in "safe" decision

    // Average confidence of all matches, adjusted by sensitivity
    const avgConfidence =
      matches.reduce((sum, m) => sum + m.pattern.confidence, 0) / matches.length;

    // More matches = higher confidence
    const matchBonus = Math.min(0.2, matches.length * 0.02);

    return Math.min(
      1,
      this.adjustConfidence(avgConfidence + matchBonus, sensitivity)
    );
  }

  private adjustConfidence(baseConfidence: number, sensitivity: number): number {
    // Higher sensitivity = more aggressive detection
    // sensitivity 0.5 = no adjustment
    // sensitivity 1.0 = +30% confidence
    // sensitivity 0.0 = -30% confidence
    const adjustment = (sensitivity - 0.5) * 0.6;
    return Math.max(0, Math.min(1, baseConfidence + adjustment));
  }

  private determineSeverity(score: number, violatedCategories: ContentModerationCategory[]): Severity {
    // Check if any violated category has a critical default severity
    for (const category of violatedCategories) {
      const meta = CATEGORY_METADATA[category];
      if (meta?.defaultSeverity === 'critical') {
        return 'critical';
      }
    }

    // Fall back to score-based severity
    if (score >= 0.9) return 'critical';
    if (score >= 0.7) return 'high';
    if (score >= 0.4) return 'medium';
    if (score >= 0.1) return 'low';
    return 'none';
  }

  private countByCategory(
    violations: ContentModerationViolation[]
  ): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const v of violations) {
      counts[v.category] = (counts[v.category] || 0) + 1;
    }
    return counts;
  }

  private makeModerationDecision(
    violations: ContentModerationViolation[],
    moderationRules: ContentModerationRule[] | undefined,
    defaultAction: ModerationAction,
    minConfidence: number,
    overallConfidence: number,
    userAgeVerified: boolean
  ): ModerationDecision {
    // No violations = ALLOW
    if (violations.length === 0) {
      return {
        allowed: true,
        action: 'ALLOW',
        reason: 'No content moderation violations detected',
        confidence: 1,
        requiresHumanReview: false,
      };
    }

    // Check if confidence meets threshold
    if (overallConfidence < minConfidence) {
      return {
        allowed: true,
        action: 'FLAG',
        reason: `Detection confidence (${(overallConfidence * 100).toFixed(1)}%) below threshold (${(minConfidence * 100).toFixed(1)}%) - flagging for review`,
        confidence: overallConfidence,
        requiresHumanReview: true,
      };
    }

    // Check for critical categories that always block
    const criticalViolations = violations.filter((v) => {
      const meta = CATEGORY_METADATA[v.category];
      return meta?.critical && v.confidence >= minConfidence;
    });

    if (criticalViolations.length > 0) {
      const categories = [...new Set(criticalViolations.map((v) => v.category))];
      return {
        allowed: false,
        action: 'BLOCK',
        reason: `Critical content violation(s) in: ${categories.join(', ')}`,
        confidence: Math.max(...criticalViolations.map((v) => v.confidence)),
        requiresHumanReview: false,
      };
    }

    // Check for age-restricted content
    const ageRestrictedViolations = violations.filter((v) => {
      const meta = CATEGORY_METADATA[v.category];
      return meta?.ageRestrictedAllowed && v.confidence >= minConfidence;
    });

    if (ageRestrictedViolations.length > 0 && !userAgeVerified) {
      const categories = [...new Set(ageRestrictedViolations.map((v) => v.category))];
      const meta = CATEGORY_METADATA[ageRestrictedViolations[0].category];
      return {
        allowed: false,
        action: 'AGE_GATE',
        reason: `Age-restricted content in: ${categories.join(', ')}. Age verification required.`,
        confidence: Math.max(...ageRestrictedViolations.map((v) => v.confidence)),
        requiresHumanReview: false,
        contentWarning: meta?.defaultWarning,
      };
    }

    // If age verified and content is age-restricted allowed, allow with warning
    if (ageRestrictedViolations.length > 0 && userAgeVerified) {
      const allViolationsAreAgeRestricted = violations.every((v) => {
        const meta = CATEGORY_METADATA[v.category];
        return meta?.ageRestrictedAllowed;
      });

      if (allViolationsAreAgeRestricted) {
        const meta = CATEGORY_METADATA[violations[0].category];
        return {
          allowed: true,
          action: 'WARN',
          reason: 'Age-restricted content allowed for verified user',
          confidence: overallConfidence,
          requiresHumanReview: false,
          contentWarning: meta?.defaultWarning,
        };
      }
    }

    // Apply custom moderation rules if provided
    if (moderationRules && moderationRules.length > 0) {
      // Sort by priority (lower = higher priority)
      const sortedRules = [...moderationRules]
        .filter((r) => r.enabled)
        .sort((a, b) => a.priority - b.priority);

      for (const rule of sortedRules) {
        const matchingViolations = violations.filter(
          (v) => v.category === rule.category && v.confidence >= rule.threshold
        );

        if (matchingViolations.length > 0) {
          const allowed = rule.action === 'ALLOW' || rule.action === 'WARN' || rule.action === 'FLAG';
          return {
            allowed,
            action: rule.action,
            reason: `Moderation rule '${rule.rule_id}' triggered: ${rule.description}`,
            confidence: Math.max(...matchingViolations.map((v) => v.confidence)),
            triggeredRuleId: rule.rule_id,
            requiresHumanReview: rule.action === 'FLAG',
          };
        }
      }
    }

    // Apply default action
    const highestSeverityViolation = violations.reduce((highest, v) => {
      const currentSeverity = this.severityToScore(v.severity);
      const highestSeverity = this.severityToScore(highest.severity);
      return currentSeverity > highestSeverity ? v : highest;
    });

    const allowed = defaultAction === 'ALLOW' || defaultAction === 'WARN' || defaultAction === 'FLAG';
    const meta = CATEGORY_METADATA[highestSeverityViolation.category];

    return {
      allowed,
      action: defaultAction,
      reason: `Content moderation violation detected in category '${highestSeverityViolation.category}': ${highestSeverityViolation.description}`,
      confidence: highestSeverityViolation.confidence,
      requiresHumanReview: defaultAction === 'FLAG',
      contentWarning: meta?.defaultWarning,
    };
  }

  private severityToScore(severity: Severity): number {
    switch (severity) {
      case 'critical':
        return 1.0;
      case 'high':
        return 0.8;
      case 'medium':
        return 0.5;
      case 'low':
        return 0.2;
      case 'none':
        return 0;
    }
  }

  private async persistDecisionEvent(
    input: ContentModerationAgentInput,
    output: ContentModerationAgentOutput,
    durationMs: number,
    categoriesChecked: ContentModerationCategory[]
  ): Promise<void> {
    // Hash the content - NEVER persist raw content
    const inputsHash = createHash('sha256').update(input.content).digest('hex');

    const event: ContentModerationDecisionEvent = {
      agent_id: 'content-moderation-agent',
      agent_version: AGENT_IDENTITY.agent_version,
      decision_type: 'content_moderation',
      inputs_hash: inputsHash,
      outputs: {
        allowed: output.result.allowed,
        action: output.result.action,
        violations_detected: output.result.violations_detected,
        risk_score: output.result.risk_score,
        severity: output.result.severity,
        confidence: output.result.confidence,
        pattern_match_count: output.result.pattern_match_count,
        violation_count: output.result.violations.length,
        violated_categories: output.result.violated_categories,
        category_counts: output.result.category_counts,
        decision_reason: output.result.decision_reason,
        requires_human_review: output.result.requires_human_review,
      },
      confidence: output.result.confidence,
      constraints_applied: input.context.policies ?? [],
      execution_ref: input.context.execution_ref,
      timestamp: input.context.timestamp,
      duration_ms: durationMs,
      telemetry: {
        content_length: input.content.length,
        content_source: input.context.content_source,
        content_type: input.content_type,
        session_id: input.context.session_id,
        caller_id: input.context.caller_id,
        categories_checked: categoriesChecked,
        rules_evaluated: input.moderation_rules?.length ?? 0,
        user_age_verified: input.user_age_verified,
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
export function createAgent(config?: AgentConfig): ContentModerationAgent {
  return new ContentModerationAgent(config);
}
