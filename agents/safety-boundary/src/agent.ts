/**
 * @module agent
 * @description Safety Boundary Enforcement Agent implementation
 *
 * Classification: ENFORCEMENT
 * Decision Type: safety_boundary_enforcement
 *
 * This agent enforces safety boundaries by evaluating content against
 * configurable safety policies and making ALLOW/BLOCK enforcement decisions.
 */

import { createHash } from 'crypto';
import {
  type AgentIdentity,
  type SafetyBoundaryAgentOutput,
  type SafetyBoundaryDecisionEvent,
  type SafetyBoundaryViolation,
  type SafetyBoundaryResult,
  type SafetyBoundaryAgentInput,
  type SafetyBoundaryCategory,
  type SafetyPolicyRule,
  type RiskFactor,
  type Severity,
  type EnforcementAction,
  SafetyBoundaryAgentInput as SafetyBoundaryAgentInputSchema,
} from '@llm-shield/agentics-contracts';
import {
  getPatternsForCategories,
  SAFETY_CATEGORIES,
} from './patterns.js';
import type { SafetyPattern, PatternMatch, EnforcementDecision } from './types.js';
import { CATEGORY_METADATA, scoreToseverity } from './types.js';
import { RuVectorClient, type RuVectorClientConfig } from './ruvector-client.js';
import { TelemetryEmitter, type TelemetryConfig } from './telemetry.js';

/**
 * Agent identity constant
 */
export const AGENT_IDENTITY: AgentIdentity = {
  agent_id: 'safety-boundary-agent',
  agent_version: '1.0.0',
  classification: 'ENFORCEMENT',
  decision_type: 'safety_boundary_enforcement',
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
  /** Default enforcement action */
  defaultAction?: EnforcementAction;
  /** Minimum confidence for enforcement */
  minEnforcementConfidence?: number;
  /** Enable detailed telemetry */
  detailedTelemetry?: boolean;
}

/**
 * Safety Boundary Enforcement Agent
 *
 * Responsibilities:
 * - Detect safety boundary violations in content
 * - Evaluate content against policy rules
 * - Make enforcement decisions (ALLOW/BLOCK)
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
export class SafetyBoundaryAgent {
  private readonly ruvectorClient: RuVectorClient;
  private readonly telemetry: TelemetryEmitter;
  private readonly config: Required<AgentConfig>;

  constructor(config: AgentConfig = {}) {
    this.config = {
      ruvectorConfig: config.ruvectorConfig ?? {},
      telemetryConfig: config.telemetryConfig ?? {},
      defaultSensitivity: config.defaultSensitivity ?? 0.7,
      defaultAction: config.defaultAction ?? 'BLOCK',
      minEnforcementConfidence: config.minEnforcementConfidence ?? 0.8,
      detailedTelemetry: config.detailedTelemetry ?? false,
    };

    this.ruvectorClient = new RuVectorClient(this.config.ruvectorConfig);
    this.telemetry = new TelemetryEmitter(AGENT_IDENTITY, {
      ...this.config.telemetryConfig,
      detailedMetrics: this.config.detailedTelemetry,
    });
  }

  /**
   * Execute enforcement on input content
   *
   * @param input - Validated input conforming to SafetyBoundaryAgentInput schema
   * @returns SafetyBoundaryAgentOutput with enforcement results
   */
  async enforce(input: SafetyBoundaryAgentInput): Promise<SafetyBoundaryAgentOutput> {
    const startTime = performance.now();

    // Emit start telemetry
    this.telemetry.emitInvocationStart(
      input.context.execution_ref,
      input.content.length,
      input.context.content_source
    );

    try {
      // Get patterns for requested categories
      const categories = input.enforce_categories ?? SAFETY_CATEGORIES;
      const patterns = getPatternsForCategories(categories);
      const sensitivity = input.sensitivity ?? this.config.defaultSensitivity;
      const minConfidence =
        input.min_enforcement_confidence ?? this.config.minEnforcementConfidence;

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
            violation.severity
          );
        }
      }

      // Build risk factors
      const riskFactors = this.buildRiskFactors(matches, sensitivity);

      // Calculate aggregated scores
      const riskScore = this.calculateRiskScore(riskFactors, sensitivity);
      const confidence = this.calculateConfidence(matches, sensitivity);
      const severity = this.determineSeverity(riskScore);
      const violatedCategories = [
        ...new Set(violations.map((v) => v.category)),
      ] as SafetyBoundaryCategory[];
      const categoryCounts = this.countByCategory(violations);

      // Make enforcement decision
      const decision = this.makeEnforcementDecision(
        violations,
        input.policy_rules,
        input.default_action ?? this.config.defaultAction,
        minConfidence,
        confidence
      );

      // Emit enforcement decision telemetry
      this.telemetry.emitEnforcementDecision(
        input.context.execution_ref,
        decision.action,
        decision.reason,
        decision.confidence
      );

      const durationMs = performance.now() - startTime;

      // Build result
      const result: SafetyBoundaryResult = {
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
      };

      // Build output
      const output: SafetyBoundaryAgentOutput = {
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
        violations.length
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
  validateInput(input: unknown): SafetyBoundaryAgentInput {
    const result = SafetyBoundaryAgentInputSchema.safeParse(input);

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
    patterns: SafetyPattern[]
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
  ): SafetyBoundaryViolation[] {
    return matches.map((m, index) => ({
      violation_id: `v-${index + 1}`,
      category: m.pattern.category,
      start: m.start,
      end: m.end,
      confidence: this.adjustConfidence(m.pattern.confidence, sensitivity),
      severity: scoreToseverity(m.pattern.severity),
      pattern_id: m.pattern.id,
      description: m.pattern.description,
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

      const meta = CATEGORY_METADATA[category as SafetyBoundaryCategory];

      factors.push({
        factor_id: `rf-${category}`,
        category,
        description: `Detected ${categoryMatches.length} ${meta?.description || category.replace(/_/g, ' ')} violation(s)`,
        severity: scoreToseverity(maxSeverity),
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

  private determineSeverity(score: number): Severity {
    if (score >= 0.9) return 'critical';
    if (score >= 0.7) return 'high';
    if (score >= 0.4) return 'medium';
    if (score >= 0.1) return 'low';
    return 'none';
  }

  private countByCategory(
    violations: SafetyBoundaryViolation[]
  ): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const v of violations) {
      counts[v.category] = (counts[v.category] || 0) + 1;
    }
    return counts;
  }

  private makeEnforcementDecision(
    violations: SafetyBoundaryViolation[],
    policyRules: SafetyPolicyRule[] | undefined,
    defaultAction: EnforcementAction,
    minConfidence: number,
    overallConfidence: number
  ): EnforcementDecision {
    // No violations = ALLOW
    if (violations.length === 0) {
      return {
        allowed: true,
        action: 'ALLOW',
        reason: 'No safety boundary violations detected',
        confidence: 1,
      };
    }

    // Check if confidence meets threshold
    if (overallConfidence < minConfidence) {
      return {
        allowed: true,
        action: 'AUDIT',
        reason: `Detection confidence (${(overallConfidence * 100).toFixed(1)}%) below threshold (${(minConfidence * 100).toFixed(1)}%) - flagging for audit`,
        confidence: overallConfidence,
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
        reason: `Critical safety violation(s) in: ${categories.join(', ')}`,
        confidence: Math.max(...criticalViolations.map((v) => v.confidence)),
      };
    }

    // Apply custom policy rules if provided
    if (policyRules && policyRules.length > 0) {
      // Sort by priority (lower = higher priority)
      const sortedRules = [...policyRules]
        .filter((r) => r.enabled)
        .sort((a, b) => a.priority - b.priority);

      for (const rule of sortedRules) {
        const matchingViolations = violations.filter(
          (v) => v.category === rule.category && v.confidence >= rule.threshold
        );

        if (matchingViolations.length > 0) {
          return {
            allowed: rule.action === 'ALLOW' || rule.action === 'AUDIT',
            action: rule.action,
            reason: `Policy rule '${rule.rule_id}' triggered: ${rule.description}`,
            confidence: Math.max(...matchingViolations.map((v) => v.confidence)),
            triggeredRuleId: rule.rule_id,
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

    return {
      allowed: defaultAction === 'ALLOW' || defaultAction === 'AUDIT',
      action: defaultAction,
      reason: `Safety boundary violation detected in category '${highestSeverityViolation.category}': ${highestSeverityViolation.description}`,
      confidence: highestSeverityViolation.confidence,
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
    input: SafetyBoundaryAgentInput,
    output: SafetyBoundaryAgentOutput,
    durationMs: number,
    categoriesChecked: SafetyBoundaryCategory[]
  ): Promise<void> {
    // Hash the content - NEVER persist raw content
    const inputsHash = createHash('sha256').update(input.content).digest('hex');

    const event: SafetyBoundaryDecisionEvent = {
      agent_id: 'safety-boundary-agent',
      agent_version: AGENT_IDENTITY.agent_version,
      decision_type: 'safety_boundary_enforcement',
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
        categories_checked: categoriesChecked,
        rules_evaluated: input.policy_rules?.length ?? 0,
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
export function createAgent(config?: AgentConfig): SafetyBoundaryAgent {
  return new SafetyBoundaryAgent(config);
}
