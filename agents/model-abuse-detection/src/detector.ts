/**
 * @module detector
 * @description Core detection logic for model abuse patterns
 *
 * This module provides stateless detection of model abuse patterns
 * using both content-based pattern matching and behavioral analysis.
 */

import type {
  ModelAbuseCategory,
  Severity,
  ModelAbuseDetectedEntity,
  RiskFactor,
} from '@llm-shield/agentics-contracts';
import {
  MODEL_ABUSE_PATTERNS,
  BEHAVIORAL_THRESHOLDS,
  getPatternsForCategories,
  getThresholdsForCategories,
  type ModelAbusePattern,
  type BehavioralThreshold,
} from './patterns.js';

/**
 * Detection configuration
 */
export interface DetectionConfig {
  /** Detection sensitivity (0.0 - 1.0) */
  sensitivity: number;
  /** Detection threshold (0.0 - 1.0) */
  threshold: number;
  /** Categories to detect */
  categories?: ModelAbuseCategory[];
}

/**
 * Request metadata for behavioral analysis
 */
export interface RequestMetadata {
  requestRate?: number;
  clientIpHash?: string;
  userAgentHash?: string;
  sessionRequestCount?: number;
  sessionTokenUsage?: number;
  appearsAutomated?: boolean;
  apiEndpoint?: string;
  requestTimestamp?: string;
}

/**
 * Historical context for pattern detection
 */
export interface HistoricalContext {
  previousRequestCount?: number;
  previousViolationCount?: number;
  sessionDurationSeconds?: number;
}

/**
 * Internal pattern match result
 */
interface PatternMatch {
  pattern: ModelAbusePattern;
  start: number;
  end: number;
  matchedText: string;
  confidence: number;
}

/**
 * Behavioral match result
 */
interface BehavioralMatch {
  threshold: BehavioralThreshold;
  actualValue: number;
  confidence: number;
}

/**
 * Behavioral analysis summary
 */
export interface BehavioralSummary {
  appearsAutomated: boolean;
  abnormalRate: boolean;
  matchesAbuseSignature: boolean;
  redFlagCount: number;
}

/**
 * All severity levels for ordering
 */
const SEVERITY_ORDER: Severity[] = ['none', 'low', 'medium', 'high', 'critical'];

/**
 * Model Abuse Detector - stateless detection class
 */
export class ModelAbuseDetector {
  private patterns: ModelAbusePattern[];
  private thresholds: BehavioralThreshold[];

  constructor() {
    this.patterns = MODEL_ABUSE_PATTERNS;
    this.thresholds = BEHAVIORAL_THRESHOLDS;
  }

  /**
   * Detect model abuse patterns in content
   */
  detect(
    content: string,
    config: DetectionConfig,
    metadata?: RequestMetadata,
    historicalContext?: HistoricalContext
  ): {
    entities: ModelAbuseDetectedEntity[];
    riskFactors: RiskFactor[];
    behavioralSummary: BehavioralSummary;
  } {
    // Get applicable patterns and thresholds
    const applicablePatterns = config.categories
      ? getPatternsForCategories(config.categories)
      : this.patterns;

    const applicableThresholds = config.categories
      ? getThresholdsForCategories(config.categories)
      : this.thresholds;

    // Detect content-based patterns
    const patternMatches = this.detectPatterns(content, applicablePatterns, config);

    // Detect behavioral patterns
    const behavioralMatches = this.detectBehavioralPatterns(
      applicableThresholds,
      metadata,
      historicalContext
    );

    // Analyze behavioral summary
    const behavioralSummary = this.analyzeBehavior(metadata, behavioralMatches);

    // Convert to entities
    const entities = this.convertToEntities(
      patternMatches,
      behavioralMatches,
      config
    );

    // Build risk factors
    const riskFactors = this.buildRiskFactors(
      patternMatches,
      behavioralMatches,
      behavioralSummary
    );

    return { entities, riskFactors, behavioralSummary };
  }

  /**
   * Detect content-based patterns
   */
  private detectPatterns(
    content: string,
    patterns: ModelAbusePattern[],
    config: DetectionConfig
  ): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const pattern of patterns) {
      // Create fresh regex with global flag
      const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        // Calculate confidence with sensitivity adjustment
        const confidence = this.calculateConfidence(
          pattern.baseConfidence,
          config.sensitivity
        );

        // Only include if above threshold
        if (confidence >= config.threshold) {
          matches.push({
            pattern,
            start: match.index,
            end: match.index + match[0].length,
            matchedText: match[0],
            confidence,
          });
        }
      }
    }

    return this.deduplicateMatches(matches);
  }

  /**
   * Detect behavioral patterns from metadata
   */
  private detectBehavioralPatterns(
    thresholds: BehavioralThreshold[],
    metadata?: RequestMetadata,
    historicalContext?: HistoricalContext
  ): BehavioralMatch[] {
    if (!metadata && !historicalContext) {
      return [];
    }

    const matches: BehavioralMatch[] = [];

    for (const threshold of thresholds) {
      let actualValue: number | undefined;

      // Map threshold to actual values
      switch (threshold.unit) {
        case 'requests_per_minute':
          actualValue = metadata?.requestRate;
          break;
        case 'tokens_per_session':
          actualValue = metadata?.sessionTokenUsage;
          break;
        case 'requests_per_session':
          actualValue = metadata?.sessionRequestCount;
          break;
        case 'previous_violations':
          actualValue = historicalContext?.previousViolationCount;
          break;
      }

      if (actualValue !== undefined && actualValue >= threshold.threshold) {
        const exceedanceRatio = actualValue / threshold.threshold;
        const confidence = Math.min(
          1.0,
          threshold.baseConfidence * Math.min(2, exceedanceRatio)
        );

        matches.push({
          threshold,
          actualValue,
          confidence,
        });
      }
    }

    return matches;
  }

  /**
   * Analyze behavioral patterns
   */
  private analyzeBehavior(
    metadata?: RequestMetadata,
    behavioralMatches?: BehavioralMatch[]
  ): BehavioralSummary {
    const redFlags: string[] = [];

    // Check if appears automated
    const appearsAutomated = metadata?.appearsAutomated ?? false;
    if (appearsAutomated) {
      redFlags.push('appears_automated');
    }

    // Check for abnormal rate
    const abnormalRate = (behavioralMatches ?? []).some(
      (m) => m.threshold.unit === 'requests_per_minute'
    );
    if (abnormalRate) {
      redFlags.push('abnormal_rate');
    }

    // Check for abuse signature matches
    const matchesAbuseSignature = (behavioralMatches ?? []).length > 0;
    if (matchesAbuseSignature && behavioralMatches!.length >= 2) {
      redFlags.push('multiple_abuse_signatures');
    }

    // Additional red flags from metadata
    if (metadata) {
      if (metadata.sessionRequestCount && metadata.sessionRequestCount > 50) {
        redFlags.push('high_session_requests');
      }
      if (metadata.sessionTokenUsage && metadata.sessionTokenUsage > 50000) {
        redFlags.push('high_token_usage');
      }
    }

    return {
      appearsAutomated,
      abnormalRate,
      matchesAbuseSignature,
      redFlagCount: redFlags.length,
    };
  }

  /**
   * Convert matches to detected entities
   */
  private convertToEntities(
    patternMatches: PatternMatch[],
    behavioralMatches: BehavioralMatch[],
    config: DetectionConfig
  ): ModelAbuseDetectedEntity[] {
    const entities: ModelAbuseDetectedEntity[] = [];

    // Convert pattern matches
    for (const match of patternMatches) {
      entities.push({
        abuse_category: match.pattern.category,
        category: match.pattern.category,
        start: match.start,
        end: match.end,
        confidence: match.confidence,
        pattern_id: match.pattern.id,
        severity: match.pattern.severity,
        indicator_count: 1,
        behavioral_indicators: match.pattern.behavioralIndicators,
      });
    }

    // Convert behavioral matches to entities (start/end = 0 for behavioral)
    for (const match of behavioralMatches) {
      if (match.confidence >= config.threshold) {
        entities.push({
          abuse_category: match.threshold.category,
          category: match.threshold.category,
          start: 0,
          end: 0,
          confidence: match.confidence,
          pattern_id: match.threshold.id,
          severity: match.threshold.severity,
          indicator_count: 1,
          behavioral_indicators: [match.threshold.name],
        });
      }
    }

    return entities;
  }

  /**
   * Build risk factors from matches
   */
  private buildRiskFactors(
    patternMatches: PatternMatch[],
    behavioralMatches: BehavioralMatch[],
    behavioralSummary: BehavioralSummary
  ): RiskFactor[] {
    const factors: RiskFactor[] = [];

    // Group pattern matches by category
    const categoryCounts = new Map<string, number>();
    for (const match of patternMatches) {
      const count = categoryCounts.get(match.pattern.category) ?? 0;
      categoryCounts.set(match.pattern.category, count + 1);
    }

    // Add category-based risk factors
    for (const [category, count] of categoryCounts) {
      factors.push({
        factor_id: `category-${category}`,
        category: 'pattern_match',
        description: `Detected ${count} ${category.replace(/_/g, ' ')} pattern(s)`,
        severity: this.getCategorySeverity(category as ModelAbuseCategory, patternMatches),
        score_contribution: Math.min(0.4, count * 0.1),
        confidence: this.getCategoryConfidence(category, patternMatches),
      });
    }

    // Add behavioral risk factors
    for (const match of behavioralMatches) {
      factors.push({
        factor_id: `behavioral-${match.threshold.id}`,
        category: 'behavioral',
        description: match.threshold.description,
        severity: match.threshold.severity,
        score_contribution: Math.min(0.3, match.confidence * 0.3),
        confidence: match.confidence,
      });
    }

    // Add summary risk factors
    if (behavioralSummary.appearsAutomated) {
      factors.push({
        factor_id: 'automated-request',
        category: 'behavioral',
        description: 'Request appears to be automated',
        severity: 'medium',
        score_contribution: 0.15,
        confidence: 0.80,
      });
    }

    if (behavioralSummary.redFlagCount >= 3) {
      factors.push({
        factor_id: 'multiple-red-flags',
        category: 'composite',
        description: `Multiple behavioral red flags detected (${behavioralSummary.redFlagCount})`,
        severity: 'high',
        score_contribution: 0.25,
        confidence: 0.85,
      });
    }

    return factors;
  }

  /**
   * Calculate confidence with sensitivity adjustment
   */
  private calculateConfidence(baseConfidence: number, sensitivity: number): number {
    // Sensitivity adjusts the confidence:
    // - sensitivity 0.5 = no adjustment
    // - sensitivity > 0.5 = increase confidence (more sensitive)
    // - sensitivity < 0.5 = decrease confidence (less sensitive)
    const adjustment = (sensitivity - 0.5) * 0.2;
    return Math.max(0, Math.min(1, baseConfidence + adjustment));
  }

  /**
   * Deduplicate overlapping matches
   */
  private deduplicateMatches(matches: PatternMatch[]): PatternMatch[] {
    if (matches.length <= 1) {
      return matches;
    }

    // Sort by start position
    const sorted = [...matches].sort((a, b) => a.start - b.start);
    const deduplicated: PatternMatch[] = [];

    for (const match of sorted) {
      // Check if this match overlaps with the last added match
      const last = deduplicated[deduplicated.length - 1];
      if (!last || match.start >= last.end) {
        deduplicated.push(match);
      } else if (match.confidence > last.confidence) {
        // Replace with higher confidence match
        deduplicated[deduplicated.length - 1] = match;
      }
    }

    return deduplicated;
  }

  /**
   * Get highest severity for a category from matches
   */
  private getCategorySeverity(
    category: ModelAbuseCategory,
    matches: PatternMatch[]
  ): Severity {
    const categoryMatches = matches.filter((m) => m.pattern.category === category);
    if (categoryMatches.length === 0) {
      return 'none';
    }

    let maxSeverityIndex = 0;
    for (const match of categoryMatches) {
      const index = SEVERITY_ORDER.indexOf(match.pattern.severity);
      if (index > maxSeverityIndex) {
        maxSeverityIndex = index;
      }
    }

    return SEVERITY_ORDER[maxSeverityIndex] ?? 'none';
  }

  /**
   * Get average confidence for a category
   */
  private getCategoryConfidence(
    category: string,
    matches: PatternMatch[]
  ): number {
    const categoryMatches = matches.filter((m) => m.pattern.category === category);
    if (categoryMatches.length === 0) {
      return 0;
    }

    const sum = categoryMatches.reduce((acc, m) => acc + m.confidence, 0);
    return Math.round((sum / categoryMatches.length) * 100) / 100;
  }

  /**
   * Calculate overall risk score from entities
   */
  calculateRiskScore(
    entities: ModelAbuseDetectedEntity[],
    behavioralSummary: BehavioralSummary
  ): number {
    if (entities.length === 0) {
      return 0;
    }

    // Base score from entity count and severity
    let score = 0;
    const severityWeights: Record<Severity, number> = {
      none: 0,
      low: 0.1,
      medium: 0.25,
      high: 0.4,
      critical: 0.6,
    };

    for (const entity of entities) {
      score += severityWeights[entity.severity] * entity.confidence;
    }

    // Add behavioral penalties
    if (behavioralSummary.appearsAutomated) {
      score += 0.1;
    }
    if (behavioralSummary.abnormalRate) {
      score += 0.15;
    }
    if (behavioralSummary.matchesAbuseSignature) {
      score += 0.1;
    }

    // Red flag multiplier
    if (behavioralSummary.redFlagCount >= 3) {
      score *= 1.2;
    }

    return Math.min(1, Math.round(score * 100) / 100);
  }

  /**
   * Get maximum severity from entities
   */
  getMaxSeverity(entities: ModelAbuseDetectedEntity[]): Severity {
    if (entities.length === 0) {
      return 'none';
    }

    let maxIndex = 0;
    for (const entity of entities) {
      const index = SEVERITY_ORDER.indexOf(entity.severity);
      if (index > maxIndex) {
        maxIndex = index;
      }
    }

    return SEVERITY_ORDER[maxIndex] ?? 'none';
  }

  /**
   * Calculate overall confidence from entities
   */
  calculateOverallConfidence(entities: ModelAbuseDetectedEntity[]): number {
    if (entities.length === 0) {
      return 0;
    }

    // Use weighted average based on severity
    const severityWeights: Record<Severity, number> = {
      none: 0,
      low: 1,
      medium: 2,
      high: 3,
      critical: 4,
    };

    let weightedSum = 0;
    let totalWeight = 0;

    for (const entity of entities) {
      const weight = severityWeights[entity.severity];
      weightedSum += entity.confidence * weight;
      totalWeight += weight;
    }

    if (totalWeight === 0) {
      return 0;
    }

    return Math.round((weightedSum / totalWeight) * 100) / 100;
  }

  /**
   * Get detected categories
   */
  getDetectedCategories(
    entities: ModelAbuseDetectedEntity[]
  ): ModelAbuseCategory[] {
    const categories = new Set<ModelAbuseCategory>();
    for (const entity of entities) {
      categories.add(entity.abuse_category);
    }
    return [...categories];
  }

  /**
   * Get category counts
   */
  getCategoryCounts(
    entities: ModelAbuseDetectedEntity[]
  ): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const entity of entities) {
      counts[entity.abuse_category] = (counts[entity.abuse_category] ?? 0) + 1;
    }
    return counts;
  }
}

/**
 * Create a new detector instance
 */
export function createDetector(): ModelAbuseDetector {
  return new ModelAbuseDetector();
}
