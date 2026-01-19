/**
 * @module types
 * @description Internal type definitions for Safety Boundary Agent
 */

import type { SafetyBoundaryCategory, Severity, EnforcementAction } from '@llm-shield/agentics-contracts';

/**
 * Detection pattern for safety boundary violations
 */
export interface SafetyPattern {
  /** Unique pattern ID */
  id: string;
  /** Regex pattern string */
  pattern: string;
  /** Safety category this pattern detects */
  category: SafetyBoundaryCategory;
  /** Base confidence score (0.0 - 1.0) */
  confidence: number;
  /** Base severity score (0.0 - 1.0 maps to severity levels) */
  severity: number;
  /** Human-readable description */
  description: string;
  /** Whether pattern is case-sensitive */
  caseSensitive?: boolean;
  /** Tags for pattern grouping */
  tags?: string[];
}

/**
 * Result from pattern matching
 */
export interface PatternMatch {
  /** The pattern that matched */
  pattern: SafetyPattern;
  /** The regex match result */
  match: RegExpMatchArray;
  /** Start position in content */
  start: number;
  /** End position in content */
  end: number;
}

/**
 * Enforcement decision result
 */
export interface EnforcementDecision {
  /** Whether content is allowed */
  allowed: boolean;
  /** Action to take */
  action: EnforcementAction;
  /** Reason for decision */
  reason: string;
  /** Confidence in decision */
  confidence: number;
  /** Triggered rule ID if any */
  triggeredRuleId?: string;
}

/**
 * Category metadata
 */
export interface CategoryMeta {
  /** Category identifier */
  category: SafetyBoundaryCategory;
  /** Default severity for this category */
  defaultSeverity: Severity;
  /** Human-readable description */
  description: string;
  /** Whether category is critical (always block if detected) */
  critical: boolean;
}

/**
 * Category metadata map
 */
export const CATEGORY_METADATA: Record<SafetyBoundaryCategory, CategoryMeta> = {
  harmful_content: {
    category: 'harmful_content',
    defaultSeverity: 'high',
    description: 'General harmful or dangerous content',
    critical: false,
  },
  explicit_content: {
    category: 'explicit_content',
    defaultSeverity: 'medium',
    description: 'Adult or sexually explicit material',
    critical: false,
  },
  hate_speech: {
    category: 'hate_speech',
    defaultSeverity: 'critical',
    description: 'Discriminatory or hateful content',
    critical: true,
  },
  violence: {
    category: 'violence',
    defaultSeverity: 'high',
    description: 'Violent or threatening content',
    critical: false,
  },
  self_harm: {
    category: 'self_harm',
    defaultSeverity: 'critical',
    description: 'Self-harm or suicide-related content',
    critical: true,
  },
  illegal_activity: {
    category: 'illegal_activity',
    defaultSeverity: 'critical',
    description: 'Instructions for illegal activities',
    critical: true,
  },
  dangerous_instructions: {
    category: 'dangerous_instructions',
    defaultSeverity: 'high',
    description: 'Dangerous or harmful instructions',
    critical: false,
  },
  deceptive_content: {
    category: 'deceptive_content',
    defaultSeverity: 'medium',
    description: 'Misinformation or deceptive content',
    critical: false,
  },
  privacy_violation: {
    category: 'privacy_violation',
    defaultSeverity: 'high',
    description: 'Content that violates privacy',
    critical: false,
  },
  intellectual_property: {
    category: 'intellectual_property',
    defaultSeverity: 'medium',
    description: 'Copyright or trademark violations',
    critical: false,
  },
};

/**
 * Map severity score to severity level
 */
export function scoreToseverity(score: number): Severity {
  if (score >= 0.9) return 'critical';
  if (score >= 0.7) return 'high';
  if (score >= 0.4) return 'medium';
  if (score >= 0.1) return 'low';
  return 'none';
}
