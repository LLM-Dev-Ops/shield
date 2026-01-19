/**
 * @module types
 * @description Internal type definitions for Content Moderation Agent
 */

import type { ContentModerationCategory, Severity, ModerationAction } from '@llm-shield/agentics-contracts';

/**
 * Detection pattern for content moderation violations
 */
export interface ModerationPattern {
  /** Unique pattern ID */
  id: string;
  /** Regex pattern string */
  pattern: string;
  /** Moderation category this pattern detects */
  category: ContentModerationCategory;
  /** Base confidence score (0.0 - 1.0) */
  confidence: number;
  /** Base severity score (0.0 - 1.0 maps to severity levels) */
  severity: number;
  /** Human-readable description */
  description: string;
  /** Recommended action for this pattern */
  recommended_action: ModerationAction;
  /** Whether pattern is case-sensitive */
  caseSensitive?: boolean;
  /** Tags for pattern grouping */
  tags?: string[];
  /** Whether this pattern requires age verification to allow */
  age_restricted?: boolean;
}

/**
 * Result from pattern matching
 */
export interface PatternMatch {
  /** The pattern that matched */
  pattern: ModerationPattern;
  /** The regex match result */
  match: RegExpMatchArray;
  /** Start position in content */
  start: number;
  /** End position in content */
  end: number;
}

/**
 * Moderation decision result
 */
export interface ModerationDecision {
  /** Whether content is allowed */
  allowed: boolean;
  /** Action to take */
  action: ModerationAction;
  /** Reason for decision */
  reason: string;
  /** Confidence in decision */
  confidence: number;
  /** Triggered rule ID if any */
  triggeredRuleId?: string;
  /** Whether human review is recommended */
  requiresHumanReview: boolean;
  /** Content warning if applicable */
  contentWarning?: string;
}

/**
 * Category metadata
 */
export interface CategoryMeta {
  /** Category identifier */
  category: ContentModerationCategory;
  /** Default severity for this category */
  defaultSeverity: Severity;
  /** Human-readable description */
  description: string;
  /** Whether category requires immediate action (always block) */
  critical: boolean;
  /** Whether content in this category can be allowed with age verification */
  ageRestrictedAllowed: boolean;
  /** Default content warning for this category */
  defaultWarning: string;
}

/**
 * Category metadata map
 */
export const CATEGORY_METADATA: Record<ContentModerationCategory, CategoryMeta> = {
  adult_content: {
    category: 'adult_content',
    defaultSeverity: 'medium',
    description: 'Adult or sexually explicit material',
    critical: false,
    ageRestrictedAllowed: true,
    defaultWarning: 'This content may contain adult material',
  },
  violence_graphic: {
    category: 'violence_graphic',
    defaultSeverity: 'high',
    description: 'Graphic violence or gore',
    critical: false,
    ageRestrictedAllowed: true,
    defaultWarning: 'This content contains graphic violence',
  },
  hate_discriminatory: {
    category: 'hate_discriminatory',
    defaultSeverity: 'critical',
    description: 'Hate speech or discriminatory content',
    critical: true,
    ageRestrictedAllowed: false,
    defaultWarning: 'This content contains hate speech',
  },
  harassment_bullying: {
    category: 'harassment_bullying',
    defaultSeverity: 'high',
    description: 'Harassment or bullying content',
    critical: false,
    ageRestrictedAllowed: false,
    defaultWarning: 'This content contains harassment',
  },
  spam_misleading: {
    category: 'spam_misleading',
    defaultSeverity: 'low',
    description: 'Spam or misleading content',
    critical: false,
    ageRestrictedAllowed: false,
    defaultWarning: 'This content may be misleading',
  },
  illegal_regulated: {
    category: 'illegal_regulated',
    defaultSeverity: 'critical',
    description: 'Illegal or heavily regulated content',
    critical: true,
    ageRestrictedAllowed: false,
    defaultWarning: 'This content may be illegal',
  },
  self_harm: {
    category: 'self_harm',
    defaultSeverity: 'critical',
    description: 'Self-harm or suicide-related content',
    critical: true,
    ageRestrictedAllowed: false,
    defaultWarning: 'This content discusses self-harm',
  },
  child_safety: {
    category: 'child_safety',
    defaultSeverity: 'critical',
    description: 'Content that endangers children',
    critical: true,
    ageRestrictedAllowed: false,
    defaultWarning: 'Child safety violation',
  },
  terrorism_extremism: {
    category: 'terrorism_extremism',
    defaultSeverity: 'critical',
    description: 'Terrorism or extremist content',
    critical: true,
    ageRestrictedAllowed: false,
    defaultWarning: 'This content promotes terrorism',
  },
  misinformation: {
    category: 'misinformation',
    defaultSeverity: 'medium',
    description: 'Deliberate misinformation or fake news',
    critical: false,
    ageRestrictedAllowed: false,
    defaultWarning: 'This content may contain misinformation',
  },
};

/**
 * Map severity score to severity level
 */
export function scoreToSeverity(score: number): Severity {
  if (score >= 0.9) return 'critical';
  if (score >= 0.7) return 'high';
  if (score >= 0.4) return 'medium';
  if (score >= 0.1) return 'low';
  return 'none';
}
