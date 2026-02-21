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
export declare const CATEGORY_METADATA: Record<ContentModerationCategory, CategoryMeta>;
/**
 * Map severity score to severity level
 */
export declare function scoreToSeverity(score: number): Severity;
