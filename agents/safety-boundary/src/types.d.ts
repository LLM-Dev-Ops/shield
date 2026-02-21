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
export declare const CATEGORY_METADATA: Record<SafetyBoundaryCategory, CategoryMeta>;
/**
 * Map severity score to severity level
 */
export declare function scoreToseverity(score: number): Severity;
