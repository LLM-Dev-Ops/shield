/**
 * @module patterns
 * @description Detection patterns for prompt injection identification
 *
 * Patterns are organized by category with severity weights
 * for confidence scoring.
 */
/**
 * Pattern definition with metadata
 */
export interface DetectionPattern {
    /** Unique pattern identifier */
    id: string;
    /** Pattern category */
    category: string;
    /** Regular expression for matching */
    pattern: RegExp;
    /** Severity weight (0.0 - 1.0) */
    severity: number;
    /** Base confidence for matches */
    confidence: number;
    /** Human-readable description */
    description: string;
}
/**
 * Detection categories
 */
export declare const CATEGORIES: {
    readonly INSTRUCTION_OVERRIDE: "instruction_override";
    readonly ROLE_MANIPULATION: "role_manipulation";
    readonly SYSTEM_PROMPT_ATTACK: "system_prompt_attack";
    readonly JAILBREAK: "jailbreak";
    readonly DELIMITER_INJECTION: "delimiter_injection";
    readonly ENCODING_ATTACK: "encoding_attack";
    readonly CONTEXT_MANIPULATION: "context_manipulation";
};
export type Category = (typeof CATEGORIES)[keyof typeof CATEGORIES];
/**
 * All detection patterns organized by category
 */
export declare const DETECTION_PATTERNS: DetectionPattern[];
/**
 * Get patterns by category
 */
export declare function getPatternsByCategory(category: Category): DetectionPattern[];
/**
 * Get patterns for multiple categories
 */
export declare function getPatternsForCategories(categories: Category[]): DetectionPattern[];
/**
 * Get all pattern IDs
 */
export declare function getAllPatternIds(): string[];
/**
 * Get pattern by ID
 */
export declare function getPatternById(id: string): DetectionPattern | undefined;
