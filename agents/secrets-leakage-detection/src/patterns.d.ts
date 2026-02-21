/**
 * @module secrets-leakage-detection/patterns
 * @description Secret detection patterns for the Secrets Leakage Detection Agent
 */
import type { SecretTypeCategory } from '@llm-shield/agentics-contracts';
export interface SecretPattern {
    /** Unique pattern identifier */
    pattern_id: string;
    /** Regular expression for matching */
    regex: RegExp;
    /** Category of secret */
    category: SecretTypeCategory;
    /** Default severity for matches */
    severity: 'low' | 'medium' | 'high' | 'critical';
    /** Base confidence for pattern matches */
    confidence: number;
    /** Human-readable description */
    description: string;
}
/**
 * Built-in secret detection patterns organized by category
 */
export declare const SECRET_PATTERNS: ReadonlyArray<SecretPattern>;
/**
 * Get patterns filtered by category
 */
export declare function getPatternsByCategory(categories?: SecretTypeCategory[]): SecretPattern[];
/**
 * Create custom pattern from user input
 */
export declare function createCustomPattern(patternId: string, regexStr: string, category?: SecretTypeCategory): SecretPattern | null;
