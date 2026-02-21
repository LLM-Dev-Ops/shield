/**
 * @module patterns
 * @description Model abuse detection patterns for identifying misuse and exploitation
 *
 * These patterns detect various forms of model abuse including:
 * - Rate limit evasion attempts
 * - Model extraction attempts
 * - Training data extraction
 * - Adversarial inputs
 * - API abuse patterns
 */
import type { ModelAbuseCategory, Severity } from '@llm-shield/agentics-contracts';
/**
 * Model abuse pattern definition
 */
export interface ModelAbusePattern {
    /** Unique pattern identifier */
    id: string;
    /** Abuse category this pattern detects */
    category: ModelAbuseCategory;
    /** Human-readable name */
    name: string;
    /** Regex pattern for content-based detection */
    pattern: RegExp;
    /** Severity level of this abuse type */
    severity: Severity;
    /** Base confidence score for this pattern (0.0 - 1.0) */
    baseConfidence: number;
    /** Description of what this pattern detects */
    description: string;
    /** Behavioral indicators that strengthen detection */
    behavioralIndicators?: string[];
}
/**
 * Behavioral threshold definition
 */
export interface BehavioralThreshold {
    /** Threshold identifier */
    id: string;
    /** Abuse category this threshold applies to */
    category: ModelAbuseCategory;
    /** Threshold name */
    name: string;
    /** Description */
    description: string;
    /** Severity when threshold is exceeded */
    severity: Severity;
    /** Threshold value */
    threshold: number;
    /** Unit of measurement */
    unit: string;
    /** Base confidence when exceeded */
    baseConfidence: number;
}
/**
 * Content-based abuse detection patterns
 */
export declare const MODEL_ABUSE_PATTERNS: ModelAbusePattern[];
/**
 * Behavioral thresholds for abuse detection
 */
export declare const BEHAVIORAL_THRESHOLDS: BehavioralThreshold[];
/**
 * Get all pattern IDs
 */
export declare function getAllPatternIds(): string[];
/**
 * Get patterns for specific categories
 */
export declare function getPatternsForCategories(categories: ModelAbuseCategory[]): ModelAbusePattern[];
/**
 * Get behavioral thresholds for specific categories
 */
export declare function getThresholdsForCategories(categories: ModelAbuseCategory[]): BehavioralThreshold[];
/**
 * Get pattern by ID
 */
export declare function getPatternById(id: string): ModelAbusePattern | undefined;
/**
 * Get threshold by ID
 */
export declare function getThresholdById(id: string): BehavioralThreshold | undefined;
