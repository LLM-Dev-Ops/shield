/**
 * Detection patterns for the Data Redaction Agent
 *
 * IMPORTANT: These patterns are used for DETECTION only.
 * Raw matched content is NEVER persisted to ruvector-service.
 */
import type { Severity } from '@llm-shield/agentics-contracts';
export interface DetectionPattern {
    /** Unique pattern identifier */
    id: string;
    /** Category: pii, secret, or credential */
    category: 'pii' | 'secret' | 'credential';
    /** Specific entity type */
    type: string;
    /** Regular expression for detection */
    pattern: RegExp;
    /** Severity level */
    severity: Severity;
    /** Base confidence score (0.0 - 1.0) */
    baseConfidence: number;
    /** Optional validation function */
    validate?: (match: string) => boolean;
}
export declare const PII_PATTERNS: DetectionPattern[];
export declare const SECRET_PATTERNS: DetectionPattern[];
export declare const CREDENTIAL_PATTERNS: DetectionPattern[];
export declare const ALL_PATTERNS: DetectionPattern[];
/**
 * Get patterns by category
 */
export declare function getPatternsByCategory(category: 'pii' | 'secret' | 'credential'): DetectionPattern[];
/**
 * Get patterns by type
 */
export declare function getPatternsByType(type: string): DetectionPattern[];
/**
 * Get pattern by ID
 */
export declare function getPatternById(id: string): DetectionPattern | undefined;
