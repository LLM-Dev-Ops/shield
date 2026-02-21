/**
 * Redaction logic for the Data Redaction Agent
 *
 * This module handles the detection and redaction of sensitive data.
 * It produces sanitized output with no raw sensitive data exposed.
 */
import { type DetectionPattern } from './patterns.js';
import type { RedactionStrategy, Severity, PIITypeCategory, SecretTypeCategory } from '@llm-shield/agentics-contracts';
export interface RedactionConfig {
    /** Detection sensitivity (0.0 - 1.0) */
    sensitivity: number;
    /** Redaction strategy */
    strategy: RedactionStrategy;
    /** PII types to detect (undefined = all) */
    piiTypes?: PIITypeCategory[];
    /** Secret types to detect (undefined = all) */
    secretTypes?: SecretTypeCategory[];
    /** Enable PII detection */
    detectPii: boolean;
    /** Enable secret detection */
    detectSecrets: boolean;
    /** Enable credential detection */
    detectCredentials: boolean;
    /** Minimum confidence threshold */
    minConfidence: number;
    /** Return redacted content */
    returnRedactedContent: boolean;
    /** Custom placeholder */
    customPlaceholder?: string;
    /** Chars to preserve for partial_mask */
    partialMaskChars: number;
}
export interface DetectedMatch {
    /** Pattern that matched */
    pattern: DetectionPattern;
    /** Match text (for internal use only, NEVER persisted) */
    matchText: string;
    /** Start position in original */
    start: number;
    /** End position in original */
    end: number;
    /** Calculated confidence */
    confidence: number;
    /** Placeholder to use */
    placeholder: string;
}
export interface RedactedEntityResult {
    entityType: string;
    category: 'pii' | 'secret' | 'credential';
    originalStart: number;
    originalEnd: number;
    redactedStart: number;
    redactedEnd: number;
    confidence: number;
    severity: Severity;
    patternId: string;
    strategyApplied: RedactionStrategy;
    originalLength: number;
    redactedPlaceholder: string;
}
export interface RedactionResult {
    /** Whether any data was redacted */
    dataRedacted: boolean;
    /** Number of redactions */
    redactionCount: number;
    /** Risk score of original content */
    originalRiskScore: number;
    /** Overall severity */
    severity: Severity;
    /** Overall confidence */
    confidence: number;
    /** Redacted entities metadata */
    redactedEntities: RedactedEntityResult[];
    /** Redacted (sanitized) content */
    redactedContent?: string;
    /** Detected categories */
    detectedCategories: string[];
    /** Count by category */
    categoryCounts: Record<string, number>;
    /** Count by severity */
    severityCounts: Record<string, number>;
    /** Count by entity type */
    entityTypeCounts: Record<string, number>;
}
/**
 * Main redaction engine
 */
export declare class Redactor {
    private config;
    constructor(config: RedactionConfig);
    /**
     * Redact sensitive data from content
     *
     * @param content - The content to redact
     * @returns Redaction result with sanitized output
     */
    redact(content: string): RedactionResult;
    /**
     * Get applicable patterns based on config
     */
    private getApplicablePatterns;
    /**
     * Detect all matches in content
     */
    private detectMatches;
    /**
     * Get placeholder for a match based on strategy
     */
    private getPlaceholder;
    /**
     * Generate pseudonymized replacement
     */
    private pseudonymize;
    /**
     * Apply partial masking
     */
    private partialMask;
    /**
     * Count entities by a key
     */
    private countBy;
    /**
     * Calculate maximum severity
     */
    private calculateMaxSeverity;
    /**
     * Calculate average confidence
     */
    private calculateAverageConfidence;
    /**
     * Calculate risk score
     */
    private calculateRiskScore;
}
/**
 * Compute SHA-256 hash of content
 */
export declare function hashContent(content: string): string;
