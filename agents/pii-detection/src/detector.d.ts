/**
 * PII Detector
 *
 * Core detection logic for the PII Detection Agent.
 * Handles pattern matching, validation, and confidence calculation.
 *
 * @module pii-detection-agent/detector
 */
import type { PIIType, PIICountry, Severity, PatternMatch, DetectionConfig } from './types.js';
/**
 * PII Detector class
 *
 * Detects PII in text content using pattern matching and validation.
 * This class is stateless and can be reused across invocations.
 */
export declare class PIIDetector {
    private patterns;
    constructor();
    /**
     * Detect PII in content
     *
     * @param content - Text content to analyze
     * @param config - Detection configuration
     * @returns Array of pattern matches
     */
    detect(content: string, config: DetectionConfig): PatternMatch[];
    /**
     * Filter patterns based on configuration
     */
    private filterPatterns;
    /**
     * Validate a matched value
     */
    private validate;
    /**
     * Luhn algorithm for credit card validation
     */
    private luhnCheck;
    /**
     * SSN area number validation
     * - Area numbers 000, 666, and 900-999 are invalid
     * - Group number 00 is invalid
     * - Serial number 0000 is invalid
     */
    private ssnAreaCheck;
    /**
     * Basic format validation
     */
    private formatCheck;
    /**
     * Validate IP address ranges
     */
    private validateIPAddress;
    /**
     * Calculate confidence based on pattern, validation, and sensitivity
     */
    private calculateConfidence;
    /**
     * Get confidence threshold based on sensitivity
     */
    private getConfidenceThreshold;
    /**
     * Remove overlapping matches, keeping highest confidence
     */
    private deduplicateMatches;
    /**
     * Calculate overall risk score from matches
     */
    calculateRiskScore(matches: PatternMatch[]): number;
    /**
     * Get maximum severity from matches
     */
    getMaxSeverity(matches: PatternMatch[]): Severity;
    /**
     * Create default detection configuration
     */
    static createDefaultConfig(input: {
        sensitivity?: number;
        detect_types?: PIIType[];
        countries?: PIICountry[];
    }): DetectionConfig;
}
