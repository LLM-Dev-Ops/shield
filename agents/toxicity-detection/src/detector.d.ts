/**
 * Toxicity Detector
 *
 * Core detection logic for the Toxicity Detection Agent.
 * Handles pattern matching, scoring, and confidence calculation.
 *
 * @module toxicity-detection-agent/detector
 */
import type { ToxicityCategory, Severity, PatternMatch, DetectionConfig } from './types.js';
/**
 * Toxicity Detector class
 *
 * Detects toxic content in text using pattern matching and heuristics.
 * This class is stateless and can be reused across invocations.
 */
export declare class ToxicityDetector {
    private patterns;
    constructor();
    /**
     * Detect toxicity in content
     *
     * @param content - Text content to analyze
     * @param config - Detection configuration
     * @returns Array of pattern matches
     */
    detect(content: string, config: DetectionConfig): PatternMatch[];
    /**
     * Match a single pattern against content
     */
    private matchPattern;
    /**
     * Check if required context is present
     */
    private checkContext;
    /**
     * Filter patterns based on configuration
     */
    private filterPatterns;
    /**
     * Calculate confidence based on pattern, sensitivity, and indicators
     */
    private calculateConfidence;
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
        threshold?: number;
        detect_categories?: ToxicityCategory[];
    }): DetectionConfig;
}
