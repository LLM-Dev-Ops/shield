/**
 * @module detector
 * @description Core detection logic for model abuse patterns
 *
 * This module provides stateless detection of model abuse patterns
 * using both content-based pattern matching and behavioral analysis.
 */
import type { ModelAbuseCategory, Severity, ModelAbuseDetectedEntity, RiskFactor } from '@llm-shield/agentics-contracts';
/**
 * Detection configuration
 */
export interface DetectionConfig {
    /** Detection sensitivity (0.0 - 1.0) */
    sensitivity: number;
    /** Detection threshold (0.0 - 1.0) */
    threshold: number;
    /** Categories to detect */
    categories?: ModelAbuseCategory[];
}
/**
 * Request metadata for behavioral analysis
 */
export interface RequestMetadata {
    requestRate?: number;
    clientIpHash?: string;
    userAgentHash?: string;
    sessionRequestCount?: number;
    sessionTokenUsage?: number;
    appearsAutomated?: boolean;
    apiEndpoint?: string;
    requestTimestamp?: string;
}
/**
 * Historical context for pattern detection
 */
export interface HistoricalContext {
    previousRequestCount?: number;
    previousViolationCount?: number;
    sessionDurationSeconds?: number;
}
/**
 * Behavioral analysis summary
 */
export interface BehavioralSummary {
    appearsAutomated: boolean;
    abnormalRate: boolean;
    matchesAbuseSignature: boolean;
    redFlagCount: number;
}
/**
 * Model Abuse Detector - stateless detection class
 */
export declare class ModelAbuseDetector {
    private patterns;
    private thresholds;
    constructor();
    /**
     * Detect model abuse patterns in content
     */
    detect(content: string, config: DetectionConfig, metadata?: RequestMetadata, historicalContext?: HistoricalContext): {
        entities: ModelAbuseDetectedEntity[];
        riskFactors: RiskFactor[];
        behavioralSummary: BehavioralSummary;
    };
    /**
     * Detect content-based patterns
     */
    private detectPatterns;
    /**
     * Detect behavioral patterns from metadata
     */
    private detectBehavioralPatterns;
    /**
     * Analyze behavioral patterns
     */
    private analyzeBehavior;
    /**
     * Convert matches to detected entities
     */
    private convertToEntities;
    /**
     * Build risk factors from matches
     */
    private buildRiskFactors;
    /**
     * Calculate confidence with sensitivity adjustment
     */
    private calculateConfidence;
    /**
     * Deduplicate overlapping matches
     */
    private deduplicateMatches;
    /**
     * Get highest severity for a category from matches
     */
    private getCategorySeverity;
    /**
     * Get average confidence for a category
     */
    private getCategoryConfidence;
    /**
     * Calculate overall risk score from entities
     */
    calculateRiskScore(entities: ModelAbuseDetectedEntity[], behavioralSummary: BehavioralSummary): number;
    /**
     * Get maximum severity from entities
     */
    getMaxSeverity(entities: ModelAbuseDetectedEntity[]): Severity;
    /**
     * Calculate overall confidence from entities
     */
    calculateOverallConfidence(entities: ModelAbuseDetectedEntity[]): number;
    /**
     * Get detected categories
     */
    getDetectedCategories(entities: ModelAbuseDetectedEntity[]): ModelAbuseCategory[];
    /**
     * Get category counts
     */
    getCategoryCounts(entities: ModelAbuseDetectedEntity[]): Record<string, number>;
}
/**
 * Create a new detector instance
 */
export declare function createDetector(): ModelAbuseDetector;
