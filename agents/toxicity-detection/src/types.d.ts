/**
 * Internal types for Toxicity Detection Agent
 *
 * @module toxicity-detection-agent/types
 */
import type { ToxicityCategory, Severity, ToxicityDetectedEntity, ToxicityDetectionInput, ToxicityDetectionResult, ToxicityDetectionAgentOutput, ToxicityDetectionDecisionEvent, RiskFactor, AgentIdentity, PolicyReference } from '@llm-shield/agentics-contracts';
export type { ToxicityCategory, Severity, ToxicityDetectedEntity, ToxicityDetectionInput, ToxicityDetectionResult, ToxicityDetectionAgentOutput, ToxicityDetectionDecisionEvent, RiskFactor, AgentIdentity, PolicyReference, };
/**
 * Agent identity constant
 */
export declare const AGENT_IDENTITY: AgentIdentity;
/**
 * Internal toxicity pattern definition
 */
export interface ToxicityPattern {
    /** Unique pattern identifier */
    id: string;
    /** Toxicity category this pattern detects */
    category: ToxicityCategory;
    /** Human-readable name */
    name: string;
    /** Keywords or phrases to match */
    keywords: string[];
    /** Regular expression pattern (optional) */
    pattern?: RegExp;
    /** Severity level for this pattern */
    severity: Severity;
    /** Base confidence score (0.0 - 1.0) */
    baseConfidence: number;
    /** Whether this is case-sensitive */
    caseSensitive?: boolean;
    /** Required context (e.g., must be near certain words) */
    contextRequired?: string[];
}
/**
 * Pattern match result
 */
export interface PatternMatch {
    /** Pattern that matched */
    pattern: ToxicityPattern;
    /** Start position in content */
    start: number;
    /** End position in content */
    end: number;
    /** Matched text (for internal scoring only, NOT persisted) */
    matchedText: string;
    /** Final confidence after context analysis */
    confidence: number;
    /** Number of indicators that contributed to this match */
    indicatorCount: number;
}
/**
 * Detection configuration with defaults applied
 */
export interface DetectionConfig {
    /** Detection sensitivity */
    sensitivity: number;
    /** Detection threshold */
    threshold: number;
    /** Toxicity categories to detect */
    detectCategories: ToxicityCategory[];
}
/**
 * Telemetry event for LLM-Observatory
 */
export interface TelemetryEvent {
    /** Event type */
    event_type: 'toxicity_detection';
    /** Agent ID */
    agent_id: string;
    /** Agent version */
    agent_version: string;
    /** Execution reference */
    execution_ref: string;
    /** Timestamp */
    timestamp: string;
    /** Duration in milliseconds */
    duration_ms: number;
    /** Content length (no content) */
    content_length: number;
    /** Content source */
    content_source: string;
    /** Whether toxicity was detected */
    toxicity_detected: boolean;
    /** Number of entities */
    entity_count: number;
    /** Detected categories */
    detected_categories: string[];
    /** Risk score */
    risk_score: number;
    /** Severity */
    severity: Severity;
    /** Session ID (if available) */
    session_id?: string;
    /** Caller ID (if available) */
    caller_id?: string;
}
/**
 * ruvector-service client configuration
 */
export interface RuvectorClientConfig {
    /** Service endpoint */
    endpoint: string;
    /** API key (if required) */
    apiKey?: string;
    /** Timeout in milliseconds */
    timeout?: number;
    /** Retry attempts */
    retryAttempts?: number;
}
/**
 * ruvector-service client interface
 */
export interface RuvectorClient {
    /** Persist a decision event */
    persistDecisionEvent(event: ToxicityDetectionDecisionEvent): Promise<void>;
    /** Health check */
    isHealthy(): Promise<boolean>;
}
/**
 * Severity weights for risk calculation
 */
export declare const SEVERITY_WEIGHTS: Record<Severity, number>;
/**
 * Default toxicity categories to detect when not specified
 */
export declare const DEFAULT_TOXICITY_CATEGORIES: ToxicityCategory[];
/**
 * Default detection threshold
 */
export declare const DEFAULT_THRESHOLD = 0.7;
/**
 * Default sensitivity
 */
export declare const DEFAULT_SENSITIVITY = 0.5;
