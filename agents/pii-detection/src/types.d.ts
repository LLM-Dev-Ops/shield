/**
 * Internal types for PII Detection Agent
 *
 * @module pii-detection-agent/types
 */
import type { PIIType, PIICountry, Severity, PIIDetectedEntity, PIIDetectionInput, PIIDetectionResult, PIIDetectionAgentOutput, PIIDetectionDecisionEvent, RiskFactor, AgentIdentity, PolicyReference } from '@llm-shield/agentics-contracts';
export type { PIIType, PIICountry, Severity, PIIDetectedEntity, PIIDetectionInput, PIIDetectionResult, PIIDetectionAgentOutput, PIIDetectionDecisionEvent, RiskFactor, AgentIdentity, PolicyReference, };
/**
 * Agent identity constant
 */
export declare const AGENT_IDENTITY: AgentIdentity;
/**
 * Internal PII pattern definition
 */
export interface PIIPattern {
    /** Unique pattern identifier */
    id: string;
    /** PII type this pattern detects */
    type: PIIType;
    /** Human-readable name */
    name: string;
    /** Regular expression pattern */
    pattern: RegExp;
    /** Severity level for this pattern */
    severity: Severity;
    /** Base confidence score (0.0 - 1.0) */
    baseConfidence: number;
    /** Validation method (if any) */
    validationMethod?: 'luhn' | 'area_check' | 'format' | 'checksum';
    /** Country codes this pattern applies to */
    countries?: PIICountry[];
}
/**
 * Pattern match result
 */
export interface PatternMatch {
    /** Pattern that matched */
    pattern: PIIPattern;
    /** Start position in content */
    start: number;
    /** End position in content */
    end: number;
    /** Matched text (for internal validation only, NOT persisted) */
    matchedText: string;
    /** Whether validation passed (if applicable) */
    validationPassed?: boolean;
    /** Final confidence after validation */
    confidence: number;
}
/**
 * Detection configuration with defaults applied
 */
export interface DetectionConfig {
    /** Detection sensitivity */
    sensitivity: number;
    /** PII types to detect */
    detectTypes: PIIType[];
    /** Countries to check */
    countries: PIICountry[];
}
/**
 * Telemetry event for LLM-Observatory
 */
export interface TelemetryEvent {
    /** Event type */
    event_type: 'pii_detection';
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
    /** Whether PII was detected */
    pii_detected: boolean;
    /** Number of entities */
    entity_count: number;
    /** Detected types */
    detected_types: string[];
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
    persistDecisionEvent(event: PIIDetectionDecisionEvent): Promise<void>;
    /** Health check */
    isHealthy(): Promise<boolean>;
}
/**
 * Severity weights for risk calculation
 */
export declare const SEVERITY_WEIGHTS: Record<Severity, number>;
/**
 * Default PII types to detect when not specified
 */
export declare const DEFAULT_PII_TYPES: PIIType[];
/**
 * Default countries when not specified
 */
export declare const DEFAULT_COUNTRIES: PIICountry[];
