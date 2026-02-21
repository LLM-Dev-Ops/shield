/**
 * ruvector-service client for DecisionEvent persistence
 *
 * This client handles all persistence operations to ruvector-service.
 * LLM-Shield agents NEVER connect directly to databases.
 * All persistence goes through this client to ruvector-service.
 *
 * CRITICAL: Raw content, PII, secrets MUST NEVER be sent to this service.
 * Only hashes, counts, and sanitized metadata are persisted.
 */
import type { PolicyReference, RedactionStrategy, Severity } from '@llm-shield/agentics-contracts';
export interface RuvectorClientConfig {
    /** Base URL for ruvector-service */
    baseUrl: string;
    /** API key for authentication */
    apiKey?: string;
    /** Request timeout in ms */
    timeout: number;
    /** Retry attempts */
    retryAttempts: number;
    /** Retry delay in ms */
    retryDelay: number;
}
export interface PersistResult {
    /** Whether persistence was successful */
    success: boolean;
    /** Event ID if successful */
    eventId?: string;
    /** Error message if failed */
    error?: string;
    /** Retry count */
    retryCount: number;
}
export interface DecisionEventPayload {
    agentId: string;
    agentVersion: string;
    decisionType: 'data_redaction';
    inputsHash: string;
    outputsHash: string;
    outputs: {
        dataRedacted: boolean;
        redactionCount: number;
        originalRiskScore: number;
        severity: Severity;
        confidence: number;
        detectedCategories: string[];
        categoryCounts: Record<string, number>;
        severityCounts: Record<string, number>;
        entityTypeCounts: Record<string, number>;
    };
    confidence: number;
    constraintsApplied: PolicyReference[];
    executionRef: string;
    timestamp: string;
    durationMs: number;
    telemetry: {
        originalContentLength: number;
        redactedContentLength: number;
        contentSource: string;
        sessionId?: string;
        callerId?: string;
        redactionStrategy: RedactionStrategy;
    };
}
/**
 * Client for persisting DecisionEvents to ruvector-service
 */
export declare class RuvectorClient {
    private config;
    constructor(config?: Partial<RuvectorClientConfig>);
    /**
     * Persist a DecisionEvent to ruvector-service
     *
     * @param payload - The decision event data (no raw content)
     * @returns Persistence result
     */
    persistDecisionEvent(payload: DecisionEventPayload): Promise<PersistResult>;
    /**
     * Send event with retry logic
     */
    private sendWithRetry;
    /**
     * Send HTTP request to ruvector-service
     */
    private sendRequest;
    /**
     * Delay helper
     */
    private delay;
    /**
     * Health check for ruvector-service
     */
    healthCheck(): Promise<boolean>;
}
/**
 * Create a default ruvector client instance
 */
export declare function createRuvectorClient(config?: Partial<RuvectorClientConfig>): RuvectorClient;
