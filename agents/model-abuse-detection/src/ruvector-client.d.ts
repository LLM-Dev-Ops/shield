/**
 * @module ruvector-client
 * @description Client for persisting DecisionEvents to ruvector-service
 *
 * CRITICAL: This is the ONLY module that communicates with ruvector-service.
 * All persistence of decisions, detections, and outcomes happens through this client.
 * LLM-Shield NEVER connects directly to Google SQL.
 */
import type { ModelAbuseDetectionDecisionEvent } from '@llm-shield/agentics-contracts';
/**
 * RuVector client configuration
 */
export interface RuVectorClientConfig {
    /** Service endpoint URL */
    endpoint: string;
    /** API authentication key */
    apiKey?: string;
    /** Request timeout in milliseconds */
    timeout?: number;
    /** Enable retry logic */
    retry?: boolean;
    /** Maximum retry attempts */
    maxRetries?: number;
}
/**
 * Response from ruvector-service
 */
export interface RuVectorResponse {
    /** Whether the operation succeeded */
    success: boolean;
    /** Event ID if persisted */
    event_id?: string;
    /** Timestamp when persisted */
    persisted_at?: string;
    /** Error message if failed */
    error?: string;
}
/**
 * RuVector client for decision event persistence
 */
export declare class RuVectorClient {
    private config;
    constructor(config: RuVectorClientConfig);
    /**
     * Persist a decision event to ruvector-service
     *
     * This is an async, non-blocking operation.
     * The agent does NOT wait for persistence confirmation before returning.
     */
    persistDecisionEvent(event: ModelAbuseDetectionDecisionEvent): Promise<RuVectorResponse>;
    /**
     * Retrieve a decision event by execution reference
     */
    getDecisionEvent(executionRef: string): Promise<ModelAbuseDetectionDecisionEvent | null>;
    /**
     * Health check for ruvector-service
     */
    healthCheck(): Promise<boolean>;
}
/**
 * Create RuVector client from environment variables
 */
export declare function createClientFromEnv(): RuVectorClient;
/**
 * Create a no-op client for testing/simulation
 */
export declare function createNoOpClient(): RuVectorClient;
