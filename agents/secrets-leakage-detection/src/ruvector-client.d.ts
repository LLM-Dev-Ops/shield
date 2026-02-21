/**
 * @module secrets-leakage-detection/ruvector-client
 * @description Client for persisting DecisionEvents to ruvector-service
 *
 * CRITICAL: This is the ONLY persistence mechanism.
 * LLM-Shield NEVER connects directly to Google SQL.
 * All persistence occurs via ruvector-service client calls only.
 */
import type { DecisionEvent } from '@llm-shield/agentics-contracts';
/**
 * Configuration for ruvector-service client
 */
export interface RuVectorClientConfig {
    /** Service endpoint URL */
    endpoint: string;
    /** API key for authentication */
    apiKey?: string;
    /** Request timeout in milliseconds */
    timeout?: number;
    /** Enable retry on failure */
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
    /** Error message if failed */
    error?: string;
    /** Timestamp of persistence */
    persisted_at?: string;
}
/**
 * Client for interacting with ruvector-service
 *
 * This client handles all persistence operations for DecisionEvents.
 * It never stores raw secrets, PII, or sensitive content.
 */
export declare class RuVectorClient {
    private readonly config;
    constructor(config: RuVectorClientConfig);
    /**
     * Persist a DecisionEvent to ruvector-service
     *
     * @param event - The DecisionEvent to persist
     * @returns Response from the service
     */
    persistDecisionEvent(event: DecisionEvent): Promise<RuVectorResponse>;
    /**
     * Retrieve a DecisionEvent by execution reference
     *
     * @param executionRef - The execution_ref UUID
     * @returns The DecisionEvent if found
     */
    getDecisionEvent(executionRef: string): Promise<DecisionEvent | null>;
}
/**
 * Create a ruvector-service client from environment variables
 */
export declare function createClientFromEnv(): RuVectorClient;
/**
 * Create a no-op client for testing (does not persist)
 */
export declare function createNoOpClient(): RuVectorClient;
