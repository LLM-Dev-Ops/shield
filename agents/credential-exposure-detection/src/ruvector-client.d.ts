/**
 * @module credential-exposure-detection/ruvector-client
 * @description Client for persisting DecisionEvents to ruvector-service
 *
 * CRITICAL: This is the ONLY persistence mechanism.
 * LLM-Shield NEVER connects directly to Google SQL.
 * All persistence occurs via ruvector-service client calls only.
 *
 * SECURITY: Raw credentials (usernames, passwords) are NEVER stored.
 * Only SHA-256 hashes and aggregated metadata are persisted.
 */
import type { CredentialExposureDecisionEvent } from '@llm-shield/agentics-contracts';
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
 * It never stores raw credentials, PII, or sensitive content.
 */
export declare class RuVectorClient {
    private readonly config;
    constructor(config: RuVectorClientConfig);
    /**
     * Persist a CredentialExposureDecisionEvent to ruvector-service
     *
     * @param event - The DecisionEvent to persist
     * @returns Response from the service
     */
    persistDecisionEvent(event: CredentialExposureDecisionEvent): Promise<RuVectorResponse>;
    /**
     * Retrieve a DecisionEvent by execution reference
     *
     * @param executionRef - The execution_ref UUID
     * @returns The DecisionEvent if found
     */
    getDecisionEvent(executionRef: string): Promise<CredentialExposureDecisionEvent | null>;
    /**
     * Health check for ruvector-service
     *
     * @returns Whether the service is healthy
     */
    healthCheck(): Promise<boolean>;
}
/**
 * Create a ruvector-service client from environment variables
 */
export declare function createClientFromEnv(): RuVectorClient;
/**
 * Create a no-op client for testing (does not persist)
 */
export declare function createNoOpClient(): RuVectorClient;
