/**
 * @module ruvector-client
 * @description Client for persisting DecisionEvents to ruvector-service
 *
 * LLM-Shield agents NEVER connect directly to Google SQL.
 * All persistence occurs via ruvector-service API calls only.
 */
import type { SafetyBoundaryDecisionEvent } from '@llm-shield/agentics-contracts';
/**
 * Configuration for ruvector-service client
 */
export interface RuVectorClientConfig {
    /** Base URL of ruvector-service */
    baseUrl: string;
    /** API key for authentication */
    apiKey?: string;
    /** Request timeout in milliseconds */
    timeout?: number;
    /** Enable retry on transient failures */
    retryEnabled?: boolean;
    /** Maximum retry attempts */
    maxRetries?: number;
}
/**
 * Response from ruvector-service
 */
export interface RuVectorResponse {
    success: boolean;
    event_id?: string;
    error?: string;
    timestamp: string;
}
/**
 * Client for persisting DecisionEvents to ruvector-service
 *
 * This client handles:
 * - Event serialization
 * - HTTP transport
 * - Error handling
 * - Retry logic
 *
 * This client does NOT:
 * - Execute SQL queries
 * - Connect to databases directly
 * - Store raw content
 */
export declare class RuVectorClient {
    private readonly config;
    private readonly endpoint;
    constructor(config?: Partial<RuVectorClientConfig>);
    /**
     * Persist a SafetyBoundaryDecisionEvent to ruvector-service
     *
     * @param event - The DecisionEvent to persist
     * @returns Response from ruvector-service
     */
    persistDecisionEvent(event: SafetyBoundaryDecisionEvent): Promise<RuVectorResponse>;
    /**
     * Health check for ruvector-service
     */
    healthCheck(): Promise<boolean>;
    private delay;
}
/**
 * Create a mock client for testing
 */
export declare function createMockRuVectorClient(): RuVectorClient;
