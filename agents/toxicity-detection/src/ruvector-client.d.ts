/**
 * ruvector-service Client
 *
 * Client for persisting DecisionEvents to ruvector-service.
 * All database persistence MUST go through this client.
 *
 * CRITICAL: This is the ONLY path for data persistence.
 * The agent MUST NOT connect directly to Google SQL or any database.
 *
 * @module toxicity-detection-agent/ruvector-client
 */
import type { ToxicityDetectionDecisionEvent, RuvectorClient, RuvectorClientConfig } from './types.js';
/**
 * Create a ruvector-service client
 */
export declare function createRuvectorClient(config?: Partial<RuvectorClientConfig>): RuvectorClient;
/**
 * SHA-256 hash function for content
 *
 * Used to create inputs_hash for DecisionEvent.
 * The actual content is NEVER persisted, only the hash.
 */
export declare function sha256(content: string): Promise<string>;
/**
 * Create a DecisionEvent from agent output
 */
export declare function createDecisionEvent(params: {
    agentVersion: string;
    executionRef: string;
    timestamp: string;
    inputsHash: string;
    outputs: ToxicityDetectionDecisionEvent['outputs'];
    confidence: number;
    constraintsApplied: ToxicityDetectionDecisionEvent['constraints_applied'];
    durationMs: number;
    telemetry?: ToxicityDetectionDecisionEvent['telemetry'];
}): ToxicityDetectionDecisionEvent;
