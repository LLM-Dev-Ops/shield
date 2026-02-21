/**
 * @module handler
 * @description Google Cloud Edge Function handler for Model Abuse Detection Agent
 *
 * This module implements the HTTP handler for the agent, designed to be deployed
 * as a Google Cloud Edge Function. It is stateless and deterministic.
 */
import { ModelAbuseDetectionAgentOutput, AgentError, AgentIdentity } from '@llm-shield/agentics-contracts';
import { RuVectorClient } from './ruvector-client.js';
import { TelemetryEmitter } from './telemetry.js';
/**
 * Agent identity constant
 */
export declare const AGENT_IDENTITY: AgentIdentity;
/**
 * Handler configuration
 */
export interface HandlerConfig {
    /** RuVector client (optional, created from env if not provided) */
    ruvectorClient?: RuVectorClient;
    /** Telemetry emitter (optional, created from env if not provided) */
    telemetryEmitter?: TelemetryEmitter;
    /** Skip persistence (for simulation mode) */
    skipPersistence?: boolean;
    /** Skip telemetry */
    skipTelemetry?: boolean;
}
/**
 * Handle detection request
 *
 * This is the main entry point for the agent. It:
 * 1. Validates input against schema
 * 2. Performs detection
 * 3. Persists decision event to ruvector-service
 * 4. Emits telemetry
 * 5. Returns result
 */
export declare function handleDetection(rawInput: unknown, config?: HandlerConfig): Promise<ModelAbuseDetectionAgentOutput | AgentError>;
/**
 * Google Cloud Edge Function export
 *
 * This is the entry point for the Edge Function.
 * It handles HTTP requests and returns responses.
 */
declare const _default: {
    fetch(request: Request): Promise<Response>;
};
export default _default;
