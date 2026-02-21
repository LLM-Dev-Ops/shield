/**
 * @module secrets-leakage-detection/handler
 * @description Edge Function handler for Secrets Leakage Detection Agent
 *
 * Deployment: Google Cloud Edge Function
 * Classification: DETECTION-ONLY
 * Decision Type: secret_detection
 *
 * This agent:
 * - Inspects prompts, model outputs, and tool calls
 * - Detects secret patterns using regex and entropy analysis
 * - Calculates confidence scores
 * - Emits DecisionEvents to ruvector-service
 *
 * This agent MUST NOT:
 * - Modify, sanitize, or redact content
 * - Orchestrate workflows
 * - Trigger retries or alerts
 * - Modify policies
 * - Connect directly to databases
 * - Store raw secrets
 */
import { AgentOutput, AgentError } from '@llm-shield/agentics-contracts';
import { RuVectorClient } from './ruvector-client.js';
import { TelemetryEmitter } from './telemetry.js';
/**
 * Handler configuration
 */
export interface HandlerConfig {
    /** ruvector-service client */
    ruvectorClient?: RuVectorClient;
    /** Telemetry emitter */
    telemetryEmitter?: TelemetryEmitter;
    /** Skip persistence (for testing) */
    skipPersistence?: boolean;
}
/**
 * Main detection handler
 *
 * This is the Edge Function entry point.
 */
export declare function handleDetection(rawInput: unknown, config?: HandlerConfig): Promise<AgentOutput | AgentError>;
/**
 * Edge Function export
 *
 * Compatible with Google Cloud Functions, Cloudflare Workers, Vercel Edge
 */
declare const _default: {
    fetch(request: Request): Promise<Response>;
};
export default _default;
