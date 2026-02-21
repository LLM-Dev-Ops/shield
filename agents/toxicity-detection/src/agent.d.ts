/**
 * Toxicity Detection Agent
 *
 * Main agent implementation that orchestrates toxicity detection.
 *
 * Classification: DETECTION_ONLY
 * Decision Type: toxicity_detection
 *
 * This agent:
 * - Inspects prompts, outputs, and tool calls
 * - Detects toxicity patterns with confidence scoring
 * - Classifies toxicity by category
 * - Emits DecisionEvents to ruvector-service
 *
 * This agent does NOT:
 * - Modify, sanitize, or redact content
 * - Block or allow content
 * - Orchestrate workflows
 * - Trigger retries or escalations
 * - Connect directly to databases
 *
 * @module toxicity-detection-agent/agent
 */
import { TelemetryEmitter } from './telemetry.js';
import { type ToxicityDetectionInput, type ToxicityDetectionAgentOutput, type RuvectorClient } from './types.js';
/**
 * Agent configuration
 */
export interface ToxicityDetectionAgentConfig {
    /** ruvector-service client (optional, creates default if not provided) */
    ruvectorClient?: RuvectorClient;
    /** Telemetry emitter (optional, uses global if not provided) */
    telemetryEmitter?: TelemetryEmitter;
    /** Whether to persist DecisionEvents (default: true) */
    persistEvents?: boolean;
    /** Whether to emit telemetry (default: true) */
    emitTelemetry?: boolean;
}
/**
 * Toxicity Detection Agent
 *
 * Stateless agent that detects toxic content.
 * Each invocation produces exactly one DecisionEvent.
 */
export declare class ToxicityDetectionAgent {
    private detector;
    private ruvectorClient;
    private telemetryEmitter;
    private persistEvents;
    private emitTelemetry;
    constructor(config?: ToxicityDetectionAgentConfig);
    /**
     * Detect toxicity in content
     *
     * Main entry point for toxicity detection. Validates input, runs detection,
     * and emits DecisionEvent.
     *
     * @param input - Detection input following ToxicityDetectionInput schema
     * @returns Agent output with detection results
     */
    detect(input: ToxicityDetectionInput): Promise<ToxicityDetectionAgentOutput>;
    /**
     * Validate input against schema
     */
    private validateInput;
    /**
     * Create detection result from matches
     */
    private createResult;
    /**
     * Create risk factors from matches
     */
    private createRiskFactors;
    /**
     * Get severity weight
     */
    private getSeverityWeight;
    /**
     * Persist DecisionEvent to ruvector-service
     */
    private persistDecisionEvent;
    /**
     * Emit telemetry event
     */
    private emitTelemetryEvent;
    /**
     * Create an AgentError from an exception
     */
    private createAgentError;
}
