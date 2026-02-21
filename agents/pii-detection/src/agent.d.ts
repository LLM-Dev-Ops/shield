/**
 * PII Detection Agent
 *
 * Main agent implementation that orchestrates PII detection.
 *
 * Classification: DETECTION_ONLY
 * Decision Type: pii_detection
 *
 * This agent:
 * - Inspects prompts, outputs, and tool calls
 * - Detects PII patterns with validation
 * - Calculates confidence scores
 * - Emits DecisionEvents to ruvector-service
 *
 * This agent does NOT:
 * - Modify, sanitize, or redact content
 * - Block or allow content
 * - Orchestrate workflows
 * - Trigger retries or escalations
 * - Connect directly to databases
 *
 * @module pii-detection-agent/agent
 */
import { TelemetryEmitter } from './telemetry.js';
import { type PIIDetectionInput, type PIIDetectionAgentOutput, type RuvectorClient } from './types.js';
/**
 * Agent configuration
 */
export interface PIIDetectionAgentConfig {
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
 * PII Detection Agent
 *
 * Stateless agent that detects PII in content.
 * Each invocation produces exactly one DecisionEvent.
 */
export declare class PIIDetectionAgent {
    private detector;
    private ruvectorClient;
    private telemetryEmitter;
    private persistEvents;
    private emitTelemetry;
    constructor(config?: PIIDetectionAgentConfig);
    /**
     * Detect PII in content
     *
     * Main entry point for PII detection. Validates input, runs detection,
     * and emits DecisionEvent.
     *
     * @param input - Detection input following PIIDetectionInput schema
     * @returns Agent output with detection results
     */
    detect(input: PIIDetectionInput): Promise<PIIDetectionAgentOutput>;
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
