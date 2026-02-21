/**
 * Data Redaction Agent - Main Entry Point
 *
 * This is the main handler for the Data Redaction Agent.
 * It can be deployed as a Google Cloud Edge Function.
 *
 * Classification: REDACTION
 * Decision Type: data_redaction
 *
 * This agent:
 * - Detects PII, secrets, and credentials
 * - Redacts detected sensitive data
 * - Returns sanitized content
 * - Emits DecisionEvents to ruvector-service
 * - Emits telemetry to LLM-Observatory
 *
 * This agent does NOT:
 * - Orchestrate workflows
 * - Trigger retries
 * - Modify policies
 * - Connect to databases directly
 * - Store raw sensitive data
 */
import { z } from 'zod';
import { DataRedactionAgentInput, DataRedactionAgentOutput, AgentError } from '@llm-shield/agentics-contracts';
import { Redactor, hashContent, type RedactionConfig, type RedactionResult } from './redactor.js';
import { RuvectorClient, createRuvectorClient, type DecisionEventPayload } from './ruvector-client.js';
import { TelemetryEmitter, createTelemetryEmitter, type RedactionTelemetry } from './telemetry.js';
export declare const AGENT_ID = "data-redaction-agent";
export declare const AGENT_VERSION = "1.0.0";
export declare const AGENT_CLASSIFICATION: "REDACTION";
export declare const DECISION_TYPE: "data_redaction";
export interface AgentConfig {
    /** ruvector-service client configuration */
    ruvectorClient?: RuvectorClient;
    /** Telemetry emitter configuration */
    telemetryEmitter?: TelemetryEmitter;
    /** Skip persistence (for testing) */
    skipPersistence?: boolean;
    /** Skip telemetry (for testing) */
    skipTelemetry?: boolean;
}
export type DataRedactionInput = z.infer<typeof DataRedactionAgentInput>;
export type DataRedactionOutput = z.infer<typeof DataRedactionAgentOutput>;
export type AgentErrorOutput = z.infer<typeof AgentError>;
/**
 * Data Redaction Agent
 *
 * Detects and redacts sensitive data (PII, secrets, credentials) from content.
 */
export declare class DataRedactionAgent {
    private ruvectorClient;
    private telemetryEmitter;
    private skipPersistence;
    private skipTelemetry;
    constructor(config?: AgentConfig);
    /**
     * Process a redaction request
     *
     * @param input - The validated input
     * @returns Redaction result (with sanitized content)
     */
    process(input: DataRedactionInput): Promise<DataRedactionOutput | AgentErrorOutput>;
    /**
     * Validate input against schema
     */
    private validateInput;
    /**
     * Build redaction configuration from input
     */
    private buildRedactionConfig;
    /**
     * Build agent output from redaction result
     */
    private buildOutput;
    /**
     * Persist decision event to ruvector-service
     */
    private persistDecisionEvent;
    /**
     * Emit telemetry to LLM-Observatory
     */
    private emitTelemetry;
    /**
     * Build error response
     */
    private buildErrorResponse;
}
/**
 * GCP Edge Function handler
 *
 * This is the entry point for the Google Cloud Edge Function deployment.
 */
export declare function handleRequest(request: Request): Promise<Response>;
/**
 * CLI handler for test/simulate/inspect modes
 */
export declare function handleCli(mode: 'test' | 'simulate' | 'inspect', options: {
    content?: string;
    executionRef?: string;
    strategy?: string;
    sensitivity?: number;
    piiTypes?: string[];
    secretTypes?: string[];
    format?: 'json' | 'text' | 'table';
    verbose?: boolean;
}): Promise<string>;
export { Redactor, RuvectorClient, TelemetryEmitter, createRuvectorClient, createTelemetryEmitter, hashContent, };
export type { RedactionConfig, RedactionResult, RedactionTelemetry, DecisionEventPayload, };
