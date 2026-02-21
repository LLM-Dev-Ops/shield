/**
 * @module agent
 * @description Prompt Injection Detection Agent implementation
 *
 * Classification: DETECTION_ONLY
 * Decision Type: prompt_injection_detection
 *
 * This agent detects prompt injection attempts in LLM input content.
 * It does NOT modify, sanitize, or block content - detection only.
 */
import { type AgentIdentity, type AgentOutput, type PromptInjectionDetectionInput } from '@llm-shield/agentics-contracts';
import { type RuVectorClientConfig } from './ruvector-client.js';
import { type TelemetryConfig } from './telemetry.js';
/**
 * Agent identity constant
 */
export declare const AGENT_IDENTITY: AgentIdentity;
/**
 * Agent configuration
 */
export interface AgentConfig {
    /** ruvector-service client configuration */
    ruvectorConfig?: Partial<RuVectorClientConfig>;
    /** Telemetry configuration */
    telemetryConfig?: Partial<TelemetryConfig>;
    /** Default sensitivity (0.0 - 1.0) */
    defaultSensitivity?: number;
    /** Enable detailed pattern matching telemetry */
    detailedTelemetry?: boolean;
}
/**
 * Prompt Injection Detection Agent
 *
 * Responsibilities:
 * - Detect prompt injection patterns in input content
 * - Calculate risk scores and confidence levels
 * - Emit DecisionEvents to ruvector-service
 * - Emit telemetry to LLM-Observatory
 *
 * Non-Responsibilities:
 * - Does NOT modify content
 * - Does NOT block or allow content
 * - Does NOT orchestrate workflows
 * - Does NOT retry operations
 * - Does NOT connect to databases directly
 */
export declare class PromptInjectionDetectionAgent {
    private readonly ruvectorClient;
    private readonly telemetry;
    private readonly config;
    constructor(config?: AgentConfig);
    /**
     * Execute detection on input content
     *
     * @param input - Validated input conforming to PromptInjectionDetectionInput schema
     * @returns AgentOutput with detection results
     */
    detect(input: PromptInjectionDetectionInput): Promise<AgentOutput>;
    /**
     * Validate input against schema
     */
    validateInput(input: unknown): PromptInjectionDetectionInput;
    /**
     * Shutdown agent gracefully
     */
    shutdown(): Promise<void>;
    private getActivePatterns;
    private findMatches;
    private buildEntities;
    private buildRiskFactors;
    private calculateRiskScore;
    private calculateConfidence;
    private adjustConfidence;
    private determineSeverity;
    private persistDecisionEvent;
}
/**
 * Create agent instance with default configuration
 */
export declare function createAgent(config?: AgentConfig): PromptInjectionDetectionAgent;
