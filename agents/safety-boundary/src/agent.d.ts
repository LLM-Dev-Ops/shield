/**
 * @module agent
 * @description Safety Boundary Enforcement Agent implementation
 *
 * Classification: ENFORCEMENT
 * Decision Type: safety_boundary_enforcement
 *
 * This agent enforces safety boundaries by evaluating content against
 * configurable safety policies and making ALLOW/BLOCK enforcement decisions.
 */
import { type AgentIdentity, type SafetyBoundaryAgentOutput, type SafetyBoundaryAgentInput, type EnforcementAction } from '@llm-shield/agentics-contracts';
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
    /** Default enforcement action */
    defaultAction?: EnforcementAction;
    /** Minimum confidence for enforcement */
    minEnforcementConfidence?: number;
    /** Enable detailed telemetry */
    detailedTelemetry?: boolean;
}
/**
 * Safety Boundary Enforcement Agent
 *
 * Responsibilities:
 * - Detect safety boundary violations in content
 * - Evaluate content against policy rules
 * - Make enforcement decisions (ALLOW/BLOCK)
 * - Emit DecisionEvents to ruvector-service
 * - Emit telemetry to LLM-Observatory
 *
 * Non-Responsibilities:
 * - Does NOT modify content (enforcement only)
 * - Does NOT orchestrate workflows
 * - Does NOT retry operations
 * - Does NOT connect to databases directly
 * - Does NOT trigger alerts or incidents
 * - Does NOT modify policies at runtime
 */
export declare class SafetyBoundaryAgent {
    private readonly ruvectorClient;
    private readonly telemetry;
    private readonly config;
    constructor(config?: AgentConfig);
    /**
     * Execute enforcement on input content
     *
     * @param input - Validated input conforming to SafetyBoundaryAgentInput schema
     * @returns SafetyBoundaryAgentOutput with enforcement results
     */
    enforce(input: SafetyBoundaryAgentInput): Promise<SafetyBoundaryAgentOutput>;
    /**
     * Validate input against schema
     */
    validateInput(input: unknown): SafetyBoundaryAgentInput;
    /**
     * Shutdown agent gracefully
     */
    shutdown(): Promise<void>;
    private findMatches;
    private buildViolations;
    private buildRiskFactors;
    private calculateRiskScore;
    private calculateConfidence;
    private adjustConfidence;
    private determineSeverity;
    private countByCategory;
    private makeEnforcementDecision;
    private severityToScore;
    private persistDecisionEvent;
}
/**
 * Create agent instance with default configuration
 */
export declare function createAgent(config?: AgentConfig): SafetyBoundaryAgent;
