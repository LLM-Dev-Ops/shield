/**
 * @module agent
 * @description Content Moderation Enforcement Agent implementation
 *
 * Classification: ENFORCEMENT
 * Decision Type: content_moderation
 *
 * This agent applies moderation policies to classify or block
 * disallowed content categories.
 */
import { type AgentIdentity, type ContentModerationAgentOutput, type ContentModerationAgentInput, type ModerationAction } from '@llm-shield/agentics-contracts';
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
    /** Default moderation action */
    defaultAction?: ModerationAction;
    /** Minimum confidence for moderation */
    minModerationConfidence?: number;
    /** Enable detailed telemetry */
    detailedTelemetry?: boolean;
}
/**
 * Content Moderation Enforcement Agent
 *
 * Responsibilities:
 * - Detect content moderation violations
 * - Evaluate content against moderation policies
 * - Make enforcement decisions (ALLOW/BLOCK/FLAG/WARN/AGE_GATE)
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
export declare class ContentModerationAgent {
    private readonly ruvectorClient;
    private readonly telemetry;
    private readonly config;
    constructor(config?: AgentConfig);
    /**
     * Execute moderation on input content
     *
     * @param input - Validated input conforming to ContentModerationAgentInput schema
     * @returns ContentModerationAgentOutput with moderation results
     */
    moderate(input: ContentModerationAgentInput): Promise<ContentModerationAgentOutput>;
    /**
     * Validate input against schema
     */
    validateInput(input: unknown): ContentModerationAgentInput;
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
    private makeModerationDecision;
    private severityToScore;
    private persistDecisionEvent;
}
/**
 * Create agent instance with default configuration
 */
export declare function createAgent(config?: AgentConfig): ContentModerationAgent;
