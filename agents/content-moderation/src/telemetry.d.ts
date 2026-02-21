/**
 * @module telemetry
 * @description Telemetry emission for LLM-Observatory integration
 *
 * All agent invocations emit telemetry for observability.
 * Telemetry NEVER contains raw content, PII, or secrets.
 */
import type { AgentIdentity, ContentModerationDecisionEvent, ModerationAction } from '@llm-shield/agentics-contracts';
/**
 * Telemetry event types
 */
export type TelemetryEventType = 'agent.invocation.start' | 'agent.invocation.complete' | 'agent.invocation.error' | 'agent.moderation.decision' | 'agent.moderation.violation' | 'agent.persistence.success' | 'agent.persistence.failure';
/**
 * Base telemetry event
 */
export interface TelemetryEvent {
    type: TelemetryEventType;
    agent: AgentIdentity;
    execution_ref: string;
    timestamp: string;
    data: Record<string, unknown>;
}
/**
 * Telemetry configuration
 */
export interface TelemetryConfig {
    /** Enable telemetry emission */
    enabled: boolean;
    /** LLM-Observatory endpoint */
    observatoryUrl?: string;
    /** Batch events before sending */
    batchSize?: number;
    /** Flush interval in milliseconds */
    flushInterval?: number;
    /** Include detailed metrics */
    detailedMetrics?: boolean;
}
/**
 * Telemetry emitter for LLM-Observatory
 */
export declare class TelemetryEmitter {
    private readonly config;
    private readonly agent;
    private readonly buffer;
    private flushTimer;
    constructor(agent: AgentIdentity, config?: Partial<TelemetryConfig>);
    /**
     * Emit invocation start event
     */
    emitInvocationStart(executionRef: string, contentLength: number, contentSource: string, contentType?: string): void;
    /**
     * Emit invocation complete event
     */
    emitInvocationComplete(executionRef: string, durationMs: number, allowed: boolean, action: ModerationAction, riskScore: number, violationCount: number, requiresHumanReview: boolean): void;
    /**
     * Emit invocation error event
     */
    emitInvocationError(executionRef: string, errorCode: string, errorMessage: string): void;
    /**
     * Emit moderation decision event
     */
    emitModerationDecision(executionRef: string, action: ModerationAction, reason: string, confidence: number, requiresHumanReview: boolean): void;
    /**
     * Emit violation detection event (for detailed metrics)
     */
    emitViolationDetected(executionRef: string, category: string, patternId: string, confidence: number, severity: string, recommendedAction: ModerationAction): void;
    /**
     * Emit persistence success event
     */
    emitPersistenceSuccess(executionRef: string, eventId: string): void;
    /**
     * Emit persistence failure event
     */
    emitPersistenceFailure(executionRef: string, error: string): void;
    /**
     * Emit from DecisionEvent (convenience method)
     */
    emitFromDecisionEvent(event: ContentModerationDecisionEvent): void;
    /**
     * Force flush all buffered events
     */
    flush(): Promise<void>;
    /**
     * Shutdown the emitter
     */
    shutdown(): Promise<void>;
    private emit;
    private startFlushTimer;
    private sendEvents;
}
/**
 * Create a no-op telemetry emitter for testing
 */
export declare function createNoOpTelemetryEmitter(agent: AgentIdentity): TelemetryEmitter;
