/**
 * @module telemetry
 * @description Telemetry emission for LLM-Observatory integration
 *
 * All agent invocations emit telemetry for observability.
 * Telemetry NEVER contains raw content, PII, or secrets.
 */

import type {
  AgentIdentity,
  ContentModerationDecisionEvent,
  ModerationAction,
} from '@llm-shield/agentics-contracts';

/**
 * Telemetry event types
 */
export type TelemetryEventType =
  | 'agent.invocation.start'
  | 'agent.invocation.complete'
  | 'agent.invocation.error'
  | 'agent.moderation.decision'
  | 'agent.moderation.violation'
  | 'agent.persistence.success'
  | 'agent.persistence.failure';

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
 * Default telemetry configuration
 */
const DEFAULT_CONFIG: TelemetryConfig = {
  enabled: process.env.TELEMETRY_ENABLED !== 'false',
  observatoryUrl: process.env.LLM_OBSERVATORY_URL || 'http://localhost:9090',
  batchSize: 10,
  flushInterval: 5000,
  detailedMetrics: false,
};

/**
 * Telemetry emitter for LLM-Observatory
 */
export class TelemetryEmitter {
  private readonly config: TelemetryConfig;
  private readonly agent: AgentIdentity;
  private readonly buffer: TelemetryEvent[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(agent: AgentIdentity, config: Partial<TelemetryConfig> = {}) {
    this.agent = agent;
    this.config = { ...DEFAULT_CONFIG, ...config };

    if (this.config.enabled && this.config.flushInterval) {
      this.startFlushTimer();
    }
  }

  /**
   * Emit invocation start event
   */
  emitInvocationStart(
    executionRef: string,
    contentLength: number,
    contentSource: string,
    contentType?: string
  ): void {
    this.emit({
      type: 'agent.invocation.start',
      agent: this.agent,
      execution_ref: executionRef,
      timestamp: new Date().toISOString(),
      data: {
        content_length: contentLength,
        content_source: contentSource,
        content_type: contentType,
      },
    });
  }

  /**
   * Emit invocation complete event
   */
  emitInvocationComplete(
    executionRef: string,
    durationMs: number,
    allowed: boolean,
    action: ModerationAction,
    riskScore: number,
    violationCount: number,
    requiresHumanReview: boolean
  ): void {
    this.emit({
      type: 'agent.invocation.complete',
      agent: this.agent,
      execution_ref: executionRef,
      timestamp: new Date().toISOString(),
      data: {
        duration_ms: durationMs,
        allowed,
        action,
        risk_score: riskScore,
        violation_count: violationCount,
        requires_human_review: requiresHumanReview,
      },
    });
  }

  /**
   * Emit invocation error event
   */
  emitInvocationError(
    executionRef: string,
    errorCode: string,
    errorMessage: string
  ): void {
    this.emit({
      type: 'agent.invocation.error',
      agent: this.agent,
      execution_ref: executionRef,
      timestamp: new Date().toISOString(),
      data: {
        error_code: errorCode,
        error_message: errorMessage,
      },
    });
  }

  /**
   * Emit moderation decision event
   */
  emitModerationDecision(
    executionRef: string,
    action: ModerationAction,
    reason: string,
    confidence: number,
    requiresHumanReview: boolean
  ): void {
    this.emit({
      type: 'agent.moderation.decision',
      agent: this.agent,
      execution_ref: executionRef,
      timestamp: new Date().toISOString(),
      data: {
        action,
        reason,
        confidence,
        requires_human_review: requiresHumanReview,
      },
    });
  }

  /**
   * Emit violation detection event (for detailed metrics)
   */
  emitViolationDetected(
    executionRef: string,
    category: string,
    patternId: string,
    confidence: number,
    severity: string,
    recommendedAction: ModerationAction
  ): void {
    if (!this.config.detailedMetrics) return;

    this.emit({
      type: 'agent.moderation.violation',
      agent: this.agent,
      execution_ref: executionRef,
      timestamp: new Date().toISOString(),
      data: {
        category,
        pattern_id: patternId,
        confidence,
        severity,
        recommended_action: recommendedAction,
      },
    });
  }

  /**
   * Emit persistence success event
   */
  emitPersistenceSuccess(executionRef: string, eventId: string): void {
    this.emit({
      type: 'agent.persistence.success',
      agent: this.agent,
      execution_ref: executionRef,
      timestamp: new Date().toISOString(),
      data: {
        event_id: eventId,
      },
    });
  }

  /**
   * Emit persistence failure event
   */
  emitPersistenceFailure(executionRef: string, error: string): void {
    this.emit({
      type: 'agent.persistence.failure',
      agent: this.agent,
      execution_ref: executionRef,
      timestamp: new Date().toISOString(),
      data: {
        error,
      },
    });
  }

  /**
   * Emit from DecisionEvent (convenience method)
   */
  emitFromDecisionEvent(event: ContentModerationDecisionEvent): void {
    this.emitInvocationComplete(
      event.execution_ref,
      event.duration_ms,
      event.outputs.allowed,
      event.outputs.action,
      event.outputs.risk_score,
      event.outputs.violation_count,
      event.outputs.requires_human_review
    );
  }

  /**
   * Force flush all buffered events
   */
  async flush(): Promise<void> {
    if (!this.config.enabled || this.buffer.length === 0) return;

    const events = [...this.buffer];
    this.buffer.length = 0;

    try {
      await this.sendEvents(events);
    } catch (error) {
      // Telemetry failures are non-fatal
      console.warn('[Telemetry] Failed to flush events:', error);
    }
  }

  /**
   * Shutdown the emitter
   */
  async shutdown(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flush();
  }

  private emit(event: TelemetryEvent): void {
    if (!this.config.enabled) return;

    this.buffer.push(event);

    if (this.buffer.length >= this.config.batchSize!) {
      this.flush().catch(() => {});
    }
  }

  private startFlushTimer(): void {
    this.flushTimer = setInterval(() => {
      this.flush().catch(() => {});
    }, this.config.flushInterval);
  }

  private async sendEvents(events: TelemetryEvent[]): Promise<void> {
    if (!this.config.observatoryUrl) return;

    const response = await fetch(
      `${this.config.observatoryUrl}/api/v1/telemetry/batch`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Agent-ID': this.agent.agent_id,
        },
        body: JSON.stringify({ events }),
      }
    );

    if (!response.ok) {
      throw new Error(`Observatory returned ${response.status}`);
    }
  }
}

/**
 * Create a no-op telemetry emitter for testing
 */
export function createNoOpTelemetryEmitter(
  agent: AgentIdentity
): TelemetryEmitter {
  return new TelemetryEmitter(agent, { enabled: false });
}
