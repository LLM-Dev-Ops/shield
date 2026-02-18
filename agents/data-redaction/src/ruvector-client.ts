/**
 * ruvector-service client for DecisionEvent persistence
 *
 * This client handles all persistence operations to ruvector-service.
 * LLM-Shield agents NEVER connect directly to databases.
 * All persistence goes through this client to ruvector-service.
 *
 * CRITICAL: Raw content, PII, secrets MUST NEVER be sent to this service.
 * Only hashes, counts, and sanitized metadata are persisted.
 */

import type { DataRedactionDecisionEvent, PolicyReference, RedactionStrategy, Severity } from '@llm-shield/agentics-contracts';

// =============================================================================
// INTERFACES
// =============================================================================

export interface RuvectorClientConfig {
  /** Base URL for ruvector-service */
  baseUrl: string;
  /** API key for authentication */
  apiKey?: string;
  /** Request timeout in ms */
  timeout: number;
  /** Retry attempts */
  retryAttempts: number;
  /** Retry delay in ms */
  retryDelay: number;
}

export interface PersistResult {
  /** Whether persistence was successful */
  success: boolean;
  /** Event ID if successful */
  eventId?: string;
  /** Error message if failed */
  error?: string;
  /** Retry count */
  retryCount: number;
}

export interface DecisionEventPayload {
  agentId: string;
  agentVersion: string;
  decisionType: 'data_redaction';
  inputsHash: string;
  outputsHash: string;
  outputs: {
    dataRedacted: boolean;
    redactionCount: number;
    originalRiskScore: number;
    severity: Severity;
    confidence: number;
    detectedCategories: string[];
    categoryCounts: Record<string, number>;
    severityCounts: Record<string, number>;
    entityTypeCounts: Record<string, number>;
  };
  confidence: number;
  constraintsApplied: PolicyReference[];
  executionRef: string;
  timestamp: string;
  durationMs: number;
  telemetry: {
    originalContentLength: number;
    redactedContentLength: number;
    contentSource: string;
    sessionId?: string;
    callerId?: string;
    redactionStrategy: RedactionStrategy;
  };
}

// =============================================================================
// DEFAULT CONFIGURATION
// =============================================================================

const DEFAULT_CONFIG: RuvectorClientConfig = {
  baseUrl: process.env.RUVECTOR_SERVICE_URL || 'http://localhost:8080',
  apiKey: process.env.RUVECTOR_API_KEY,
  timeout: 5000,
  retryAttempts: 3,
  retryDelay: 1000,
};

// =============================================================================
// RUVECTOR CLIENT
// =============================================================================

/**
 * Client for persisting DecisionEvents to ruvector-service
 */
export class RuvectorClient {
  private config: RuvectorClientConfig;

  constructor(config: Partial<RuvectorClientConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Persist a DecisionEvent to ruvector-service
   *
   * @param payload - The decision event data (no raw content)
   * @returns Persistence result
   */
  async persistDecisionEvent(payload: DecisionEventPayload): Promise<PersistResult> {
    // Convert to wire format
    const event: DataRedactionDecisionEvent = {
      agent_id: 'data-redaction-agent',
      agent_version: payload.agentVersion,
      decision_type: 'data_redaction',
      inputs_hash: payload.inputsHash,
      outputs_hash: payload.outputsHash,
      outputs: {
        data_redacted: payload.outputs.dataRedacted,
        redaction_count: payload.outputs.redactionCount,
        original_risk_score: payload.outputs.originalRiskScore,
        severity: payload.outputs.severity,
        confidence: payload.outputs.confidence,
        detected_categories: payload.outputs.detectedCategories,
        category_counts: payload.outputs.categoryCounts,
        severity_counts: payload.outputs.severityCounts,
        entity_type_counts: payload.outputs.entityTypeCounts,
      },
      confidence: payload.confidence,
      constraints_applied: payload.constraintsApplied,
      execution_ref: payload.executionRef,
      timestamp: payload.timestamp,
      duration_ms: payload.durationMs,
      telemetry: {
        original_content_length: payload.telemetry.originalContentLength,
        redacted_content_length: payload.telemetry.redactedContentLength,
        content_source: payload.telemetry.contentSource,
        session_id: payload.telemetry.sessionId,
        caller_id: payload.telemetry.callerId,
        redaction_strategy: payload.telemetry.redactionStrategy,
      },
    };

    return this.sendWithRetry(event);
  }

  /**
   * Send event with retry logic
   */
  private async sendWithRetry(event: DataRedactionDecisionEvent): Promise<PersistResult> {
    let lastError: Error | undefined;
    let retryCount = 0;

    for (let attempt = 0; attempt <= this.config.retryAttempts; attempt++) {
      try {
        const result = await this.sendRequest(event);
        return {
          success: true,
          eventId: result.eventId,
          retryCount,
        };
      } catch (error) {
        lastError = error as Error;
        retryCount = attempt;

        if (attempt < this.config.retryAttempts) {
          await this.delay(this.config.retryDelay * (attempt + 1));
        }
      }
    }

    return {
      success: false,
      error: lastError?.message || 'Unknown error',
      retryCount,
    };
  }

  /**
   * Send HTTP request to ruvector-service
   */
  private async sendRequest(event: DataRedactionDecisionEvent): Promise<{ eventId: string }> {
    const url = `${this.config.baseUrl}/api/v1/decisions`;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Agent-ID': 'data-redaction-agent',
      'X-Agent-Version': event.agent_version,
    };

    if (this.config.apiKey) {
      headers['Authorization'] = `Bearer ${this.config.apiKey}`;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(event),
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`ruvector-service error: ${response.status} - ${errorText}`);
      }

      const result = await response.json() as Record<string, unknown>;
      return { eventId: (result.event_id || result.id) as string };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Delay helper
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Health check for ruvector-service
   */
  async healthCheck(): Promise<boolean> {
    try {
      const url = `${this.config.baseUrl}/health`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);

      try {
        const response = await fetch(url, {
          method: 'GET',
          signal: controller.signal,
        });
        return response.ok;
      } finally {
        clearTimeout(timeoutId);
      }
    } catch {
      return false;
    }
  }
}

/**
 * Create a default ruvector client instance
 */
export function createRuvectorClient(config?: Partial<RuvectorClientConfig>): RuvectorClient {
  return new RuvectorClient(config);
}
