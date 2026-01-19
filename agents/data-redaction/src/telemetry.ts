/**
 * Telemetry emission for LLM-Observatory
 *
 * This module handles telemetry emission for observability.
 * All telemetry is sanitized - no raw content is ever emitted.
 */

// =============================================================================
// INTERFACES
// =============================================================================

export interface TelemetryConfig {
  /** Enable telemetry emission */
  enabled: boolean;
  /** Service name */
  serviceName: string;
  /** Environment (production, staging, development) */
  environment: string;
  /** Collector endpoint */
  collectorUrl?: string;
}

export interface RedactionTelemetry {
  /** Agent ID */
  agentId: string;
  /** Agent version */
  agentVersion: string;
  /** Decision type */
  decisionType: string;
  /** Execution reference (trace ID) */
  executionRef: string;
  /** Content source */
  contentSource: string;
  /** Original content length (NOT the content) */
  originalContentLength: number;
  /** Redacted content length */
  redactedContentLength: number;
  /** Whether data was redacted */
  dataRedacted: boolean;
  /** Number of redactions */
  redactionCount: number;
  /** Categories detected */
  detectedCategories: string[];
  /** Severity */
  severity: string;
  /** Confidence */
  confidence: number;
  /** Risk score */
  riskScore: number;
  /** Redaction strategy used */
  redactionStrategy: string;
  /** Duration in ms */
  durationMs: number;
  /** Timestamp */
  timestamp: string;
  /** Session ID (if available) */
  sessionId?: string;
  /** Caller ID (if available) */
  callerId?: string;
  /** Persistence result */
  persistenceSuccess?: boolean;
  /** Error if any (no sensitive data) */
  error?: string;
}

export interface Span {
  /** Span ID */
  spanId: string;
  /** Trace ID (same as executionRef) */
  traceId: string;
  /** Operation name */
  operationName: string;
  /** Start timestamp */
  startTime: number;
  /** End timestamp */
  endTime?: number;
  /** Duration in ms */
  durationMs?: number;
  /** Span status */
  status: 'ok' | 'error';
  /** Attributes (sanitized) */
  attributes: Record<string, string | number | boolean>;
}

// =============================================================================
// DEFAULT CONFIGURATION
// =============================================================================

const DEFAULT_CONFIG: TelemetryConfig = {
  enabled: process.env.TELEMETRY_ENABLED !== 'false',
  serviceName: 'data-redaction-agent',
  environment: process.env.NODE_ENV || 'development',
  collectorUrl: process.env.OTEL_COLLECTOR_URL,
};

// =============================================================================
// TELEMETRY EMITTER
// =============================================================================

/**
 * Telemetry emitter for LLM-Observatory
 */
export class TelemetryEmitter {
  private config: TelemetryConfig;
  private spans: Map<string, Span> = new Map();

  constructor(config: Partial<TelemetryConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Start a new span for tracing
   */
  startSpan(executionRef: string, operationName: string): string {
    const spanId = this.generateSpanId();
    const span: Span = {
      spanId,
      traceId: executionRef,
      operationName,
      startTime: Date.now(),
      status: 'ok',
      attributes: {
        'service.name': this.config.serviceName,
        'deployment.environment': this.config.environment,
      },
    };

    this.spans.set(spanId, span);
    return spanId;
  }

  /**
   * End a span
   */
  endSpan(spanId: string, status: 'ok' | 'error' = 'ok', attributes?: Record<string, string | number | boolean>): void {
    const span = this.spans.get(spanId);
    if (!span) return;

    span.endTime = Date.now();
    span.durationMs = span.endTime - span.startTime;
    span.status = status;

    if (attributes) {
      span.attributes = { ...span.attributes, ...attributes };
    }

    // Emit span if collector is configured
    if (this.config.enabled && this.config.collectorUrl) {
      this.emitSpan(span);
    }

    this.spans.delete(spanId);
  }

  /**
   * Emit redaction telemetry
   */
  async emitRedactionTelemetry(telemetry: RedactionTelemetry): Promise<void> {
    if (!this.config.enabled) return;

    // Create structured log entry (no sensitive data)
    const logEntry = {
      timestamp: telemetry.timestamp,
      level: 'INFO',
      message: `Data redaction completed: ${telemetry.redactionCount} redactions`,
      service: this.config.serviceName,
      environment: this.config.environment,
      trace_id: telemetry.executionRef,
      attributes: {
        'agent.id': telemetry.agentId,
        'agent.version': telemetry.agentVersion,
        'decision.type': telemetry.decisionType,
        'content.source': telemetry.contentSource,
        'content.original_length': telemetry.originalContentLength,
        'content.redacted_length': telemetry.redactedContentLength,
        'redaction.performed': telemetry.dataRedacted,
        'redaction.count': telemetry.redactionCount,
        'redaction.strategy': telemetry.redactionStrategy,
        'detection.categories': telemetry.detectedCategories.join(','),
        'detection.severity': telemetry.severity,
        'detection.confidence': telemetry.confidence,
        'detection.risk_score': telemetry.riskScore,
        'execution.duration_ms': telemetry.durationMs,
        'persistence.success': telemetry.persistenceSuccess,
      },
    };

    // Log locally
    this.logTelemetry(logEntry);

    // Send to collector if configured
    if (this.config.collectorUrl) {
      await this.sendToCollector(logEntry);
    }
  }

  /**
   * Emit error telemetry
   */
  async emitErrorTelemetry(
    executionRef: string,
    errorCode: string,
    errorMessage: string,
    details?: Record<string, unknown>
  ): Promise<void> {
    if (!this.config.enabled) return;

    const logEntry = {
      timestamp: new Date().toISOString(),
      level: 'ERROR',
      message: `Agent error: ${errorCode}`,
      service: this.config.serviceName,
      environment: this.config.environment,
      trace_id: executionRef,
      attributes: {
        'error.code': errorCode,
        'error.message': errorMessage,
        // Only include non-sensitive details
        ...(details ? this.sanitizeDetails(details) : {}),
      },
    };

    this.logTelemetry(logEntry);

    if (this.config.collectorUrl) {
      await this.sendToCollector(logEntry);
    }
  }

  /**
   * Emit metric
   */
  emitMetric(
    name: string,
    value: number,
    unit: string,
    attributes?: Record<string, string | number>
  ): void {
    if (!this.config.enabled) return;

    const metric = {
      name: `data_redaction.${name}`,
      value,
      unit,
      timestamp: Date.now(),
      attributes: {
        'service.name': this.config.serviceName,
        'deployment.environment': this.config.environment,
        ...attributes,
      },
    };

    // Log metric locally
    if (process.env.DEBUG_METRICS) {
      console.log('[METRIC]', JSON.stringify(metric));
    }
  }

  /**
   * Generate a random span ID
   */
  private generateSpanId(): string {
    const bytes = new Uint8Array(8);
    crypto.getRandomValues(bytes);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Sanitize details to remove sensitive data
   */
  private sanitizeDetails(details: Record<string, unknown>): Record<string, string | number | boolean> {
    const sanitized: Record<string, string | number | boolean> = {};
    const sensitiveKeys = ['content', 'secret', 'password', 'key', 'token', 'credential'];

    for (const [key, value] of Object.entries(details)) {
      // Skip sensitive keys
      if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
        continue;
      }

      // Only include primitive values
      if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  /**
   * Log telemetry locally
   */
  private logTelemetry(entry: Record<string, unknown>): void {
    // In production, this would use structured logging
    const level = entry.level as string;
    const message = entry.message as string;

    if (level === 'ERROR') {
      console.error(`[${this.config.serviceName}] ${message}`, JSON.stringify(entry.attributes));
    } else if (process.env.DEBUG_TELEMETRY) {
      console.log(`[${this.config.serviceName}] ${message}`, JSON.stringify(entry.attributes));
    }
  }

  /**
   * Emit span to collector
   */
  private async emitSpan(span: Span): Promise<void> {
    if (!this.config.collectorUrl) return;

    try {
      await fetch(`${this.config.collectorUrl}/v1/traces`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resourceSpans: [{
            resource: {
              attributes: [
                { key: 'service.name', value: { stringValue: this.config.serviceName } },
                { key: 'deployment.environment', value: { stringValue: this.config.environment } },
              ],
            },
            scopeSpans: [{
              scope: { name: this.config.serviceName },
              spans: [span],
            }],
          }],
        }),
      });
    } catch (error) {
      // Don't fail agent execution due to telemetry errors
      console.error('[Telemetry] Failed to emit span:', error);
    }
  }

  /**
   * Send to collector
   */
  private async sendToCollector(entry: Record<string, unknown>): Promise<void> {
    if (!this.config.collectorUrl) return;

    try {
      await fetch(`${this.config.collectorUrl}/v1/logs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resourceLogs: [{
            resource: {
              attributes: [
                { key: 'service.name', value: { stringValue: this.config.serviceName } },
              ],
            },
            scopeLogs: [{
              scope: { name: this.config.serviceName },
              logRecords: [entry],
            }],
          }],
        }),
      });
    } catch (error) {
      // Don't fail agent execution due to telemetry errors
      console.error('[Telemetry] Failed to send log:', error);
    }
  }
}

/**
 * Create a default telemetry emitter
 */
export function createTelemetryEmitter(config?: Partial<TelemetryConfig>): TelemetryEmitter {
  return new TelemetryEmitter(config);
}
