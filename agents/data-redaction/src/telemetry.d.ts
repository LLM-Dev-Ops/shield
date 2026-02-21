/**
 * Telemetry emission for LLM-Observatory
 *
 * This module handles telemetry emission for observability.
 * All telemetry is sanitized - no raw content is ever emitted.
 */
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
/**
 * Telemetry emitter for LLM-Observatory
 */
export declare class TelemetryEmitter {
    private config;
    private spans;
    constructor(config?: Partial<TelemetryConfig>);
    /**
     * Start a new span for tracing
     */
    startSpan(executionRef: string, operationName: string): string;
    /**
     * End a span
     */
    endSpan(spanId: string, status?: 'ok' | 'error', attributes?: Record<string, string | number | boolean>): void;
    /**
     * Emit redaction telemetry
     */
    emitRedactionTelemetry(telemetry: RedactionTelemetry): Promise<void>;
    /**
     * Emit error telemetry
     */
    emitErrorTelemetry(executionRef: string, errorCode: string, errorMessage: string, details?: Record<string, unknown>): Promise<void>;
    /**
     * Emit metric
     */
    emitMetric(name: string, value: number, unit: string, attributes?: Record<string, string | number>): void;
    /**
     * Generate a random span ID
     */
    private generateSpanId;
    /**
     * Sanitize details to remove sensitive data
     */
    private sanitizeDetails;
    /**
     * Log telemetry locally
     */
    private logTelemetry;
    /**
     * Emit span to collector
     */
    private emitSpan;
    /**
     * Send to collector
     */
    private sendToCollector;
}
/**
 * Create a default telemetry emitter
 */
export declare function createTelemetryEmitter(config?: Partial<TelemetryConfig>): TelemetryEmitter;
