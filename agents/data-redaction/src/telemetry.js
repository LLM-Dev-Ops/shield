/**
 * Telemetry emission for LLM-Observatory
 *
 * This module handles telemetry emission for observability.
 * All telemetry is sanitized - no raw content is ever emitted.
 */
// =============================================================================
// DEFAULT CONFIGURATION
// =============================================================================
const DEFAULT_CONFIG = {
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
    config;
    spans = new Map();
    constructor(config = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }
    /**
     * Start a new span for tracing
     */
    startSpan(executionRef, operationName) {
        const spanId = this.generateSpanId();
        const span = {
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
    endSpan(spanId, status = 'ok', attributes) {
        const span = this.spans.get(spanId);
        if (!span)
            return;
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
    async emitRedactionTelemetry(telemetry) {
        if (!this.config.enabled)
            return;
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
    async emitErrorTelemetry(executionRef, errorCode, errorMessage, details) {
        if (!this.config.enabled)
            return;
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
    emitMetric(name, value, unit, attributes) {
        if (!this.config.enabled)
            return;
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
    generateSpanId() {
        const bytes = new Uint8Array(8);
        crypto.getRandomValues(bytes);
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
    /**
     * Sanitize details to remove sensitive data
     */
    sanitizeDetails(details) {
        const sanitized = {};
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
    logTelemetry(entry) {
        // In production, this would use structured logging
        const level = entry.level;
        const message = entry.message;
        if (level === 'ERROR') {
            console.error(`[${this.config.serviceName}] ${message}`, JSON.stringify(entry.attributes));
        }
        else if (process.env.DEBUG_TELEMETRY) {
            console.log(`[${this.config.serviceName}] ${message}`, JSON.stringify(entry.attributes));
        }
    }
    /**
     * Emit span to collector
     */
    async emitSpan(span) {
        if (!this.config.collectorUrl)
            return;
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
        }
        catch (error) {
            // Don't fail agent execution due to telemetry errors
            console.error('[Telemetry] Failed to emit span:', error);
        }
    }
    /**
     * Send to collector
     */
    async sendToCollector(entry) {
        if (!this.config.collectorUrl)
            return;
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
        }
        catch (error) {
            // Don't fail agent execution due to telemetry errors
            console.error('[Telemetry] Failed to send log:', error);
        }
    }
}
/**
 * Create a default telemetry emitter
 */
export function createTelemetryEmitter(config) {
    return new TelemetryEmitter(config);
}
//# sourceMappingURL=telemetry.js.map