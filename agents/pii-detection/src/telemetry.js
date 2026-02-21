/**
 * Telemetry Emitter
 *
 * Emits telemetry events to LLM-Observatory for monitoring and analytics.
 * All telemetry MUST NOT contain raw content or PII values.
 *
 * @module pii-detection-agent/telemetry
 */
/**
 * Default telemetry configuration
 */
const DEFAULT_CONFIG = {
    endpoint: process.env.LLM_OBSERVATORY_ENDPOINT || 'http://localhost:9090',
    enabled: process.env.TELEMETRY_ENABLED !== 'false',
    batchSize: 10,
    flushIntervalMs: 5000,
};
/**
 * Telemetry Emitter for LLM-Observatory
 *
 * Collects and sends telemetry events for monitoring agent performance.
 * Events are batched for efficiency.
 */
export class TelemetryEmitter {
    config;
    buffer = [];
    flushTimer = null;
    constructor(config) {
        this.config = { ...DEFAULT_CONFIG, ...config };
        if (this.config.enabled && this.config.flushIntervalMs > 0) {
            this.startFlushTimer();
        }
    }
    /**
     * Emit a telemetry event
     *
     * CRITICAL: Ensure no PII or raw content is included in the event.
     */
    emit(event) {
        if (!this.config.enabled) {
            return;
        }
        // Validate event does not contain sensitive data
        this.validateEvent(event);
        this.buffer.push(event);
        // Flush if buffer is full
        if (this.buffer.length >= this.config.batchSize) {
            this.flush().catch(err => {
                console.error('Failed to flush telemetry:', err);
            });
        }
    }
    /**
     * Create a telemetry event from detection results
     */
    static createEvent(params) {
        return {
            event_type: 'pii_detection',
            agent_id: params.agentId,
            agent_version: params.agentVersion,
            execution_ref: params.executionRef,
            timestamp: params.timestamp,
            duration_ms: params.durationMs,
            content_length: params.contentLength,
            content_source: params.contentSource,
            pii_detected: params.piiDetected,
            entity_count: params.entityCount,
            detected_types: params.detectedTypes,
            risk_score: params.riskScore,
            severity: params.severity,
            session_id: params.sessionId,
            caller_id: params.callerId,
        };
    }
    /**
     * Flush buffered events to LLM-Observatory
     */
    async flush() {
        if (!this.config.enabled || this.buffer.length === 0) {
            return;
        }
        const events = [...this.buffer];
        this.buffer = [];
        try {
            const url = `${this.config.endpoint}/api/v1/events`;
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ events }),
            });
            if (!response.ok) {
                // Re-buffer events on failure (with limit)
                if (this.buffer.length < this.config.batchSize * 2) {
                    this.buffer.unshift(...events);
                }
                console.warn(`Telemetry flush failed: ${response.status}`);
            }
        }
        catch (error) {
            // Re-buffer events on error (with limit)
            if (this.buffer.length < this.config.batchSize * 2) {
                this.buffer.unshift(...events);
            }
            console.warn('Telemetry flush error:', error);
        }
    }
    /**
     * Validate event does not contain sensitive data
     */
    validateEvent(event) {
        // Check for suspicious field values that might indicate PII
        const suspiciousPatterns = [
            /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Email
            /\b\d{3}-\d{2}-\d{4}\b/, // SSN
            /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, // Credit card
        ];
        const eventStr = JSON.stringify(event);
        for (const pattern of suspiciousPatterns) {
            if (pattern.test(eventStr)) {
                throw new Error('Telemetry event contains potential PII - blocked');
            }
        }
    }
    /**
     * Start the flush timer
     */
    startFlushTimer() {
        this.flushTimer = setInterval(() => {
            this.flush().catch(err => {
                console.error('Scheduled telemetry flush failed:', err);
            });
        }, this.config.flushIntervalMs);
        // Unref to allow process to exit
        if (this.flushTimer.unref) {
            this.flushTimer.unref();
        }
    }
    /**
     * Stop the flush timer and flush remaining events
     */
    async shutdown() {
        if (this.flushTimer) {
            clearInterval(this.flushTimer);
            this.flushTimer = null;
        }
        await this.flush();
    }
    /**
     * Get current buffer size
     */
    getBufferSize() {
        return this.buffer.length;
    }
    /**
     * Check if telemetry is enabled
     */
    isEnabled() {
        return this.config.enabled;
    }
}
/**
 * Global telemetry emitter instance
 */
let globalEmitter = null;
/**
 * Get or create the global telemetry emitter
 */
export function getTelemetryEmitter() {
    if (!globalEmitter) {
        globalEmitter = new TelemetryEmitter();
    }
    return globalEmitter;
}
/**
 * Shutdown the global telemetry emitter
 */
export async function shutdownTelemetry() {
    if (globalEmitter) {
        await globalEmitter.shutdown();
        globalEmitter = null;
    }
}
//# sourceMappingURL=telemetry.js.map