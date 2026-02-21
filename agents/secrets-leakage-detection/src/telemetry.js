/**
 * @module secrets-leakage-detection/telemetry
 * @description Telemetry emission for LLM-Observatory compatibility
 *
 * CRITICAL: Telemetry MUST NOT contain:
 * - Raw secrets or credentials
 * - PII data
 * - Matched text content
 * - API keys or tokens
 */
/**
 * Console-based telemetry emitter (for development)
 */
export class ConsoleTelemetryEmitter {
    async emit(event) {
        console.log(JSON.stringify(event));
    }
}
/**
 * HTTP-based telemetry emitter (for production)
 */
export class HttpTelemetryEmitter {
    endpoint;
    apiKey;
    constructor(endpoint, apiKey) {
        this.endpoint = endpoint;
        this.apiKey = apiKey;
    }
    async emit(event) {
        try {
            await fetch(this.endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...(this.apiKey && { Authorization: `Bearer ${this.apiKey}` }),
                },
                body: JSON.stringify(event),
            });
        }
        catch {
            // Telemetry failures are non-fatal
        }
    }
}
/**
 * No-op telemetry emitter (for testing)
 */
export class NoOpTelemetryEmitter {
    async emit(_event) {
        // No-op
    }
}
/**
 * Buffered telemetry emitter (batches events)
 */
export class BufferedTelemetryEmitter {
    buffer = [];
    maxSize;
    flushInterval;
    inner;
    flushTimer;
    constructor(inner, maxSize = 100, flushInterval = 5000) {
        this.inner = inner;
        this.maxSize = maxSize;
        this.flushInterval = flushInterval;
        this.startFlushTimer();
    }
    startFlushTimer() {
        this.flushTimer = setTimeout(() => {
            this.flush();
            this.startFlushTimer();
        }, this.flushInterval);
    }
    async emit(event) {
        this.buffer.push(event);
        if (this.buffer.length >= this.maxSize) {
            await this.flush();
        }
    }
    async flush() {
        const events = this.buffer;
        this.buffer = [];
        for (const event of events) {
            await this.inner.emit(event);
        }
    }
    stop() {
        if (this.flushTimer) {
            clearTimeout(this.flushTimer);
        }
    }
}
/**
 * Agent identity for telemetry
 */
const AGENT_ID = 'secrets-leakage-detection-agent';
const AGENT_VERSION = '1.0.0';
/**
 * Create telemetry emitter from environment
 */
export function createTelemetryEmitter() {
    const endpoint = process.env.LLM_OBSERVATORY_ENDPOINT;
    const apiKey = process.env.LLM_OBSERVATORY_API_KEY;
    if (endpoint) {
        return new HttpTelemetryEmitter(endpoint, apiKey);
    }
    if (process.env.NODE_ENV === 'development') {
        return new ConsoleTelemetryEmitter();
    }
    return new NoOpTelemetryEmitter();
}
/**
 * Emit detection started event
 */
export function emitDetectionStarted(emitter, executionRef, contentLength, contentSource) {
    emitter.emit({
        event_type: 'detection_started',
        agent_id: AGENT_ID,
        agent_version: AGENT_VERSION,
        execution_ref: executionRef,
        timestamp: new Date().toISOString(),
        payload: {
            content_length: contentLength,
            content_source: contentSource,
        },
    });
}
/**
 * Emit detection completed event
 */
export function emitDetectionCompleted(emitter, executionRef, durationMs, threatsDetected, entityCount, categories) {
    emitter.emit({
        event_type: 'detection_completed',
        agent_id: AGENT_ID,
        agent_version: AGENT_VERSION,
        execution_ref: executionRef,
        timestamp: new Date().toISOString(),
        payload: {
            duration_ms: durationMs,
            threats_detected: threatsDetected,
            entity_count: entityCount,
            category_count: categories.length,
            categories: categories,
        },
    });
}
/**
 * Emit detection error event
 */
export function emitDetectionError(emitter, executionRef, errorCode, errorMessage) {
    emitter.emit({
        event_type: 'detection_error',
        agent_id: AGENT_ID,
        agent_version: AGENT_VERSION,
        execution_ref: executionRef,
        timestamp: new Date().toISOString(),
        payload: {
            error_code: errorCode,
            error_message: errorMessage,
        },
    });
}
//# sourceMappingURL=telemetry.js.map