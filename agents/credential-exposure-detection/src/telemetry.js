/**
 * @module credential-exposure-detection/telemetry
 * @description Telemetry emission for LLM-Observatory compatibility
 *
 * All telemetry is sanitized and NEVER contains raw credentials.
 */
/**
 * Abstract telemetry emitter interface
 */
export class TelemetryEmitter {
}
/**
 * Console telemetry emitter (for development/debugging)
 */
export class ConsoleTelemetryEmitter extends TelemetryEmitter {
    emit(event) {
        console.log('[TELEMETRY]', JSON.stringify(event, null, 2));
    }
    async flush() {
        // No-op for console emitter
    }
}
/**
 * HTTP telemetry emitter (for LLM-Observatory)
 */
export class HttpTelemetryEmitter extends TelemetryEmitter {
    endpoint;
    apiKey;
    buffer = [];
    bufferSize;
    flushInterval;
    flushTimer;
    constructor(options) {
        super();
        this.endpoint = options.endpoint;
        this.apiKey = options.apiKey;
        this.bufferSize = options.bufferSize ?? 100;
        this.flushInterval = options.flushIntervalMs ?? 5000;
        // Start flush timer
        this.startFlushTimer();
    }
    emit(event) {
        this.buffer.push(event);
        if (this.buffer.length >= this.bufferSize) {
            this.flush().catch(console.error);
        }
    }
    async flush() {
        if (this.buffer.length === 0) {
            return;
        }
        const events = this.buffer.splice(0, this.buffer.length);
        try {
            await fetch(this.endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...(this.apiKey && {
                        Authorization: `Bearer ${this.apiKey}`,
                    }),
                },
                body: JSON.stringify({ events }),
            });
        }
        catch (error) {
            // Re-add events to buffer on failure
            this.buffer.unshift(...events);
            console.error('[TELEMETRY] Flush failed:', error);
        }
    }
    startFlushTimer() {
        this.flushTimer = setInterval(() => {
            this.flush().catch(console.error);
        }, this.flushInterval);
    }
    destroy() {
        if (this.flushTimer) {
            clearInterval(this.flushTimer);
        }
        this.flush().catch(console.error);
    }
}
/**
 * No-op telemetry emitter (for testing or disabled telemetry)
 */
export class NoOpTelemetryEmitter extends TelemetryEmitter {
    emit(_event) {
        // No-op
    }
    async flush() {
        // No-op
    }
}
/**
 * Buffered telemetry emitter (collects events for batch processing)
 */
export class BufferedTelemetryEmitter extends TelemetryEmitter {
    events = [];
    emit(event) {
        this.events.push(event);
    }
    async flush() {
        // No-op - events remain in buffer
    }
    getEvents() {
        return [...this.events];
    }
    clear() {
        this.events.length = 0;
    }
}
/**
 * Create telemetry emitter from environment
 */
export function createTelemetryEmitter() {
    const observatoryEndpoint = process.env.LLM_OBSERVATORY_ENDPOINT;
    const observatoryApiKey = process.env.LLM_OBSERVATORY_API_KEY;
    if (observatoryEndpoint) {
        return new HttpTelemetryEmitter({
            endpoint: observatoryEndpoint,
            apiKey: observatoryApiKey,
        });
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
        agent_id: 'credential-exposure-detection-agent',
        agent_version: '1.0.0',
        execution_ref: executionRef,
        timestamp: new Date().toISOString(),
        data: {
            content_length: contentLength,
            content_source: contentSource,
        },
    });
}
/**
 * Emit detection completed event
 */
export function emitDetectionCompleted(emitter, executionRef, durationMs, credentialsDetected, entityCount, detectedTypes, severity) {
    emitter.emit({
        event_type: 'detection_completed',
        agent_id: 'credential-exposure-detection-agent',
        agent_version: '1.0.0',
        execution_ref: executionRef,
        timestamp: new Date().toISOString(),
        data: {
            duration_ms: durationMs,
            credentials_detected: credentialsDetected,
            entity_count: entityCount,
            detected_types: detectedTypes,
            severity,
        },
    });
}
/**
 * Emit detection error event
 */
export function emitDetectionError(emitter, executionRef, errorCode, errorMessage) {
    emitter.emit({
        event_type: 'detection_error',
        agent_id: 'credential-exposure-detection-agent',
        agent_version: '1.0.0',
        execution_ref: executionRef,
        timestamp: new Date().toISOString(),
        data: {
            error_code: errorCode,
            error_message: errorMessage,
        },
    });
}
/**
 * Emit persistence success event
 */
export function emitPersistenceSuccess(emitter, executionRef, eventId) {
    emitter.emit({
        event_type: 'persistence_success',
        agent_id: 'credential-exposure-detection-agent',
        agent_version: '1.0.0',
        execution_ref: executionRef,
        timestamp: new Date().toISOString(),
        data: {
            event_id: eventId,
        },
    });
}
/**
 * Emit persistence error event
 */
export function emitPersistenceError(emitter, executionRef, errorMessage) {
    emitter.emit({
        event_type: 'persistence_error',
        agent_id: 'credential-exposure-detection-agent',
        agent_version: '1.0.0',
        execution_ref: executionRef,
        timestamp: new Date().toISOString(),
        data: {
            error_message: errorMessage,
        },
    });
}
//# sourceMappingURL=telemetry.js.map