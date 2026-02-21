/**
 * @module telemetry
 * @description Telemetry emission for LLM-Observatory integration
 *
 * This module provides structured telemetry emission without sensitive data.
 * All telemetry is compatible with LLM-Observatory specifications.
 */
/**
 * Console-based telemetry emitter for development
 */
class ConsoleTelemetryEmitter {
    enabled;
    constructor(enabled = true) {
        this.enabled = enabled;
    }
    emit(event) {
        if (this.enabled) {
            console.log(JSON.stringify({
                ...event,
                _source: 'model-abuse-detection-agent',
            }));
        }
    }
    async flush() {
        // Console emitter doesn't buffer
    }
    async shutdown() {
        // Nothing to clean up
    }
}
/**
 * No-op telemetry emitter for testing
 */
class NoOpTelemetryEmitter {
    emit(_event) {
        // Intentionally empty
    }
    async flush() {
        // Nothing to flush
    }
    async shutdown() {
        // Nothing to shutdown
    }
}
/**
 * HTTP-based telemetry emitter for production
 */
class HttpTelemetryEmitter {
    endpoint;
    apiKey;
    buffer = [];
    flushInterval = null;
    maxBufferSize = 100;
    flushIntervalMs = 5000;
    constructor(endpoint, apiKey) {
        this.endpoint = endpoint;
        this.apiKey = apiKey;
        // Start periodic flush
        this.flushInterval = setInterval(() => {
            this.flush().catch(() => {
                // Silently ignore flush errors
            });
        }, this.flushIntervalMs);
    }
    emit(event) {
        this.buffer.push(event);
        // Flush if buffer is full
        if (this.buffer.length >= this.maxBufferSize) {
            this.flush().catch(() => {
                // Silently ignore flush errors
            });
        }
    }
    async flush() {
        if (this.buffer.length === 0) {
            return;
        }
        const events = [...this.buffer];
        this.buffer = [];
        try {
            await fetch(this.endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...(this.apiKey && { Authorization: `Bearer ${this.apiKey}` }),
                },
                body: JSON.stringify({ events }),
            });
        }
        catch {
            // Re-add events to buffer on failure (with limit)
            if (this.buffer.length + events.length <= this.maxBufferSize * 2) {
                this.buffer.unshift(...events);
            }
        }
    }
    async shutdown() {
        if (this.flushInterval) {
            clearInterval(this.flushInterval);
            this.flushInterval = null;
        }
        await this.flush();
    }
}
/**
 * Create telemetry emitter based on configuration
 */
export function createTelemetryEmitter(config) {
    if (!config || !config.enabled) {
        return new NoOpTelemetryEmitter();
    }
    if (config.useConsole) {
        return new ConsoleTelemetryEmitter(true);
    }
    if (config.endpoint) {
        return new HttpTelemetryEmitter(config.endpoint, config.apiKey);
    }
    return new ConsoleTelemetryEmitter(true);
}
/**
 * Create telemetry emitter from environment variables
 */
export function createTelemetryEmitterFromEnv() {
    const enabled = process.env.TELEMETRY_ENABLED !== 'false';
    const endpoint = process.env.TELEMETRY_ENDPOINT;
    const apiKey = process.env.TELEMETRY_API_KEY;
    const useConsole = process.env.TELEMETRY_USE_CONSOLE === 'true' ||
        process.env.NODE_ENV === 'development';
    return createTelemetryEmitter({
        enabled,
        endpoint,
        apiKey,
        useConsole,
    });
}
// Agent identity constants
const AGENT_ID = 'model-abuse-detection-agent';
const AGENT_VERSION = '1.0.0';
/**
 * Emit detection started event
 */
export function emitDetectionStarted(emitter, executionRef, contentLength, contentSource) {
    emitter.emit({
        type: 'detection_started',
        execution_ref: executionRef,
        timestamp: new Date().toISOString(),
        agent_id: AGENT_ID,
        agent_version: AGENT_VERSION,
        data: {
            content_length: contentLength,
            content_source: contentSource,
        },
    });
}
/**
 * Emit detection completed event
 */
export function emitDetectionCompleted(emitter, executionRef, durationMs, abuseDetected, entityCount, categories, riskScore) {
    emitter.emit({
        type: 'detection_completed',
        execution_ref: executionRef,
        timestamp: new Date().toISOString(),
        agent_id: AGENT_ID,
        agent_version: AGENT_VERSION,
        data: {
            duration_ms: durationMs,
            abuse_detected: abuseDetected,
            entity_count: entityCount,
            detected_categories: categories,
            risk_score: riskScore,
        },
    });
}
/**
 * Emit detection error event
 */
export function emitDetectionError(emitter, executionRef, errorCode, errorMessage) {
    emitter.emit({
        type: 'detection_error',
        execution_ref: executionRef,
        timestamp: new Date().toISOString(),
        agent_id: AGENT_ID,
        agent_version: AGENT_VERSION,
        data: {
            error_code: errorCode,
            error_message: errorMessage,
        },
    });
}
/**
 * Emit behavioral analysis completed event
 */
export function emitBehavioralAnalysisCompleted(emitter, executionRef, appearsAutomated, abnormalRate, redFlagCount) {
    emitter.emit({
        type: 'behavioral_analysis_completed',
        execution_ref: executionRef,
        timestamp: new Date().toISOString(),
        agent_id: AGENT_ID,
        agent_version: AGENT_VERSION,
        data: {
            appears_automated: appearsAutomated,
            abnormal_rate: abnormalRate,
            red_flag_count: redFlagCount,
        },
    });
}
/**
 * Emit pattern match found event
 */
export function emitPatternMatchFound(emitter, executionRef, patternId, category, severity, confidence) {
    emitter.emit({
        type: 'pattern_match_found',
        execution_ref: executionRef,
        timestamp: new Date().toISOString(),
        agent_id: AGENT_ID,
        agent_version: AGENT_VERSION,
        data: {
            pattern_id: patternId,
            category: category,
            severity: severity,
            confidence: confidence,
        },
    });
}
// Singleton instance
let globalEmitter = null;
/**
 * Get or create the global telemetry emitter
 */
export function getTelemetryEmitter() {
    if (!globalEmitter) {
        globalEmitter = createTelemetryEmitterFromEnv();
    }
    return globalEmitter;
}
/**
 * Set the global telemetry emitter
 */
export function setTelemetryEmitter(emitter) {
    globalEmitter = emitter;
}
//# sourceMappingURL=telemetry.js.map