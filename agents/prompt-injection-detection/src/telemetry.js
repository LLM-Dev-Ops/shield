/**
 * @module telemetry
 * @description Telemetry emission for LLM-Observatory integration
 *
 * All agent invocations emit telemetry for observability.
 * Telemetry NEVER contains raw content, PII, or secrets.
 */
/**
 * Default telemetry configuration
 */
const DEFAULT_CONFIG = {
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
    config;
    agent;
    buffer = [];
    flushTimer = null;
    constructor(agent, config = {}) {
        this.agent = agent;
        this.config = { ...DEFAULT_CONFIG, ...config };
        if (this.config.enabled && this.config.flushInterval) {
            this.startFlushTimer();
        }
    }
    /**
     * Emit invocation start event
     */
    emitInvocationStart(executionRef, contentLength, contentSource) {
        this.emit({
            type: 'agent.invocation.start',
            agent: this.agent,
            execution_ref: executionRef,
            timestamp: new Date().toISOString(),
            data: {
                content_length: contentLength,
                content_source: contentSource,
            },
        });
    }
    /**
     * Emit invocation complete event
     */
    emitInvocationComplete(executionRef, durationMs, threatsDetected, riskScore, patternMatchCount) {
        this.emit({
            type: 'agent.invocation.complete',
            agent: this.agent,
            execution_ref: executionRef,
            timestamp: new Date().toISOString(),
            data: {
                duration_ms: durationMs,
                threats_detected: threatsDetected,
                risk_score: riskScore,
                pattern_match_count: patternMatchCount,
            },
        });
    }
    /**
     * Emit invocation error event
     */
    emitInvocationError(executionRef, errorCode, errorMessage) {
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
     * Emit pattern match event (for detailed metrics)
     */
    emitPatternMatch(executionRef, category, patternId, confidence) {
        if (!this.config.detailedMetrics)
            return;
        this.emit({
            type: 'agent.detection.pattern_match',
            agent: this.agent,
            execution_ref: executionRef,
            timestamp: new Date().toISOString(),
            data: {
                category,
                pattern_id: patternId,
                confidence,
            },
        });
    }
    /**
     * Emit persistence success event
     */
    emitPersistenceSuccess(executionRef, eventId) {
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
    emitPersistenceFailure(executionRef, error) {
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
    emitFromDecisionEvent(event) {
        this.emitInvocationComplete(event.execution_ref, event.duration_ms, event.outputs.threats_detected, event.outputs.risk_score, event.outputs.pattern_match_count);
    }
    /**
     * Force flush all buffered events
     */
    async flush() {
        if (!this.config.enabled || this.buffer.length === 0)
            return;
        const events = [...this.buffer];
        this.buffer.length = 0;
        try {
            await this.sendEvents(events);
        }
        catch (error) {
            // Telemetry failures are non-fatal
            console.warn('[Telemetry] Failed to flush events:', error);
        }
    }
    /**
     * Shutdown the emitter
     */
    async shutdown() {
        if (this.flushTimer) {
            clearInterval(this.flushTimer);
            this.flushTimer = null;
        }
        await this.flush();
    }
    emit(event) {
        if (!this.config.enabled)
            return;
        this.buffer.push(event);
        if (this.buffer.length >= this.config.batchSize) {
            this.flush().catch(() => { });
        }
    }
    startFlushTimer() {
        this.flushTimer = setInterval(() => {
            this.flush().catch(() => { });
        }, this.config.flushInterval);
    }
    async sendEvents(events) {
        if (!this.config.observatoryUrl)
            return;
        const response = await fetch(`${this.config.observatoryUrl}/api/v1/telemetry/batch`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Agent-ID': this.agent.agent_id,
            },
            body: JSON.stringify({ events }),
        });
        if (!response.ok) {
            throw new Error(`Observatory returned ${response.status}`);
        }
    }
}
/**
 * Create a no-op telemetry emitter for testing
 */
export function createNoOpTelemetryEmitter(agent) {
    return new TelemetryEmitter(agent, { enabled: false });
}
//# sourceMappingURL=telemetry.js.map