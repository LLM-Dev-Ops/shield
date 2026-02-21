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
 * Telemetry event types
 */
export type TelemetryEventType = 'detection_started' | 'detection_completed' | 'detection_error' | 'pattern_matched' | 'entropy_detected';
/**
 * Base telemetry event structure
 */
export interface TelemetryEvent {
    /** Event type */
    event_type: TelemetryEventType;
    /** Agent ID */
    agent_id: string;
    /** Agent version */
    agent_version: string;
    /** Execution reference for correlation */
    execution_ref: string;
    /** UTC timestamp */
    timestamp: string;
    /** Event-specific payload (no sensitive data) */
    payload: Record<string, unknown>;
}
/**
 * Telemetry emitter interface
 */
export interface TelemetryEmitter {
    emit(event: TelemetryEvent): Promise<void>;
}
/**
 * Console-based telemetry emitter (for development)
 */
export declare class ConsoleTelemetryEmitter implements TelemetryEmitter {
    emit(event: TelemetryEvent): Promise<void>;
}
/**
 * HTTP-based telemetry emitter (for production)
 */
export declare class HttpTelemetryEmitter implements TelemetryEmitter {
    private readonly endpoint;
    private readonly apiKey?;
    constructor(endpoint: string, apiKey?: string);
    emit(event: TelemetryEvent): Promise<void>;
}
/**
 * No-op telemetry emitter (for testing)
 */
export declare class NoOpTelemetryEmitter implements TelemetryEmitter {
    emit(_event: TelemetryEvent): Promise<void>;
}
/**
 * Buffered telemetry emitter (batches events)
 */
export declare class BufferedTelemetryEmitter implements TelemetryEmitter {
    private buffer;
    private readonly maxSize;
    private readonly flushInterval;
    private readonly inner;
    private flushTimer?;
    constructor(inner: TelemetryEmitter, maxSize?: number, flushInterval?: number);
    private startFlushTimer;
    emit(event: TelemetryEvent): Promise<void>;
    flush(): Promise<void>;
    stop(): void;
}
/**
 * Create telemetry emitter from environment
 */
export declare function createTelemetryEmitter(): TelemetryEmitter;
/**
 * Emit detection started event
 */
export declare function emitDetectionStarted(emitter: TelemetryEmitter, executionRef: string, contentLength: number, contentSource: string): void;
/**
 * Emit detection completed event
 */
export declare function emitDetectionCompleted(emitter: TelemetryEmitter, executionRef: string, durationMs: number, threatsDetected: boolean, entityCount: number, categories: string[]): void;
/**
 * Emit detection error event
 */
export declare function emitDetectionError(emitter: TelemetryEmitter, executionRef: string, errorCode: string, errorMessage: string): void;
