/**
 * @module credential-exposure-detection/telemetry
 * @description Telemetry emission for LLM-Observatory compatibility
 *
 * All telemetry is sanitized and NEVER contains raw credentials.
 */
import type { CredentialType, Severity } from '@llm-shield/agentics-contracts';
/**
 * Telemetry event types
 */
export type TelemetryEventType = 'detection_started' | 'detection_completed' | 'detection_error' | 'persistence_success' | 'persistence_error';
/**
 * Telemetry event structure (compatible with LLM-Observatory)
 */
export interface TelemetryEvent {
    /** Event type */
    event_type: TelemetryEventType;
    /** Agent ID */
    agent_id: string;
    /** Agent version */
    agent_version: string;
    /** Execution reference UUID */
    execution_ref: string;
    /** Timestamp (UTC ISO 8601) */
    timestamp: string;
    /** Event-specific data (sanitized - no credentials) */
    data: Record<string, unknown>;
}
/**
 * Abstract telemetry emitter interface
 */
export declare abstract class TelemetryEmitter {
    abstract emit(event: TelemetryEvent): void;
    abstract flush(): Promise<void>;
}
/**
 * Console telemetry emitter (for development/debugging)
 */
export declare class ConsoleTelemetryEmitter extends TelemetryEmitter {
    emit(event: TelemetryEvent): void;
    flush(): Promise<void>;
}
/**
 * HTTP telemetry emitter (for LLM-Observatory)
 */
export declare class HttpTelemetryEmitter extends TelemetryEmitter {
    private readonly endpoint;
    private readonly apiKey?;
    private readonly buffer;
    private readonly bufferSize;
    private readonly flushInterval;
    private flushTimer?;
    constructor(options: {
        endpoint: string;
        apiKey?: string;
        bufferSize?: number;
        flushIntervalMs?: number;
    });
    emit(event: TelemetryEvent): void;
    flush(): Promise<void>;
    private startFlushTimer;
    destroy(): void;
}
/**
 * No-op telemetry emitter (for testing or disabled telemetry)
 */
export declare class NoOpTelemetryEmitter extends TelemetryEmitter {
    emit(_event: TelemetryEvent): void;
    flush(): Promise<void>;
}
/**
 * Buffered telemetry emitter (collects events for batch processing)
 */
export declare class BufferedTelemetryEmitter extends TelemetryEmitter {
    private readonly events;
    emit(event: TelemetryEvent): void;
    flush(): Promise<void>;
    getEvents(): TelemetryEvent[];
    clear(): void;
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
export declare function emitDetectionCompleted(emitter: TelemetryEmitter, executionRef: string, durationMs: number, credentialsDetected: boolean, entityCount: number, detectedTypes: CredentialType[], severity: Severity): void;
/**
 * Emit detection error event
 */
export declare function emitDetectionError(emitter: TelemetryEmitter, executionRef: string, errorCode: string, errorMessage: string): void;
/**
 * Emit persistence success event
 */
export declare function emitPersistenceSuccess(emitter: TelemetryEmitter, executionRef: string, eventId: string): void;
/**
 * Emit persistence error event
 */
export declare function emitPersistenceError(emitter: TelemetryEmitter, executionRef: string, errorMessage: string): void;
