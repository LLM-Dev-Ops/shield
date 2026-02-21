/**
 * @module telemetry
 * @description Telemetry emission for LLM-Observatory integration
 *
 * This module provides structured telemetry emission without sensitive data.
 * All telemetry is compatible with LLM-Observatory specifications.
 */
/**
 * Telemetry event types
 */
export type TelemetryEventType = 'detection_started' | 'detection_completed' | 'detection_error' | 'behavioral_analysis_completed' | 'pattern_match_found';
/**
 * Base telemetry event structure
 */
export interface TelemetryEvent {
    /** Event type */
    type: TelemetryEventType;
    /** Unique execution reference for correlation */
    execution_ref: string;
    /** UTC timestamp */
    timestamp: string;
    /** Agent ID */
    agent_id: string;
    /** Agent version */
    agent_version: string;
    /** Additional event-specific data (no sensitive content) */
    data?: Record<string, unknown>;
}
/**
 * Telemetry emitter interface
 */
export interface TelemetryEmitter {
    /** Emit a telemetry event */
    emit(event: TelemetryEvent): void;
    /** Flush pending events */
    flush(): Promise<void>;
    /** Shutdown the emitter */
    shutdown(): Promise<void>;
}
/**
 * Telemetry emitter configuration
 */
export interface TelemetryConfig {
    /** Enable telemetry */
    enabled: boolean;
    /** Telemetry endpoint (for HTTP emitter) */
    endpoint?: string;
    /** API key for authentication */
    apiKey?: string;
    /** Use console emitter (for development) */
    useConsole?: boolean;
}
/**
 * Create telemetry emitter based on configuration
 */
export declare function createTelemetryEmitter(config?: TelemetryConfig): TelemetryEmitter;
/**
 * Create telemetry emitter from environment variables
 */
export declare function createTelemetryEmitterFromEnv(): TelemetryEmitter;
/**
 * Emit detection started event
 */
export declare function emitDetectionStarted(emitter: TelemetryEmitter, executionRef: string, contentLength: number, contentSource: string): void;
/**
 * Emit detection completed event
 */
export declare function emitDetectionCompleted(emitter: TelemetryEmitter, executionRef: string, durationMs: number, abuseDetected: boolean, entityCount: number, categories: string[], riskScore: number): void;
/**
 * Emit detection error event
 */
export declare function emitDetectionError(emitter: TelemetryEmitter, executionRef: string, errorCode: string, errorMessage: string): void;
/**
 * Emit behavioral analysis completed event
 */
export declare function emitBehavioralAnalysisCompleted(emitter: TelemetryEmitter, executionRef: string, appearsAutomated: boolean, abnormalRate: boolean, redFlagCount: number): void;
/**
 * Emit pattern match found event
 */
export declare function emitPatternMatchFound(emitter: TelemetryEmitter, executionRef: string, patternId: string, category: string, severity: string, confidence: number): void;
/**
 * Get or create the global telemetry emitter
 */
export declare function getTelemetryEmitter(): TelemetryEmitter;
/**
 * Set the global telemetry emitter
 */
export declare function setTelemetryEmitter(emitter: TelemetryEmitter): void;
