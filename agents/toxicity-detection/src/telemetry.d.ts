/**
 * Telemetry Emitter
 *
 * Emits telemetry events to LLM-Observatory for monitoring and analytics.
 * All telemetry MUST NOT contain raw content or toxic text.
 *
 * @module toxicity-detection-agent/telemetry
 */
import type { TelemetryEvent, Severity } from './types.js';
/**
 * Telemetry configuration
 */
interface TelemetryConfig {
    /** LLM-Observatory endpoint */
    endpoint: string;
    /** Whether telemetry is enabled */
    enabled: boolean;
    /** Batch size for sending events */
    batchSize: number;
    /** Flush interval in milliseconds */
    flushIntervalMs: number;
}
/**
 * Telemetry Emitter for LLM-Observatory
 *
 * Collects and sends telemetry events for monitoring agent performance.
 * Events are batched for efficiency.
 */
export declare class TelemetryEmitter {
    private config;
    private buffer;
    private flushTimer;
    constructor(config?: Partial<TelemetryConfig>);
    /**
     * Emit a telemetry event
     *
     * CRITICAL: Ensure no toxic content or raw text is included in the event.
     */
    emit(event: TelemetryEvent): void;
    /**
     * Create a telemetry event from detection results
     */
    static createEvent(params: {
        agentId: string;
        agentVersion: string;
        executionRef: string;
        timestamp: string;
        durationMs: number;
        contentLength: number;
        contentSource: string;
        toxicityDetected: boolean;
        entityCount: number;
        detectedCategories: string[];
        riskScore: number;
        severity: Severity;
        sessionId?: string;
        callerId?: string;
    }): TelemetryEvent;
    /**
     * Flush buffered events to LLM-Observatory
     */
    flush(): Promise<void>;
    /**
     * Validate event does not contain sensitive data
     */
    private validateEvent;
    /**
     * Start the flush timer
     */
    private startFlushTimer;
    /**
     * Stop the flush timer and flush remaining events
     */
    shutdown(): Promise<void>;
    /**
     * Get current buffer size
     */
    getBufferSize(): number;
    /**
     * Check if telemetry is enabled
     */
    isEnabled(): boolean;
}
/**
 * Get or create the global telemetry emitter
 */
export declare function getTelemetryEmitter(): TelemetryEmitter;
/**
 * Shutdown the global telemetry emitter
 */
export declare function shutdownTelemetry(): Promise<void>;
export {};
