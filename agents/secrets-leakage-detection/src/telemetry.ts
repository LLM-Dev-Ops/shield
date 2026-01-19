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
export type TelemetryEventType =
  | 'detection_started'
  | 'detection_completed'
  | 'detection_error'
  | 'pattern_matched'
  | 'entropy_detected';

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
export class ConsoleTelemetryEmitter implements TelemetryEmitter {
  async emit(event: TelemetryEvent): Promise<void> {
    console.log(JSON.stringify(event));
  }
}

/**
 * HTTP-based telemetry emitter (for production)
 */
export class HttpTelemetryEmitter implements TelemetryEmitter {
  private readonly endpoint: string;
  private readonly apiKey?: string;

  constructor(endpoint: string, apiKey?: string) {
    this.endpoint = endpoint;
    this.apiKey = apiKey;
  }

  async emit(event: TelemetryEvent): Promise<void> {
    try {
      await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(this.apiKey && { Authorization: `Bearer ${this.apiKey}` }),
        },
        body: JSON.stringify(event),
      });
    } catch {
      // Telemetry failures are non-fatal
    }
  }
}

/**
 * No-op telemetry emitter (for testing)
 */
export class NoOpTelemetryEmitter implements TelemetryEmitter {
  async emit(_event: TelemetryEvent): Promise<void> {
    // No-op
  }
}

/**
 * Buffered telemetry emitter (batches events)
 */
export class BufferedTelemetryEmitter implements TelemetryEmitter {
  private buffer: TelemetryEvent[] = [];
  private readonly maxSize: number;
  private readonly flushInterval: number;
  private readonly inner: TelemetryEmitter;
  private flushTimer?: ReturnType<typeof setTimeout>;

  constructor(
    inner: TelemetryEmitter,
    maxSize: number = 100,
    flushInterval: number = 5000
  ) {
    this.inner = inner;
    this.maxSize = maxSize;
    this.flushInterval = flushInterval;
    this.startFlushTimer();
  }

  private startFlushTimer(): void {
    this.flushTimer = setTimeout(() => {
      this.flush();
      this.startFlushTimer();
    }, this.flushInterval);
  }

  async emit(event: TelemetryEvent): Promise<void> {
    this.buffer.push(event);
    if (this.buffer.length >= this.maxSize) {
      await this.flush();
    }
  }

  async flush(): Promise<void> {
    const events = this.buffer;
    this.buffer = [];
    for (const event of events) {
      await this.inner.emit(event);
    }
  }

  stop(): void {
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
export function createTelemetryEmitter(): TelemetryEmitter {
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
export function emitDetectionStarted(
  emitter: TelemetryEmitter,
  executionRef: string,
  contentLength: number,
  contentSource: string
): void {
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
export function emitDetectionCompleted(
  emitter: TelemetryEmitter,
  executionRef: string,
  durationMs: number,
  threatsDetected: boolean,
  entityCount: number,
  categories: string[]
): void {
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
export function emitDetectionError(
  emitter: TelemetryEmitter,
  executionRef: string,
  errorCode: string,
  errorMessage: string
): void {
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
