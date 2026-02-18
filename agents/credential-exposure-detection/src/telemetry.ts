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
export type TelemetryEventType =
  | 'detection_started'
  | 'detection_completed'
  | 'detection_error'
  | 'persistence_success'
  | 'persistence_error';

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
export abstract class TelemetryEmitter {
  abstract emit(event: TelemetryEvent): void;
  abstract flush(): Promise<void>;
}

/**
 * Console telemetry emitter (for development/debugging)
 */
export class ConsoleTelemetryEmitter extends TelemetryEmitter {
  emit(event: TelemetryEvent): void {
    console.log('[TELEMETRY]', JSON.stringify(event, null, 2));
  }

  async flush(): Promise<void> {
    // No-op for console emitter
  }
}

/**
 * HTTP telemetry emitter (for LLM-Observatory)
 */
export class HttpTelemetryEmitter extends TelemetryEmitter {
  private readonly endpoint: string;
  private readonly apiKey?: string;
  private readonly buffer: TelemetryEvent[] = [];
  private readonly bufferSize: number;
  private readonly flushInterval: number;
  private flushTimer?: ReturnType<typeof setTimeout>;

  constructor(options: {
    endpoint: string;
    apiKey?: string;
    bufferSize?: number;
    flushIntervalMs?: number;
  }) {
    super();
    this.endpoint = options.endpoint;
    this.apiKey = options.apiKey;
    this.bufferSize = options.bufferSize ?? 100;
    this.flushInterval = options.flushIntervalMs ?? 5000;

    // Start flush timer
    this.startFlushTimer();
  }

  emit(event: TelemetryEvent): void {
    this.buffer.push(event);

    if (this.buffer.length >= this.bufferSize) {
      this.flush().catch(console.error);
    }
  }

  async flush(): Promise<void> {
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
    } catch (error) {
      // Re-add events to buffer on failure
      this.buffer.unshift(...events);
      console.error('[TELEMETRY] Flush failed:', error);
    }
  }

  private startFlushTimer(): void {
    this.flushTimer = setInterval(() => {
      this.flush().catch(console.error);
    }, this.flushInterval);
  }

  destroy(): void {
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
  emit(_event: TelemetryEvent): void {
    // No-op
  }

  async flush(): Promise<void> {
    // No-op
  }
}

/**
 * Buffered telemetry emitter (collects events for batch processing)
 */
export class BufferedTelemetryEmitter extends TelemetryEmitter {
  private readonly events: TelemetryEvent[] = [];

  emit(event: TelemetryEvent): void {
    this.events.push(event);
  }

  async flush(): Promise<void> {
    // No-op - events remain in buffer
  }

  getEvents(): TelemetryEvent[] {
    return [...this.events];
  }

  clear(): void {
    this.events.length = 0;
  }
}

/**
 * Create telemetry emitter from environment
 */
export function createTelemetryEmitter(): TelemetryEmitter {
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
export function emitDetectionStarted(
  emitter: TelemetryEmitter,
  executionRef: string,
  contentLength: number,
  contentSource: string
): void {
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
export function emitDetectionCompleted(
  emitter: TelemetryEmitter,
  executionRef: string,
  durationMs: number,
  credentialsDetected: boolean,
  entityCount: number,
  detectedTypes: CredentialType[],
  severity: Severity
): void {
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
export function emitDetectionError(
  emitter: TelemetryEmitter,
  executionRef: string,
  errorCode: string,
  errorMessage: string
): void {
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
export function emitPersistenceSuccess(
  emitter: TelemetryEmitter,
  executionRef: string,
  eventId: string
): void {
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
export function emitPersistenceError(
  emitter: TelemetryEmitter,
  executionRef: string,
  errorMessage: string
): void {
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
