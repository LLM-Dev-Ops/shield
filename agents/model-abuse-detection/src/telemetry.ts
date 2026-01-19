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
export type TelemetryEventType =
  | 'detection_started'
  | 'detection_completed'
  | 'detection_error'
  | 'behavioral_analysis_completed'
  | 'pattern_match_found';

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
 * Console-based telemetry emitter for development
 */
class ConsoleTelemetryEmitter implements TelemetryEmitter {
  private enabled: boolean;

  constructor(enabled: boolean = true) {
    this.enabled = enabled;
  }

  emit(event: TelemetryEvent): void {
    if (this.enabled) {
      console.log(
        JSON.stringify({
          ...event,
          _source: 'model-abuse-detection-agent',
        })
      );
    }
  }

  async flush(): Promise<void> {
    // Console emitter doesn't buffer
  }

  async shutdown(): Promise<void> {
    // Nothing to clean up
  }
}

/**
 * No-op telemetry emitter for testing
 */
class NoOpTelemetryEmitter implements TelemetryEmitter {
  emit(_event: TelemetryEvent): void {
    // Intentionally empty
  }

  async flush(): Promise<void> {
    // Nothing to flush
  }

  async shutdown(): Promise<void> {
    // Nothing to shutdown
  }
}

/**
 * HTTP-based telemetry emitter for production
 */
class HttpTelemetryEmitter implements TelemetryEmitter {
  private endpoint: string;
  private apiKey?: string;
  private buffer: TelemetryEvent[] = [];
  private flushInterval: NodeJS.Timeout | null = null;
  private maxBufferSize: number = 100;
  private flushIntervalMs: number = 5000;

  constructor(endpoint: string, apiKey?: string) {
    this.endpoint = endpoint;
    this.apiKey = apiKey;

    // Start periodic flush
    this.flushInterval = setInterval(() => {
      this.flush().catch(() => {
        // Silently ignore flush errors
      });
    }, this.flushIntervalMs);
  }

  emit(event: TelemetryEvent): void {
    this.buffer.push(event);

    // Flush if buffer is full
    if (this.buffer.length >= this.maxBufferSize) {
      this.flush().catch(() => {
        // Silently ignore flush errors
      });
    }
  }

  async flush(): Promise<void> {
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
    } catch {
      // Re-add events to buffer on failure (with limit)
      if (this.buffer.length + events.length <= this.maxBufferSize * 2) {
        this.buffer.unshift(...events);
      }
    }
  }

  async shutdown(): Promise<void> {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
      this.flushInterval = null;
    }
    await this.flush();
  }
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
export function createTelemetryEmitter(config?: TelemetryConfig): TelemetryEmitter {
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
export function createTelemetryEmitterFromEnv(): TelemetryEmitter {
  const enabled = process.env.TELEMETRY_ENABLED !== 'false';
  const endpoint = process.env.TELEMETRY_ENDPOINT;
  const apiKey = process.env.TELEMETRY_API_KEY;
  const useConsole =
    process.env.TELEMETRY_USE_CONSOLE === 'true' ||
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
export function emitDetectionStarted(
  emitter: TelemetryEmitter,
  executionRef: string,
  contentLength: number,
  contentSource: string
): void {
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
export function emitDetectionCompleted(
  emitter: TelemetryEmitter,
  executionRef: string,
  durationMs: number,
  abuseDetected: boolean,
  entityCount: number,
  categories: string[],
  riskScore: number
): void {
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
export function emitDetectionError(
  emitter: TelemetryEmitter,
  executionRef: string,
  errorCode: string,
  errorMessage: string
): void {
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
export function emitBehavioralAnalysisCompleted(
  emitter: TelemetryEmitter,
  executionRef: string,
  appearsAutomated: boolean,
  abnormalRate: boolean,
  redFlagCount: number
): void {
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
export function emitPatternMatchFound(
  emitter: TelemetryEmitter,
  executionRef: string,
  patternId: string,
  category: string,
  severity: string,
  confidence: number
): void {
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
let globalEmitter: TelemetryEmitter | null = null;

/**
 * Get or create the global telemetry emitter
 */
export function getTelemetryEmitter(): TelemetryEmitter {
  if (!globalEmitter) {
    globalEmitter = createTelemetryEmitterFromEnv();
  }
  return globalEmitter;
}

/**
 * Set the global telemetry emitter
 */
export function setTelemetryEmitter(emitter: TelemetryEmitter): void {
  globalEmitter = emitter;
}
