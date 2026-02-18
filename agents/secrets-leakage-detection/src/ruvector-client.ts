/**
 * @module secrets-leakage-detection/ruvector-client
 * @description Client for persisting DecisionEvents to ruvector-service
 *
 * CRITICAL: This is the ONLY persistence mechanism.
 * LLM-Shield NEVER connects directly to Google SQL.
 * All persistence occurs via ruvector-service client calls only.
 */

import type { DecisionEvent } from '@llm-shield/agentics-contracts';

/**
 * Configuration for ruvector-service client
 */
export interface RuVectorClientConfig {
  /** Service endpoint URL */
  endpoint: string;
  /** API key for authentication */
  apiKey?: string;
  /** Request timeout in milliseconds */
  timeout?: number;
  /** Enable retry on failure */
  retry?: boolean;
  /** Maximum retry attempts */
  maxRetries?: number;
}

/**
 * Response from ruvector-service
 */
export interface RuVectorResponse {
  /** Whether the operation succeeded */
  success: boolean;
  /** Event ID if persisted */
  event_id?: string;
  /** Error message if failed */
  error?: string;
  /** Timestamp of persistence */
  persisted_at?: string;
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: Partial<RuVectorClientConfig> = {
  timeout: 5000,
  retry: false,
  maxRetries: 1,
};

/**
 * Client for interacting with ruvector-service
 *
 * This client handles all persistence operations for DecisionEvents.
 * It never stores raw secrets, PII, or sensitive content.
 */
export class RuVectorClient {
  private readonly config: RuVectorClientConfig;

  constructor(config: RuVectorClientConfig) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Persist a DecisionEvent to ruvector-service
   *
   * @param event - The DecisionEvent to persist
   * @returns Response from the service
   */
  async persistDecisionEvent(event: DecisionEvent): Promise<RuVectorResponse> {
    const url = `${this.config.endpoint}/api/v1/decisions`;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(
        () => controller.abort(),
        this.config.timeout
      );

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(this.config.apiKey && {
            Authorization: `Bearer ${this.config.apiKey}`,
          }),
        },
        body: JSON.stringify(event),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.text().catch(() => 'Unknown error');
        return {
          success: false,
          error: `HTTP ${response.status}: ${errorBody}`,
        };
      }

      const data = await response.json() as Record<string, unknown>;
      return {
        success: true,
        event_id: data.event_id as string | undefined,
        persisted_at: (data.persisted_at as string) || new Date().toISOString(),
      };
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        return {
          success: false,
          error: 'Request timeout',
        };
      }

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Retrieve a DecisionEvent by execution reference
   *
   * @param executionRef - The execution_ref UUID
   * @returns The DecisionEvent if found
   */
  async getDecisionEvent(
    executionRef: string
  ): Promise<DecisionEvent | null> {
    const url = `${this.config.endpoint}/api/v1/decisions/${executionRef}`;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(
        () => controller.abort(),
        this.config.timeout
      );

      const response = await fetch(url, {
        method: 'GET',
        headers: {
          ...(this.config.apiKey && {
            Authorization: `Bearer ${this.config.apiKey}`,
          }),
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        return null;
      }

      return await response.json() as DecisionEvent;
    } catch {
      return null;
    }
  }
}

/**
 * Create a ruvector-service client from environment variables
 */
export function createClientFromEnv(): RuVectorClient {
  const endpoint =
    process.env.RUVECTOR_ENDPOINT || 'http://localhost:8080';
  const apiKey = process.env.RUVECTOR_API_KEY;

  return new RuVectorClient({
    endpoint,
    apiKey,
    timeout: parseInt(process.env.RUVECTOR_TIMEOUT || '5000', 10),
  });
}

/**
 * Create a no-op client for testing (does not persist)
 */
export function createNoOpClient(): RuVectorClient {
  return {
    persistDecisionEvent: async () => ({
      success: true,
      event_id: 'noop-' + Date.now(),
      persisted_at: new Date().toISOString(),
    }),
    getDecisionEvent: async () => null,
  } as unknown as RuVectorClient;
}
