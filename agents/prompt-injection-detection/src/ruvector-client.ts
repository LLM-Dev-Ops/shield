/**
 * @module ruvector-client
 * @description Client for persisting DecisionEvents to ruvector-service
 *
 * LLM-Shield agents NEVER connect directly to Google SQL.
 * All persistence occurs via ruvector-service API calls only.
 */

import type { DecisionEvent } from '@llm-shield/agentics-contracts';

/**
 * Configuration for ruvector-service client
 */
export interface RuVectorClientConfig {
  /** Base URL of ruvector-service */
  baseUrl: string;
  /** API key for authentication */
  apiKey?: string;
  /** Request timeout in milliseconds */
  timeout?: number;
  /** Enable retry on transient failures */
  retryEnabled?: boolean;
  /** Maximum retry attempts */
  maxRetries?: number;
}

/**
 * Response from ruvector-service
 */
export interface RuVectorResponse {
  success: boolean;
  event_id?: string;
  error?: string;
  timestamp: string;
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: Partial<RuVectorClientConfig> = {
  baseUrl: process.env.RUVECTOR_SERVICE_URL || 'http://localhost:8080',
  timeout: 5000,
  retryEnabled: true,
  maxRetries: 3,
};

/**
 * Client for persisting DecisionEvents to ruvector-service
 *
 * This client handles:
 * - Event serialization
 * - HTTP transport
 * - Error handling
 * - Retry logic
 *
 * This client does NOT:
 * - Execute SQL queries
 * - Connect to databases directly
 * - Store raw content
 */
export class RuVectorClient {
  private readonly config: RuVectorClientConfig;
  private readonly endpoint: string;

  constructor(config: Partial<RuVectorClientConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config } as RuVectorClientConfig;
    this.endpoint = `${this.config.baseUrl}/api/v1/events/decision`;
  }

  /**
   * Persist a DecisionEvent to ruvector-service
   *
   * @param event - The DecisionEvent to persist
   * @returns Response from ruvector-service
   */
  async persistDecisionEvent(event: DecisionEvent): Promise<RuVectorResponse> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Agent-ID': event.agent_id,
      'X-Agent-Version': event.agent_version,
      'X-Execution-Ref': event.execution_ref,
    };

    if (this.config.apiKey) {
      headers['Authorization'] = `Bearer ${this.config.apiKey}`;
    }

    let lastError: Error | null = null;
    const maxAttempts = this.config.retryEnabled ? this.config.maxRetries! : 1;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(
          () => controller.abort(),
          this.config.timeout
        );

        const response = await fetch(this.endpoint, {
          method: 'POST',
          headers,
          body: JSON.stringify(event),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          const errorBody = await response.text().catch(() => 'Unknown error');
          throw new Error(
            `ruvector-service returned ${response.status}: ${errorBody}`
          );
        }

        const result = await response.json() as RuVectorResponse;
        return {
          ...result,
          success: true,
          timestamp: new Date().toISOString(),
        };
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        // Don't retry on client errors (4xx)
        if (lastError.message.includes('returned 4')) {
          break;
        }

        // Exponential backoff for retries
        if (attempt < maxAttempts) {
          await this.delay(Math.pow(2, attempt) * 100);
        }
      }
    }

    // Return failure response (agent still completes)
    return {
      success: false,
      error: lastError?.message || 'Unknown error',
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Health check for ruvector-service
   */
  async healthCheck(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);

      const response = await fetch(`${this.config.baseUrl}/health`, {
        method: 'GET',
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      return response.ok;
    } catch {
      return false;
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

/**
 * Create a mock client for testing
 */
export function createMockRuVectorClient(): RuVectorClient {
  const client = new RuVectorClient({ baseUrl: 'http://mock' });

  // Override persistDecisionEvent for testing
  client.persistDecisionEvent = async (event: DecisionEvent) => ({
    success: true,
    event_id: `mock-${event.execution_ref}`,
    timestamp: new Date().toISOString(),
  });

  return client;
}
