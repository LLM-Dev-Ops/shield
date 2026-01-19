/**
 * @module agent
 * @description Main agent class for Model Abuse Detection
 *
 * This module provides a high-level interface for the Model Abuse Detection Agent.
 * It wraps the detection logic and provides methods for input validation,
 * detection, and cleanup.
 */

import {
  ModelAbuseDetectionInput,
  ModelAbuseDetectionAgentOutput,
  AgentError,
  type AgentIdentity,
} from '@llm-shield/agentics-contracts';
import { handleDetection, AGENT_IDENTITY, type HandlerConfig } from './handler.js';
import { RuVectorClient, createClientFromEnv, createNoOpClient } from './ruvector-client.js';
import {
  TelemetryEmitter,
  createTelemetryEmitter,
  type TelemetryConfig,
} from './telemetry.js';

/**
 * Agent configuration
 */
export interface AgentConfig {
  /** RuVector service configuration */
  ruvectorConfig?: {
    baseUrl: string;
    apiKey?: string;
    timeout?: number;
  };
  /** Telemetry configuration */
  telemetryConfig?: TelemetryConfig;
  /** Skip persistence (for testing/simulation) */
  skipPersistence?: boolean;
}

/**
 * Model Abuse Detection Agent
 *
 * This class provides the main interface for detecting model abuse patterns.
 * It is designed to be stateless at runtime - each detection call is independent.
 *
 * Classification: DETECTION_ONLY
 * - This agent ONLY detects abuse patterns
 * - It does NOT block, redact, or modify content
 * - It does NOT orchestrate workflows
 * - It does NOT perform retries
 */
export class ModelAbuseDetectionAgent {
  private ruvectorClient: RuVectorClient;
  private telemetryEmitter: TelemetryEmitter;
  private config: AgentConfig;

  constructor(config: AgentConfig = {}) {
    this.config = config;

    // Initialize RuVector client
    if (config.skipPersistence) {
      this.ruvectorClient = createNoOpClient();
    } else if (config.ruvectorConfig) {
      this.ruvectorClient = new RuVectorClient({
        endpoint: config.ruvectorConfig.baseUrl,
        apiKey: config.ruvectorConfig.apiKey,
        timeout: config.ruvectorConfig.timeout,
      });
    } else {
      this.ruvectorClient = createClientFromEnv();
    }

    // Initialize telemetry emitter
    this.telemetryEmitter = createTelemetryEmitter(config.telemetryConfig);
  }

  /**
   * Get agent identity
   */
  get identity(): AgentIdentity {
    return AGENT_IDENTITY;
  }

  /**
   * Validate input against schema
   *
   * @param input - Raw input to validate
   * @returns Validated input
   * @throws Error if validation fails
   */
  validateInput(
    input: unknown
  ): ReturnType<typeof ModelAbuseDetectionInput.parse> {
    return ModelAbuseDetectionInput.parse(input);
  }

  /**
   * Safely validate input (no throw)
   *
   * @param input - Raw input to validate
   * @returns Validation result with success flag
   */
  safeValidateInput(input: unknown): {
    success: boolean;
    data?: ReturnType<typeof ModelAbuseDetectionInput.parse>;
    errors?: Array<{ path: string; message: string }>;
  } {
    const result = ModelAbuseDetectionInput.safeParse(input);
    if (result.success) {
      return { success: true, data: result.data };
    }
    return {
      success: false,
      errors: result.error.errors.map((e) => ({
        path: e.path.join('.'),
        message: e.message,
      })),
    };
  }

  /**
   * Detect model abuse patterns
   *
   * This is the main detection method. It:
   * 1. Validates input
   * 2. Runs detection logic
   * 3. Persists decision event
   * 4. Emits telemetry
   * 5. Returns result
   *
   * @param input - Validated input
   * @returns Detection output or error
   */
  async detect(
    input: ReturnType<typeof ModelAbuseDetectionInput.parse>
  ): Promise<ModelAbuseDetectionAgentOutput | AgentError> {
    const handlerConfig: HandlerConfig = {
      ruvectorClient: this.ruvectorClient,
      telemetryEmitter: this.telemetryEmitter,
      skipPersistence: this.config.skipPersistence,
    };

    return handleDetection(input, handlerConfig);
  }

  /**
   * Detect from raw input (validates first)
   *
   * Convenience method that combines validation and detection.
   *
   * @param rawInput - Raw input to validate and process
   * @returns Detection output or error
   */
  async detectRaw(
    rawInput: unknown
  ): Promise<ModelAbuseDetectionAgentOutput | AgentError> {
    const handlerConfig: HandlerConfig = {
      ruvectorClient: this.ruvectorClient,
      telemetryEmitter: this.telemetryEmitter,
      skipPersistence: this.config.skipPersistence,
    };

    return handleDetection(rawInput, handlerConfig);
  }

  /**
   * Check if ruvector-service is healthy
   */
  async healthCheck(): Promise<boolean> {
    return this.ruvectorClient.healthCheck();
  }

  /**
   * Shutdown the agent
   *
   * Flushes telemetry and cleans up resources.
   */
  async shutdown(): Promise<void> {
    await this.telemetryEmitter.flush();
    await this.telemetryEmitter.shutdown();
  }
}

/**
 * Create a new agent instance
 */
export function createAgent(config?: AgentConfig): ModelAbuseDetectionAgent {
  return new ModelAbuseDetectionAgent(config);
}

// Re-export identity for convenience
export { AGENT_IDENTITY };
