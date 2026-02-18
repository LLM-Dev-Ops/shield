/**
 * @module secrets-leakage-detection
 * @description Secrets Leakage Detection Agent for LLM-Shield
 *
 * Agent ID: secrets-leakage-detection-agent
 * Classification: DETECTION_ONLY
 * Decision Type: secret_detection
 *
 * This agent detects exposure of API keys, tokens, credentials, private keys,
 * passwords, and other sensitive secrets in model inputs or outputs.
 *
 * Deployment: Google Cloud Edge Function
 */

// Handler exports
export { handleDetection, type HandlerConfig } from './handler.js';
export { default as edgeHandler } from './handler.js';

// Pattern exports
export {
  SECRET_PATTERNS,
  getPatternsByCategory,
  createCustomPattern,
  type SecretPattern,
} from './patterns.js';

// Entropy detection exports
export {
  calculateEntropy,
  findEntropySecrets,
  looksLikeSecret,
  type EntropyCandidate,
} from './entropy.js';

// RuVector client exports
export {
  RuVectorClient,
  createClientFromEnv,
  createNoOpClient,
  type RuVectorClientConfig,
  type RuVectorResponse,
} from './ruvector-client.js';

// Telemetry exports
export {
  type TelemetryEmitter,
  ConsoleTelemetryEmitter,
  HttpTelemetryEmitter,
  NoOpTelemetryEmitter,
  BufferedTelemetryEmitter,
  createTelemetryEmitter,
  emitDetectionStarted,
  emitDetectionCompleted,
  emitDetectionError,
  type TelemetryEvent,
  type TelemetryEventType,
} from './telemetry.js';

// CLI exports
export { main as cli, handleCliInvocation } from './cli.js';

// Re-export contract types
export type {
  SecretTypeCategory,
  SecretsLeakageDetectionInput,
  DetectedSecretEntity,
} from '@llm-shield/agentics-contracts';

// Local import for use in this module
import type { SecretTypeCategory } from '@llm-shield/agentics-contracts';

/**
 * Agent identity constants
 */
export const AGENT_ID = 'secrets-leakage-detection-agent';
export const AGENT_VERSION = '1.0.0';
export const AGENT_CLASSIFICATION = 'DETECTION_ONLY' as const;
export const AGENT_DECISION_TYPE = 'secret_detection' as const;

/**
 * Quick detection function for simple use cases
 */
export async function detectSecrets(
  content: string,
  options?: {
    sensitivity?: number;
    categories?: SecretTypeCategory[];
    entropyDetection?: boolean;
    entropyThreshold?: number;
  }
): Promise<{
  detected: boolean;
  count: number;
  categories: string[];
  riskScore: number;
  severity: string;
}> {
  const { handleDetection } = await import('./handler.js');
  const { randomUUID } = await import('crypto');

  const result = await handleDetection(
    {
      content,
      context: {
        execution_ref: randomUUID(),
        timestamp: new Date().toISOString(),
        content_source: 'user_input' as const,
      },
      sensitivity: options?.sensitivity,
      detect_categories: options?.categories,
      entropy_detection: options?.entropyDetection,
      entropy_threshold: options?.entropyThreshold,
    },
    { skipPersistence: true }
  );

  if ('code' in result) {
    throw new Error(result.message);
  }

  return {
    detected: result.result.threats_detected,
    count: result.result.pattern_match_count,
    categories: result.result.detected_categories,
    riskScore: result.result.risk_score,
    severity: result.result.severity,
  };
}
