/**
 * @module credential-exposure-detection
 * @description Credential Exposure Detection Agent for LLM-Shield
 *
 * Agent ID: credential-exposure-detection-agent
 * Classification: DETECTION_ONLY
 * Decision Type: credential_exposure_detection
 *
 * This agent detects accidental exposure of usernames, passwords, access keys,
 * or authentication artifacts in model inputs or outputs.
 *
 * Purpose Statement:
 * Detect accidental exposure of authentication credentials including:
 * - Username/password combinations
 * - Basic and Bearer authentication headers
 * - Database credentials
 * - API credentials and OAuth tokens
 * - Hardcoded credentials in code
 * - Environment variable credential patterns
 *
 * Deployment: Google Cloud Edge Function
 *
 * This agent does NOT:
 * - Modify, sanitize, or redact content (DETECTION_ONLY)
 * - Block or allow content
 * - Orchestrate workflows
 * - Trigger retries or escalations
 * - Modify policies
 * - Connect directly to databases
 * - Store raw credentials
 */

// Handler exports
export { handleDetection, type HandlerConfig } from './handler.js';
export { default as edgeHandler } from './handler.js';

// Pattern exports
export {
  CREDENTIAL_PATTERNS,
  getPatternsByCategory,
  getPairPatterns,
  getPasswordOnlyPatterns,
  getUsernameOnlyPatterns,
  getAuthHeaderPatterns,
  createCustomPattern,
  type CredentialPattern,
} from './patterns.js';

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
  TelemetryEmitter,
  ConsoleTelemetryEmitter,
  HttpTelemetryEmitter,
  NoOpTelemetryEmitter,
  BufferedTelemetryEmitter,
  createTelemetryEmitter,
  emitDetectionStarted,
  emitDetectionCompleted,
  emitDetectionError,
  emitPersistenceSuccess,
  emitPersistenceError,
  type TelemetryEvent,
  type TelemetryEventType,
} from './telemetry.js';

// CLI exports
export { main as cli, handleCliInvocation } from './cli.js';

// Re-export contract types
export type {
  CredentialType,
  CredentialExposureDetectionInput,
  CredentialExposureDetectedEntity,
  CredentialExposureDetectionResult,
  CredentialExposureDetectionAgentOutput,
  CredentialExposureDecisionEvent,
} from '@llm-shield/agentics-contracts';

/**
 * Agent identity constants
 */
export const AGENT_ID = 'credential-exposure-detection-agent';
export const AGENT_VERSION = '1.0.0';
export const AGENT_CLASSIFICATION = 'DETECTION_ONLY' as const;
export const AGENT_DECISION_TYPE = 'credential_exposure_detection' as const;

/**
 * Quick detection function for simple use cases
 *
 * @param content - Content to analyze for credential exposure
 * @param options - Optional detection configuration
 * @returns Detection summary
 *
 * @example
 * ```typescript
 * const result = await detectCredentials('username=admin password=secret123');
 * console.log(result.detected); // true
 * console.log(result.categories); // ['username_password']
 * ```
 */
export async function detectCredentials(
  content: string,
  options?: {
    sensitivity?: number;
    types?: CredentialType[];
    detectPairs?: boolean;
    detectPasswords?: boolean;
    detectAuthHeaders?: boolean;
    minPasswordLength?: number;
  }
): Promise<{
  detected: boolean;
  count: number;
  pairCount: number;
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
      detect_types: options?.types,
      detect_credential_pairs: options?.detectPairs,
      detect_password_patterns: options?.detectPasswords,
      detect_auth_headers: options?.detectAuthHeaders,
      min_password_length: options?.minPasswordLength,
    },
    { skipPersistence: true }
  );

  if ('code' in result) {
    throw new Error(result.message);
  }

  return {
    detected: result.result.credentials_detected,
    count: result.result.pattern_match_count,
    pairCount: result.result.credential_pair_count,
    categories: result.result.detected_types,
    riskScore: result.result.risk_score,
    severity: result.result.severity,
  };
}

// Import for type re-export
import type { CredentialType } from '@llm-shield/agentics-contracts';
