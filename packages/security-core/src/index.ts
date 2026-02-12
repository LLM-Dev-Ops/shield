/**
 * @module @llm-shield/security-core
 * @description LLM-Security-Core - The SOLE authorized entry point for LLM-Shield scanning.
 *
 * All scanning operations MUST go through SecurityCore.
 * Direct calls to Shield, LLMShield, or quickScan are FORBIDDEN.
 *
 * @example
 * ```typescript
 * import { SecurityCore, createCallerToken } from '@llm-shield/security-core';
 *
 * const core = SecurityCore.standard({ sharedSecret: process.env.GATEWAY_SECRET! });
 * const token = createCallerToken('my-service', process.env.GATEWAY_SECRET!);
 *
 * const result = await core.scanPrompt('Hello world', {
 *   execution_id: 'exec-123',
 *   parent_span_id: 'span-456',
 *   caller: token,
 * });
 * ```
 */

// Gateway
export { SecurityCore, SecurityCoreBuilder } from './security-core.js';

// Caller token
export { createCallerToken, validateCallerToken } from './caller-token.js';

// Gateway store (for internal use by Shield runtime guard)
export { gatewayTokenStore } from './gateway-store.js';

// Types
export type {
  CallerToken,
  GatewayContext,
  SecurityCoreConfig,
  CentralizedPolicy,
  PolicyDecision,
} from './types.js';

// Errors
export {
  GatewayError,
  CallerTokenError,
  DirectAccessError,
  PolicyDeniedError,
  MissingExecutionContextError,
} from './errors.js';

// Re-export scan result types from shield-sdk for convenience
export type { ScanResult, ScanOptions, Severity } from '@llm-dev-ops/shield-sdk';
