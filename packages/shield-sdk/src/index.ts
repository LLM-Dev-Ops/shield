/**
 * @llm-dev-ops/shield-sdk
 *
 * Enterprise-grade SDK for securing Large Language Model applications.
 *
 * @example
 * ```typescript
 * import { Shield } from '@llm-dev-ops/shield-sdk';
 *
 * // Create a shield with standard security level
 * const shield = Shield.standard();
 *
 * // Scan a prompt before sending to LLM
 * const result = await shield.scanPrompt("User input here");
 *
 * if (result.isValid) {
 *   console.log("Prompt is safe to send to LLM");
 * } else {
 *   console.log("Security risk detected:", result.riskFactors);
 * }
 * ```
 *
 * @packageDocumentation
 */

// Main exports
export { Shield, ShieldBuilder, gatewayTokenStore } from './shield.js';

// Types
export type {
  Severity,
  Category,
  Entity,
  RiskFactor,
  ScanResult,
  Scanner,
  ScannerConfig,
  ShieldConfig,
  ScanOptions,
} from './types.js';

// Scanners
export {
  BaseScanner,
  PromptInjectionScanner,
  SecretsScanner,
  PIIScanner,
  ToxicityScanner,
} from './scanners/index.js';

export type {
  PromptInjectionConfig,
  SecretsConfig,
  PIIConfig,
  ToxicityConfig,
} from './scanners/index.js';

// Version
export const VERSION = '1.0.0';
