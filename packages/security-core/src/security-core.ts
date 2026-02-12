/**
 * @module security-core
 * @description LLM-Security-Core gateway - the SOLE authorized entry point for LLM-Shield.
 *
 * All scanning operations MUST go through SecurityCore.
 * Direct calls to Shield or LLMShield are forbidden.
 */

import { Shield, ShieldBuilder as SdkShieldBuilder } from '@llm-dev-ops/shield-sdk';
import type { ScanResult, ScanOptions, Scanner } from '@llm-dev-ops/shield-sdk';
import type {
  CallerToken,
  GatewayContext,
  SecurityCoreConfig,
  CentralizedPolicy,
  PolicyDecision,
} from './types.js';
import { validateCallerToken, createCallerToken } from './caller-token.js';
import {
  CallerTokenError,
  MissingExecutionContextError,
  PolicyDeniedError,
} from './errors.js';
import { gatewayTokenStore } from './gateway-store.js';

const DEFAULT_TOKEN_TTL_SECONDS = 300;

/**
 * Default policy that allows all operations.
 */
class DefaultPolicy implements CentralizedPolicy {
  async authorize(_context: GatewayContext, _operation: string): Promise<PolicyDecision> {
    return { allowed: true };
  }
}

/**
 * SecurityCore - The sole authorized gateway for all LLM-Shield scanning.
 *
 * Every scan request must provide a valid GatewayContext containing:
 * - An HMAC-signed CallerToken (caller authentication)
 * - execution_id + parent_span_id (Agentics execution context)
 *
 * @example
 * ```typescript
 * import { SecurityCore, createCallerToken } from '@llm-shield/security-core';
 *
 * const core = SecurityCore.standard({ sharedSecret: process.env.GATEWAY_SECRET! });
 *
 * const token = createCallerToken('my-service', process.env.GATEWAY_SECRET!);
 * const result = await core.scanPrompt('User input', {
 *   execution_id: 'exec-123',
 *   parent_span_id: 'span-456',
 *   caller: token,
 * });
 * ```
 */
export class SecurityCore {
  private shield: Shield;
  private config: SecurityCoreConfig;
  private policy: CentralizedPolicy;
  private tokenTtlSeconds: number;

  private constructor(
    shield: Shield,
    config: SecurityCoreConfig,
  ) {
    this.shield = shield;
    this.config = config;
    this.policy = config.policy ?? new DefaultPolicy();
    this.tokenTtlSeconds = config.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
  }

  /**
   * Create a SecurityCore with standard Shield preset (recommended).
   */
  static standard(config: SecurityCoreConfig): SecurityCore {
    return new SecurityCore(Shield.standard(), config);
  }

  /**
   * Create a SecurityCore with strict Shield preset.
   * Maximum security for regulated industries.
   */
  static strict(config: SecurityCoreConfig): SecurityCore {
    return new SecurityCore(Shield.strict(), config);
  }

  /**
   * Create a SecurityCore with permissive Shield preset.
   * Minimal security for development/testing.
   */
  static permissive(config: SecurityCoreConfig): SecurityCore {
    return new SecurityCore(Shield.permissive(), config);
  }

  /**
   * Create a builder for custom SecurityCore configuration.
   */
  static builder(): SecurityCoreBuilder {
    return new SecurityCoreBuilder();
  }

  /**
   * Generate a CallerToken for a given caller ID.
   * Utility for callers to create valid tokens.
   */
  static createCallerToken(callerId: string, sharedSecret: string): CallerToken {
    return createCallerToken(callerId, sharedSecret);
  }

  /**
   * Scan a prompt before sending to an LLM.
   * This is the ONLY authorized way to invoke prompt scanning.
   */
  async scanPrompt(
    text: string,
    context: GatewayContext,
    options?: ScanOptions,
  ): Promise<ScanResult> {
    this.validateContext(context);
    await this.authorizeOperation(context, 'scanPrompt');

    return gatewayTokenStore.run({ token: context.caller }, () => {
      return this.shield.scanPrompt(text, options);
    });
  }

  /**
   * Scan LLM output before returning to the user.
   * This is the ONLY authorized way to invoke output scanning.
   */
  async scanOutput(
    text: string,
    context: GatewayContext,
    options?: ScanOptions,
  ): Promise<ScanResult> {
    this.validateContext(context);
    await this.authorizeOperation(context, 'scanOutput');

    return gatewayTokenStore.run({ token: context.caller }, () => {
      return this.shield.scanOutput(text, options);
    });
  }

  /**
   * Scan multiple texts in batch.
   * This is the ONLY authorized way to invoke batch scanning.
   */
  async scanBatch(
    texts: string[],
    context: GatewayContext,
    options?: ScanOptions,
  ): Promise<ScanResult[]> {
    this.validateContext(context);
    await this.authorizeOperation(context, 'scanBatch');

    return gatewayTokenStore.run({ token: context.caller }, () => {
      return this.shield.scanBatch(texts, options);
    });
  }

  /**
   * Validate the full gateway context: caller token + execution context.
   */
  private validateContext(context: GatewayContext): void {
    // Validate execution context
    if (!context.execution_id) {
      throw new MissingExecutionContextError('execution_id');
    }
    if (!context.parent_span_id) {
      throw new MissingExecutionContextError('parent_span_id');
    }

    // Validate caller token
    validateCallerToken(context.caller, this.config.sharedSecret, this.tokenTtlSeconds);
  }

  /**
   * Run the centralized policy check.
   */
  private async authorizeOperation(context: GatewayContext, operation: string): Promise<void> {
    const decision = await this.policy.authorize(context, operation);
    if (!decision.allowed) {
      throw new PolicyDeniedError(decision.reason);
    }
  }
}

/**
 * Builder for creating custom SecurityCore configurations.
 */
export class SecurityCoreBuilder {
  private inputScanners: Scanner[] = [];
  private outputScanners: Scanner[] = [];
  private sharedSecret = '';
  private preset: 'standard' | 'strict' | 'permissive' = 'standard';
  private policy?: CentralizedPolicy;
  private tokenTtlSeconds?: number;
  private parallelExecution = true;
  private maxConcurrent = 4;
  private shortCircuitThreshold = 0.9;

  withSecret(secret: string): this {
    this.sharedSecret = secret;
    return this;
  }

  withPreset(preset: 'standard' | 'strict' | 'permissive'): this {
    this.preset = preset;
    return this;
  }

  withPolicy(policy: CentralizedPolicy): this {
    this.policy = policy;
    return this;
  }

  withTokenTtl(seconds: number): this {
    this.tokenTtlSeconds = seconds;
    return this;
  }

  addInputScanner(scanner: Scanner): this {
    this.inputScanners.push(scanner);
    return this;
  }

  addOutputScanner(scanner: Scanner): this {
    this.outputScanners.push(scanner);
    return this;
  }

  withParallelExecution(enabled: boolean): this {
    this.parallelExecution = enabled;
    return this;
  }

  withMaxConcurrent(max: number): this {
    this.maxConcurrent = max;
    return this;
  }

  withShortCircuit(threshold: number): this {
    this.shortCircuitThreshold = threshold;
    return this;
  }

  build(): SecurityCore {
    if (!this.sharedSecret) {
      throw new CallerTokenError('sharedSecret is required for SecurityCore');
    }

    // Build the inner Shield
    let shield: Shield;

    if (this.inputScanners.length > 0 || this.outputScanners.length > 0) {
      // Custom scanner configuration
      const builder = Shield.builder()
        .withParallelExecution(this.parallelExecution)
        .withMaxConcurrent(this.maxConcurrent)
        .withShortCircuit(this.shortCircuitThreshold);

      for (const scanner of this.inputScanners) {
        builder.addInputScanner(scanner);
      }
      for (const scanner of this.outputScanners) {
        builder.addOutputScanner(scanner);
      }

      shield = builder.build();
    } else {
      // Use preset
      switch (this.preset) {
        case 'strict':
          shield = Shield.strict();
          break;
        case 'permissive':
          shield = Shield.permissive();
          break;
        default:
          shield = Shield.standard();
      }
    }

    const config: SecurityCoreConfig = {
      sharedSecret: this.sharedSecret,
      preset: this.preset,
      policy: this.policy,
      tokenTtlSeconds: this.tokenTtlSeconds,
    };

    // Access private constructor via cast
    return new (SecurityCore as any)(shield, config);
  }
}
