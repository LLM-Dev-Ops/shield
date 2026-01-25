/**
 * @module performance-boundaries
 * @description Performance boundary enforcement for LLM-Shield agents
 *
 * Phase 1 / Layer 1 - Foundational Tooling
 *
 * Conservative defaults to prevent runaway execution:
 * - MAX_TOKENS: 800 (input content size limit)
 * - MAX_LATENCY_MS: 1500 (execution time limit)
 * - MAX_CALLS_PER_RUN: 2 (external API calls per detection)
 */

import { getAgentIdentity, structuredLog } from './startup-validator.js';

// =============================================================================
// PERFORMANCE CONSTANTS
// =============================================================================

export const PERFORMANCE_LIMITS = {
  MAX_TOKENS: 800,
  MAX_LATENCY_MS: 1500,
  MAX_CALLS_PER_RUN: 2,
} as const;

// =============================================================================
// TYPES
// =============================================================================

export interface PerformanceContext {
  startTime: number;
  callCount: number;
  tokenCount: number;
}

export interface PerformanceViolation {
  type: 'MAX_TOKENS' | 'MAX_LATENCY_MS' | 'MAX_CALLS_PER_RUN';
  limit: number;
  actual: number;
  message: string;
}

export class PerformanceBoundaryError extends Error {
  violation: PerformanceViolation;

  constructor(violation: PerformanceViolation) {
    super(violation.message);
    this.name = 'PerformanceBoundaryError';
    this.violation = violation;
  }
}

// =============================================================================
// PERFORMANCE TRACKER
// =============================================================================

export class PerformanceTracker {
  private startTime: number;
  private callCount: number = 0;
  private tokenCount: number = 0;
  private readonly executionRef: string;

  constructor(executionRef: string) {
    this.startTime = performance.now();
    this.executionRef = executionRef;
  }

  /**
   * Track token count and check against limit
   */
  trackTokens(count: number): void {
    this.tokenCount += count;
    if (this.tokenCount > PERFORMANCE_LIMITS.MAX_TOKENS) {
      const violation: PerformanceViolation = {
        type: 'MAX_TOKENS',
        limit: PERFORMANCE_LIMITS.MAX_TOKENS,
        actual: this.tokenCount,
        message: `Token limit exceeded: ${this.tokenCount} > ${PERFORMANCE_LIMITS.MAX_TOKENS}`,
      };

      this.logViolation(violation);
      throw new PerformanceBoundaryError(violation);
    }
  }

  /**
   * Track external API call and check against limit
   */
  trackCall(): void {
    this.callCount++;
    if (this.callCount > PERFORMANCE_LIMITS.MAX_CALLS_PER_RUN) {
      const violation: PerformanceViolation = {
        type: 'MAX_CALLS_PER_RUN',
        limit: PERFORMANCE_LIMITS.MAX_CALLS_PER_RUN,
        actual: this.callCount,
        message: `Call limit exceeded: ${this.callCount} > ${PERFORMANCE_LIMITS.MAX_CALLS_PER_RUN}`,
      };

      this.logViolation(violation);
      throw new PerformanceBoundaryError(violation);
    }
  }

  /**
   * Check latency and throw if exceeded
   */
  checkLatency(): void {
    const elapsed = performance.now() - this.startTime;
    if (elapsed > PERFORMANCE_LIMITS.MAX_LATENCY_MS) {
      const violation: PerformanceViolation = {
        type: 'MAX_LATENCY_MS',
        limit: PERFORMANCE_LIMITS.MAX_LATENCY_MS,
        actual: Math.round(elapsed),
        message: `Latency limit exceeded: ${Math.round(elapsed)}ms > ${PERFORMANCE_LIMITS.MAX_LATENCY_MS}ms`,
      };

      this.logViolation(violation);
      throw new PerformanceBoundaryError(violation);
    }
  }

  /**
   * Get current elapsed time
   */
  getElapsedMs(): number {
    return Math.round(performance.now() - this.startTime);
  }

  /**
   * Get performance context snapshot
   */
  getContext(): PerformanceContext {
    return {
      startTime: this.startTime,
      callCount: this.callCount,
      tokenCount: this.tokenCount,
    };
  }

  /**
   * Log performance violation
   */
  private logViolation(violation: PerformanceViolation): void {
    try {
      const identity = getAgentIdentity();
      structuredLog('agent_abort', `Performance boundary violated: ${violation.type}`, identity, {
        execution_ref: this.executionRef,
        violation_type: violation.type,
        limit: violation.limit,
        actual: violation.actual,
      });
    } catch {
      // Identity not initialized, log without it
      console.error(JSON.stringify({
        level: 'agent_abort',
        timestamp: new Date().toISOString(),
        message: `Performance boundary violated: ${violation.type}`,
        execution_ref: this.executionRef,
        violation_type: violation.type,
        limit: violation.limit,
        actual: violation.actual,
      }));
    }
  }
}

// =============================================================================
// SIMPLE TOKEN COUNTER
// =============================================================================

/**
 * Estimate token count from content
 * Uses simple word-based approximation (avg 4 chars per token)
 */
export function estimateTokenCount(content: string): number {
  // Simple estimation: ~4 characters per token on average
  return Math.ceil(content.length / 4);
}

/**
 * Check if content exceeds token limit
 */
export function checkTokenLimit(content: string): { valid: boolean; tokenCount: number } {
  const tokenCount = estimateTokenCount(content);
  return {
    valid: tokenCount <= PERFORMANCE_LIMITS.MAX_TOKENS,
    tokenCount,
  };
}
