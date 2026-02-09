/**
 * @module llm-shield/lib
 * @description Shared infrastructure for LLM-Shield agents
 *
 * Phase 1 / Layer 1 - Foundational Tooling
 *
 * This module exports all shared infrastructure:
 * - Startup validation
 * - Performance boundaries
 * - Decision event factory
 * - Read-only caching
 */

// Startup validation
export {
  assertStartupRequirements,
  validateStartup,
  validateEnvironment,
  checkRuvectorHealth,
  getAgentIdentity,
  setAgentIdentity,
  structuredLog,
  type AgentIdentityContext,
  type StartupValidationResult,
  type RuvectorHealthCheckResult,
} from './startup-validator.js';

// Performance boundaries
export {
  PERFORMANCE_LIMITS,
  PerformanceTracker,
  PerformanceBoundaryError,
  estimateTokenCount,
  checkTokenLimit,
  type PerformanceContext,
  type PerformanceViolation,
} from './performance-boundaries.js';

// Decision event
export {
  createDecisionEvent,
  validateDecisionEvent,
  emitDecisionEvent,
  resetDecisionEventCounter,
  incrementDecisionEventCounter,
  assertDecisionEventEmitted,
  type DecisionEvent,
  type DetectionSignal,
  type EvidenceRef,
  type PolicyReference,
  type TelemetryMetadata,
  type CreateDecisionEventParams,
} from './decision-event.js';

// Read-only cache
export {
  ReadOnlyCache,
  ruvectorHealthCache,
  schemaCache,
  registryCache,
  getOrCompute,
  createCacheKey,
  startCacheCleanup,
  stopCacheCleanup,
  type CacheEntry,
  type CacheStats,
} from './read-cache.js';

// Execution spans (Agentics Foundational Execution Unit)
export {
  validateExecutionContext,
  createRepoSpan,
  createAgentSpan,
  attachArtifact,
  completeSpan,
  failSpan,
  finalizeRepoSpan,
  validateExecutionOutput,
  type ExecutionContext,
  type ExecutionSpan,
  type ExecutionOutput,
  type SpanArtifact,
  type SpanType,
  type SpanStatus,
} from './execution-span.js';
