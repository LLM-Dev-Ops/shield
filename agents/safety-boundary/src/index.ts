/**
 * @module safety-boundary
 * @description Safety Boundary Enforcement Agent for LLM-Shield
 *
 * This module exports the Safety Boundary Agent which enforces safety boundaries
 * by evaluating content against configurable safety policies and making
 * ALLOW/BLOCK enforcement decisions.
 *
 * Classification: ENFORCEMENT
 * Decision Type: safety_boundary_enforcement
 */

// Agent
export {
  SafetyBoundaryAgent,
  createAgent,
  AGENT_IDENTITY,
  type AgentConfig,
} from './agent.js';

// Handler
export { handler, safetyBoundaryEnforcement, type EdgeRequest, type EdgeResponse } from './handler.js';

// Patterns
export {
  SAFETY_PATTERNS,
  SAFETY_CATEGORIES,
  getPatternsForCategories,
  getAllPatterns,
  getPatternById,
  getPatternCountByCategory,
} from './patterns.js';

// Types
export type {
  SafetyPattern,
  PatternMatch,
  EnforcementDecision,
  CategoryMeta,
} from './types.js';
export { CATEGORY_METADATA, scoreToseverity } from './types.js';

// RuVector Client
export {
  RuVectorClient,
  createMockRuVectorClient,
  type RuVectorClientConfig,
  type RuVectorResponse,
} from './ruvector-client.js';

// Telemetry
export {
  TelemetryEmitter,
  createNoOpTelemetryEmitter,
  type TelemetryConfig,
  type TelemetryEvent,
  type TelemetryEventType,
} from './telemetry.js';
