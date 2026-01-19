/**
 * @module content-moderation
 * @description Content Moderation Enforcement Agent for LLM-Shield
 *
 * This module exports the Content Moderation Agent which applies moderation
 * policies to classify or block disallowed content categories.
 *
 * Classification: ENFORCEMENT
 * Decision Type: content_moderation
 */

// Agent
export {
  ContentModerationAgent,
  createAgent,
  AGENT_IDENTITY,
  type AgentConfig,
} from './agent.js';

// Handler
export { handler, contentModeration, type EdgeRequest, type EdgeResponse } from './handler.js';

// Patterns
export {
  MODERATION_PATTERNS,
  MODERATION_CATEGORIES,
  getPatternsForCategories,
  getAllPatterns,
  getPatternById,
  getPatternCountByCategory,
} from './patterns.js';

// Types
export type {
  ModerationPattern,
  PatternMatch,
  ModerationDecision,
  CategoryMeta,
} from './types.js';
export { CATEGORY_METADATA, scoreToSeverity } from './types.js';

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

// CLI
export {
  executeCli,
  parseArgs,
  printHelp,
  type CliOptions,
  type CliResult,
} from './cli.js';
