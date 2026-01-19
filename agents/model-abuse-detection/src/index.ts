/**
 * @module @llm-shield/model-abuse-detection-agent
 * @description Model Abuse Detection Agent for LLM-Shield
 *
 * This agent detects patterns of misuse, abuse, or exploitation of LLM systems.
 *
 * Classification: DETECTION_ONLY
 * - This agent ONLY detects abuse patterns
 * - It does NOT block, redact, or modify content
 * - It does NOT orchestrate workflows
 * - It does NOT perform retries
 * - It does NOT trigger alerts or incidents
 *
 * All decisions are persisted to ruvector-service.
 * Telemetry is emitted to LLM-Observatory.
 */

// Main agent exports
export {
  ModelAbuseDetectionAgent,
  createAgent,
  AGENT_IDENTITY,
  type AgentConfig,
} from './agent.js';

// Handler exports (for Edge Function deployment)
export {
  handleDetection,
  type HandlerConfig,
} from './handler.js';
export { default as edgeHandler } from './handler.js';

// Detection exports
export {
  ModelAbuseDetector,
  createDetector,
  type DetectionConfig,
  type RequestMetadata,
  type HistoricalContext,
  type BehavioralSummary,
} from './detector.js';

// Pattern exports
export {
  MODEL_ABUSE_PATTERNS,
  BEHAVIORAL_THRESHOLDS,
  getAllPatternIds,
  getPatternsForCategories,
  getThresholdsForCategories,
  getPatternById,
  getThresholdById,
  type ModelAbusePattern,
  type BehavioralThreshold,
} from './patterns.js';

// Client exports
export {
  RuVectorClient,
  createClientFromEnv,
  createNoOpClient,
  type RuVectorClientConfig,
  type RuVectorResponse,
} from './ruvector-client.js';

// Telemetry exports
export {
  createTelemetryEmitter,
  createTelemetryEmitterFromEnv,
  getTelemetryEmitter,
  setTelemetryEmitter,
  emitDetectionStarted,
  emitDetectionCompleted,
  emitDetectionError,
  emitBehavioralAnalysisCompleted,
  emitPatternMatchFound,
  type TelemetryEmitter,
  type TelemetryConfig,
  type TelemetryEvent,
  type TelemetryEventType,
} from './telemetry.js';

// Re-export relevant types from contracts
export type {
  ModelAbuseCategory,
  ModelAbuseDetectionInput,
  ModelAbuseDetectedEntity,
  ModelAbuseDetectionResult,
  ModelAbuseDetectionAgentOutput,
  ModelAbuseDetectionDecisionEvent,
  AgentIdentity,
  AgentError,
  AgentErrorCode,
  Severity,
  RiskFactor,
  PolicyReference,
  InvocationContext,
} from '@llm-shield/agentics-contracts';
