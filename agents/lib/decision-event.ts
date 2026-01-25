/**
 * @module decision-event
 * @description Standardized DecisionEvent factory for LLM-Shield agents
 *
 * Phase 1 / Layer 1 - Foundational Tooling
 *
 * CRITICAL RULES:
 * - Agents MUST emit signals, NOT conclusions
 * - Every event MUST include: source_agent, domain, phase, layer
 * - Every event MUST include: event_type, confidence, evidence_refs (if applicable)
 * - Agents MUST NOT emit summaries, recommendations, or perform synthesis
 */

import { getAgentIdentity, structuredLog, type AgentIdentityContext } from './startup-validator.js';

// =============================================================================
// TYPES
// =============================================================================

/**
 * Evidence reference for supporting a detection signal
 */
export interface EvidenceRef {
  /** Type of evidence (pattern_match, heuristic, model_output) */
  evidence_type: 'pattern_match' | 'heuristic' | 'model_output' | 'rule_based';
  /** Identifier for the evidence source */
  source_id: string;
  /** Position in content (if applicable) */
  position?: { start: number; end: number };
  /** Evidence confidence (0-1) */
  confidence: number;
}

/**
 * Standardized DecisionEvent structure
 *
 * CRITICAL: This is a SIGNAL, not a conclusion or recommendation
 */
export interface DecisionEvent {
  // === AGENT IDENTITY (MANDATORY) ===
  /** Source agent identifier */
  source_agent: string;
  /** Agent domain */
  domain: string;
  /** Deployment phase */
  phase: string;
  /** Deployment layer */
  layer: string;

  // === EVENT METADATA (MANDATORY) ===
  /** Agent version */
  agent_version: string;
  /** Type of event/decision */
  event_type: string;
  /** Execution reference (UUID) */
  execution_ref: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Execution duration in milliseconds */
  duration_ms: number;

  // === SIGNAL DATA (MANDATORY) ===
  /** Overall confidence score (0-1) */
  confidence: number;
  /** SHA-256 hash of inputs (NEVER raw content) */
  inputs_hash: string;
  /** Detection signals (NOT conclusions) */
  signals: DetectionSignal[];
  /** Evidence references supporting the signals */
  evidence_refs: EvidenceRef[];

  // === POLICY CONTEXT ===
  /** Applied policy references */
  constraints_applied: PolicyReference[];

  // === TELEMETRY (OPTIONAL) ===
  /** Non-sensitive telemetry metadata */
  telemetry?: TelemetryMetadata;
}

/**
 * Detection signal - raw observation without synthesis
 */
export interface DetectionSignal {
  /** Signal type identifier */
  signal_type: string;
  /** Signal category */
  category: string;
  /** Severity level */
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  /** Confidence for this specific signal (0-1) */
  confidence: number;
  /** Count of occurrences */
  count: number;
  /** Evidence IDs supporting this signal */
  evidence_ids: string[];
}

/**
 * Policy reference
 */
export interface PolicyReference {
  policy_id: string;
  rule_ids?: string[];
}

/**
 * Non-sensitive telemetry metadata
 */
export interface TelemetryMetadata {
  content_length?: number;
  content_source?: string;
  session_id?: string;
  caller_id?: string;
  [key: string]: unknown;
}

// =============================================================================
// DECISION EVENT FACTORY
// =============================================================================

export interface CreateDecisionEventParams {
  /** Agent version */
  agentVersion: string;
  /** Event type (e.g., pii_detection, prompt_injection_detection) */
  eventType: string;
  /** Execution reference (UUID) */
  executionRef: string;
  /** Timestamp (ISO 8601) */
  timestamp: string;
  /** Duration in milliseconds */
  durationMs: number;
  /** Overall confidence (0-1) */
  confidence: number;
  /** SHA-256 hash of inputs */
  inputsHash: string;
  /** Detection signals */
  signals: DetectionSignal[];
  /** Evidence references */
  evidenceRefs: EvidenceRef[];
  /** Applied constraints/policies */
  constraintsApplied: PolicyReference[];
  /** Optional telemetry metadata */
  telemetry?: TelemetryMetadata;
}

/**
 * Create a standardized DecisionEvent
 *
 * Automatically injects agent identity from environment
 */
export function createDecisionEvent(params: CreateDecisionEventParams): DecisionEvent {
  let identity: AgentIdentityContext;

  try {
    identity = getAgentIdentity();
  } catch {
    // Fallback for testing or cases where identity isn't initialized
    identity = {
      agent_name: process.env.AGENT_NAME || 'unknown',
      domain: process.env.AGENT_DOMAIN || 'unknown',
      phase: process.env.AGENT_PHASE || 'unknown',
      layer: process.env.AGENT_LAYER || 'unknown',
    };
  }

  const event: DecisionEvent = {
    // Agent identity (MANDATORY)
    source_agent: identity.agent_name,
    domain: identity.domain,
    phase: identity.phase,
    layer: identity.layer,

    // Event metadata
    agent_version: params.agentVersion,
    event_type: params.eventType,
    execution_ref: params.executionRef,
    timestamp: params.timestamp,
    duration_ms: params.durationMs,

    // Signal data
    confidence: params.confidence,
    inputs_hash: params.inputsHash,
    signals: params.signals,
    evidence_refs: params.evidenceRefs,

    // Policy context
    constraints_applied: params.constraintsApplied,

    // Telemetry
    ...(params.telemetry && { telemetry: params.telemetry }),
  };

  return event;
}

// =============================================================================
// VALIDATION
// =============================================================================

/**
 * Validate a DecisionEvent meets all requirements
 */
export function validateDecisionEvent(event: DecisionEvent): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  // Check agent identity fields
  if (!event.source_agent || event.source_agent === 'unknown') {
    errors.push('Missing or invalid source_agent');
  }
  if (!event.domain || event.domain === 'unknown') {
    errors.push('Missing or invalid domain');
  }
  if (!event.phase || event.phase === 'unknown') {
    errors.push('Missing or invalid phase');
  }
  if (!event.layer || event.layer === 'unknown') {
    errors.push('Missing or invalid layer');
  }

  // Check mandatory fields
  if (!event.event_type) {
    errors.push('Missing event_type');
  }
  if (!event.execution_ref) {
    errors.push('Missing execution_ref');
  }
  if (!event.inputs_hash || !/^[a-f0-9]{64}$/.test(event.inputs_hash)) {
    errors.push('Invalid or missing inputs_hash (must be SHA-256)');
  }

  // Check confidence is valid
  if (typeof event.confidence !== 'number' || event.confidence < 0 || event.confidence > 1) {
    errors.push('Invalid confidence (must be 0-1)');
  }

  // Check signals array
  if (!Array.isArray(event.signals)) {
    errors.push('Missing signals array');
  }

  // Check evidence_refs array
  if (!Array.isArray(event.evidence_refs)) {
    errors.push('Missing evidence_refs array');
  }

  return { valid: errors.length === 0, errors };
}

// =============================================================================
// EVENT EMISSION HELPER
// =============================================================================

/**
 * Emit a DecisionEvent and log the emission
 */
export function emitDecisionEvent(event: DecisionEvent): void {
  // Validate event
  const validation = validateDecisionEvent(event);
  if (!validation.valid) {
    throw new Error(`Invalid DecisionEvent: ${validation.errors.join(', ')}`);
  }

  // Log emission
  try {
    const identity = getAgentIdentity();
    structuredLog('decision_event_emitted', `Emitted ${event.event_type} event`, identity, {
      execution_ref: event.execution_ref,
      event_type: event.event_type,
      confidence: event.confidence,
      signal_count: event.signals.length,
      evidence_count: event.evidence_refs.length,
    });
  } catch {
    // Log without identity if not initialized
    console.log(JSON.stringify({
      level: 'decision_event_emitted',
      timestamp: new Date().toISOString(),
      message: `Emitted ${event.event_type} event`,
      execution_ref: event.execution_ref,
      event_type: event.event_type,
      confidence: event.confidence,
    }));
  }
}

// =============================================================================
// CONTRACT ASSERTIONS
// =============================================================================

let _decisionEventCount = 0;

/**
 * Reset decision event counter (call at start of each run)
 */
export function resetDecisionEventCounter(): void {
  _decisionEventCount = 0;
}

/**
 * Increment decision event counter (call when event is emitted)
 */
export function incrementDecisionEventCounter(): void {
  _decisionEventCount++;
}

/**
 * Assert at least one DecisionEvent was emitted
 * Call this at the end of each agent run
 */
export function assertDecisionEventEmitted(executionRef: string): void {
  if (_decisionEventCount === 0) {
    const error = new Error(`Contract violation: No DecisionEvent emitted for execution ${executionRef}`);

    try {
      const identity = getAgentIdentity();
      structuredLog('agent_abort', 'Contract violation: No DecisionEvent emitted', identity, {
        execution_ref: executionRef,
      });
    } catch {
      console.error(JSON.stringify({
        level: 'agent_abort',
        timestamp: new Date().toISOString(),
        message: 'Contract violation: No DecisionEvent emitted',
        execution_ref: executionRef,
      }));
    }

    throw error;
  }
}
