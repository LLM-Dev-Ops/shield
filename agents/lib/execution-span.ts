/**
 * @module execution-span
 * @description Execution span management for the Agentics Foundational Execution Unit
 *
 * This module implements the span lifecycle for LLM-Shield's participation
 * in the Agentics hierarchical ExecutionGraph.
 *
 * Invariant: Core -> Repo (llm-shield) -> Agent (one or more)
 *
 * RULES:
 * - Every external invocation MUST provide execution_id and parent_span_id
 * - A repo-level span MUST be created on entry
 * - An agent-level span MUST be created for every agent that executes
 * - Artifacts MUST be attached to agent-level spans, never directly to Core
 * - Execution is INVALID if no agent-level spans exist
 * - All spans are append-only and causally ordered via parent_span_id
 */

import { randomUUID } from 'crypto';

// =============================================================================
// TYPES
// =============================================================================

/** Span type discriminator within the Agentics hierarchy */
export type SpanType = 'core' | 'repo' | 'agent';

/** Status of span execution */
export type SpanStatus = 'running' | 'completed' | 'error';

/** An artifact or evidence attached to a span */
export interface SpanArtifact {
  /** Stable reference identifier */
  artifact_id: string;
  /** Classification of the artifact */
  artifact_type: 'detection_signal' | 'evidence_ref' | 'decision_event' | 'metric';
  /** Machine-verifiable data payload */
  data: Record<string, unknown>;
  /** ISO 8601 timestamp of when the artifact was produced */
  timestamp: string;
}

/** Execution context passed inward from the Agentics Core */
export interface ExecutionContext {
  /** UUID identifying the full execution tree */
  execution_id: string;
  /** Span ID of the parent (from the Core) - REQUIRED for all external calls */
  parent_span_id: string;
}

/** A single execution span in the hierarchy */
export interface ExecutionSpan {
  /** Unique identifier for this span */
  span_id: string;
  /** Position in the hierarchy */
  span_type: SpanType;
  /** ID of the parent span (establishes causal ordering) */
  parent_span_id: string;
  /** ID of the execution tree this span belongs to */
  execution_id: string;
  /** Human-readable name */
  name: string;
  /** Type-specific attributes (repo_name, agent_name, agent_key, etc.) */
  attributes: Record<string, string>;
  /** ISO 8601 start timestamp */
  start_time: string;
  /** ISO 8601 end timestamp (null if still running) */
  end_time: string | null;
  /** Current status */
  status: SpanStatus;
  /** Duration in milliseconds (null if still running) */
  duration_ms: number | null;
  /** Artifacts and evidence attached to this span */
  artifacts: SpanArtifact[];
  /** Child spans (agent spans nested under repo span) */
  children: ExecutionSpan[];
}

/** The complete execution output envelope */
export interface ExecutionOutput {
  /** Execution tree identifier */
  execution_id: string;
  /** Root repo-level span with nested agent spans */
  repo_span: ExecutionSpan;
}

// =============================================================================
// VALIDATION
// =============================================================================

/**
 * Validate that an incoming execution context has the required fields.
 * Throws if execution_id or parent_span_id is missing or empty.
 */
export function validateExecutionContext(ctx: unknown): ExecutionContext {
  if (!ctx || typeof ctx !== 'object') {
    throw new Error('Execution context is required: parent_span_id is missing');
  }

  const obj = ctx as Record<string, unknown>;

  const execution_id = typeof obj.execution_id === 'string' ? obj.execution_id.trim() : '';
  const parent_span_id = typeof obj.parent_span_id === 'string' ? obj.parent_span_id.trim() : '';

  if (!execution_id) {
    throw new Error('Execution context is required: execution_id is missing or empty');
  }

  if (!parent_span_id) {
    throw new Error('Execution context is required: parent_span_id is missing or empty');
  }

  return { execution_id, parent_span_id };
}

// =============================================================================
// SPAN LIFECYCLE
// =============================================================================

/**
 * Create the repo-level execution span.
 * This is the first span created on entry to this repository.
 */
export function createRepoSpan(ctx: ExecutionContext): ExecutionSpan {
  return {
    span_id: randomUUID(),
    span_type: 'repo',
    parent_span_id: ctx.parent_span_id,
    execution_id: ctx.execution_id,
    name: 'llm-shield',
    attributes: { repo_name: 'llm-shield' },
    start_time: new Date().toISOString(),
    end_time: null,
    status: 'running',
    duration_ms: null,
    artifacts: [],
    children: [],
  };
}

/**
 * Create an agent-level execution span as a child of the repo span.
 * Each agent that executes logic MUST have its own span.
 */
export function createAgentSpan(
  repoSpan: ExecutionSpan,
  agentName: string,
  agentKey: string,
): ExecutionSpan {
  const span: ExecutionSpan = {
    span_id: randomUUID(),
    span_type: 'agent',
    parent_span_id: repoSpan.span_id,
    execution_id: repoSpan.execution_id,
    name: agentName,
    attributes: {
      agent_name: agentName,
      agent_key: agentKey,
      repo_name: 'llm-shield',
    },
    start_time: new Date().toISOString(),
    end_time: null,
    status: 'running',
    duration_ms: null,
    artifacts: [],
    children: [],
  };

  repoSpan.children.push(span);
  return span;
}

/**
 * Attach a machine-verifiable artifact to a span.
 * Artifacts MUST be attached to agent-level spans, not the Core span.
 */
export function attachArtifact(
  span: ExecutionSpan,
  artifactType: SpanArtifact['artifact_type'],
  data: Record<string, unknown>,
): void {
  span.artifacts.push({
    artifact_id: randomUUID(),
    artifact_type: artifactType,
    data,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Mark a span as successfully completed.
 */
export function completeSpan(span: ExecutionSpan): void {
  const endTime = new Date();
  span.end_time = endTime.toISOString();
  span.status = 'completed';
  span.duration_ms = endTime.getTime() - new Date(span.start_time).getTime();
}

/**
 * Mark a span as failed with an explicit reason.
 * Failed spans still appear in the output -- execution is never silent.
 */
export function failSpan(span: ExecutionSpan, error: string): void {
  const endTime = new Date();
  span.end_time = endTime.toISOString();
  span.status = 'error';
  span.duration_ms = endTime.getTime() - new Date(span.start_time).getTime();
  span.artifacts.push({
    artifact_id: randomUUID(),
    artifact_type: 'metric',
    data: { error_reason: error },
    timestamp: endTime.toISOString(),
  });
}

/**
 * Finalize the repo span and produce the execution output.
 *
 * INVARIANT: Throws if no agent-level spans exist.
 * If no agent span exists, execution is INVALID.
 */
export function finalizeRepoSpan(repoSpan: ExecutionSpan): ExecutionOutput {
  if (repoSpan.children.length === 0) {
    throw new Error(
      'Execution invariant violated: no agent-level spans were emitted. '
      + 'This repository MUST NOT return a successful result without agent spans.',
    );
  }

  if (repoSpan.status === 'running') {
    completeSpan(repoSpan);
  }

  return {
    execution_id: repoSpan.execution_id,
    repo_span: repoSpan,
  };
}

/**
 * Validate that a finalized execution output meets all invariants.
 *
 * Checks:
 * - repo_span exists and has type 'repo'
 * - At least one child span exists
 * - All children have type 'agent'
 * - All spans are JSON-serializable
 */
export function validateExecutionOutput(output: ExecutionOutput): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!output.execution_id) {
    errors.push('Missing execution_id');
  }

  if (!output.repo_span) {
    errors.push('Missing repo_span');
    return { valid: false, errors };
  }

  if (output.repo_span.span_type !== 'repo') {
    errors.push(`repo_span has wrong type: ${output.repo_span.span_type} (expected: repo)`);
  }

  if (output.repo_span.children.length === 0) {
    errors.push('repo_span has no agent children -- execution is INVALID');
  }

  for (const child of output.repo_span.children) {
    if (child.span_type !== 'agent') {
      errors.push(`Child span "${child.name}" has wrong type: ${child.span_type} (expected: agent)`);
    }
    if (child.parent_span_id !== output.repo_span.span_id) {
      errors.push(`Child span "${child.name}" has wrong parent_span_id`);
    }
    if (child.execution_id !== output.execution_id) {
      errors.push(`Child span "${child.name}" has wrong execution_id`);
    }
  }

  // Verify JSON-serializability
  try {
    JSON.stringify(output);
  } catch {
    errors.push('Output is not JSON-serializable');
  }

  return { valid: errors.length === 0, errors };
}
