/**
 * @module startup-validator
 * @description Mandatory startup validation for LLM-Shield agents
 *
 * Phase 1 / Layer 1 - Foundational Tooling
 *
 * CRITICAL: This module MUST be imported and executed at service startup.
 * If ANY validation fails, the service MUST crash immediately.
 *
 * Required Environment Variables:
 * - RUVECTOR_SERVICE_URL: Ruvector service endpoint (from Google Secret Manager)
 * - RUVECTOR_API_KEY: Ruvector authentication key (from Google Secret Manager)
 * - AGENT_NAME: Service name identifier
 * - AGENT_DOMAIN: Agent domain (e.g., security, detection)
 * - AGENT_PHASE: Deployment phase (must be "phase1")
 * - AGENT_LAYER: Deployment layer (must be "layer1")
 */

// =============================================================================
// TYPES
// =============================================================================

export interface AgentIdentityContext {
  agent_name: string;
  domain: string;
  phase: string;
  layer: string;
}

export interface StartupValidationResult {
  valid: boolean;
  errors: string[];
  identity: AgentIdentityContext | null;
  ruvectorHealthy: boolean;
}

export interface RuvectorHealthCheckResult {
  healthy: boolean;
  latencyMs: number;
  error?: string;
}

// =============================================================================
// CONSTANTS
// =============================================================================

const REQUIRED_ENV_VARS = [
  'RUVECTOR_SERVICE_URL',
  'RUVECTOR_API_KEY',
  'AGENT_NAME',
  'AGENT_DOMAIN',
  'AGENT_PHASE',
  'AGENT_LAYER',
] as const;

const ALLOWED_PHASES = ['phase1'] as const;
const ALLOWED_LAYERS = ['layer1'] as const;

const HEALTH_CHECK_TIMEOUT_MS = 5000;

// =============================================================================
// STRUCTURED LOGGING (MINIMAL)
// =============================================================================

type LogLevel = 'agent_started' | 'decision_event_emitted' | 'agent_abort';

interface LogEntry {
  level: LogLevel;
  timestamp: string;
  agent_name: string;
  domain: string;
  phase: string;
  layer: string;
  message: string;
  details?: Record<string, unknown>;
}

export function structuredLog(
  level: LogLevel,
  message: string,
  identity: AgentIdentityContext | null,
  details?: Record<string, unknown>
): void {
  const entry: LogEntry = {
    level,
    timestamp: new Date().toISOString(),
    agent_name: identity?.agent_name || 'unknown',
    domain: identity?.domain || 'unknown',
    phase: identity?.phase || 'unknown',
    layer: identity?.layer || 'unknown',
    message,
    ...(details && { details }),
  };

  // Output as JSON for Cloud Run log aggregation
  console.log(JSON.stringify(entry));
}

// =============================================================================
// ENVIRONMENT VALIDATION
// =============================================================================

export function validateEnvironment(): { valid: boolean; errors: string[]; identity: AgentIdentityContext | null } {
  const errors: string[] = [];

  // Check all required environment variables
  for (const envVar of REQUIRED_ENV_VARS) {
    const value = process.env[envVar];
    if (!value || value.trim() === '') {
      errors.push(`Missing required environment variable: ${envVar}`);
    }
  }

  // Validate AGENT_PHASE
  const phase = process.env.AGENT_PHASE;
  if (phase && !ALLOWED_PHASES.includes(phase as typeof ALLOWED_PHASES[number])) {
    errors.push(`Invalid AGENT_PHASE: "${phase}". Must be one of: ${ALLOWED_PHASES.join(', ')}`);
  }

  // Validate AGENT_LAYER
  const layer = process.env.AGENT_LAYER;
  if (layer && !ALLOWED_LAYERS.includes(layer as typeof ALLOWED_LAYERS[number])) {
    errors.push(`Invalid AGENT_LAYER: "${layer}". Must be one of: ${ALLOWED_LAYERS.join(', ')}`);
  }

  // Validate RUVECTOR_SERVICE_URL format
  const ruvectorUrl = process.env.RUVECTOR_SERVICE_URL;
  if (ruvectorUrl) {
    try {
      new URL(ruvectorUrl);
    } catch {
      errors.push(`Invalid RUVECTOR_SERVICE_URL format: "${ruvectorUrl}"`);
    }
  }

  const identity: AgentIdentityContext | null = errors.length === 0 ? {
    agent_name: process.env.AGENT_NAME!,
    domain: process.env.AGENT_DOMAIN!,
    phase: process.env.AGENT_PHASE!,
    layer: process.env.AGENT_LAYER!,
  } : null;

  return { valid: errors.length === 0, errors, identity };
}

// =============================================================================
// RUVECTOR HEALTH CHECK
// =============================================================================

export async function checkRuvectorHealth(): Promise<RuvectorHealthCheckResult> {
  const ruvectorUrl = process.env.RUVECTOR_SERVICE_URL;
  const apiKey = process.env.RUVECTOR_API_KEY;

  if (!ruvectorUrl || !apiKey) {
    return {
      healthy: false,
      latencyMs: 0,
      error: 'RUVECTOR_SERVICE_URL or RUVECTOR_API_KEY not configured',
    };
  }

  const startTime = performance.now();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), HEALTH_CHECK_TIMEOUT_MS);

    const response = await fetch(`${ruvectorUrl}/health`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Accept': 'application/json',
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    const latencyMs = Math.round(performance.now() - startTime);

    if (!response.ok) {
      return {
        healthy: false,
        latencyMs,
        error: `Ruvector health check returned ${response.status}: ${response.statusText}`,
      };
    }

    return { healthy: true, latencyMs };
  } catch (error) {
    const latencyMs = Math.round(performance.now() - startTime);
    const err = error as Error;

    if (err.name === 'AbortError') {
      return {
        healthy: false,
        latencyMs,
        error: `Ruvector health check timed out after ${HEALTH_CHECK_TIMEOUT_MS}ms`,
      };
    }

    return {
      healthy: false,
      latencyMs,
      error: `Ruvector health check failed: ${err.message}`,
    };
  }
}

// =============================================================================
// FULL STARTUP VALIDATION
// =============================================================================

export async function validateStartup(): Promise<StartupValidationResult> {
  // Step 1: Validate environment
  const envResult = validateEnvironment();

  if (!envResult.valid) {
    return {
      valid: false,
      errors: envResult.errors,
      identity: null,
      ruvectorHealthy: false,
    };
  }

  // Step 2: Check Ruvector health (CRITICAL)
  const ruvectorResult = await checkRuvectorHealth();

  if (!ruvectorResult.healthy) {
    return {
      valid: false,
      errors: [`Ruvector health check failed: ${ruvectorResult.error}`],
      identity: envResult.identity,
      ruvectorHealthy: false,
    };
  }

  return {
    valid: true,
    errors: [],
    identity: envResult.identity,
    ruvectorHealthy: true,
  };
}

// =============================================================================
// CRASH IF VALIDATION FAILS
// =============================================================================

export async function assertStartupRequirements(): Promise<AgentIdentityContext> {
  const result = await validateStartup();

  if (!result.valid) {
    // Log abort event
    structuredLog('agent_abort', 'Startup validation failed', result.identity, {
      errors: result.errors,
      ruvector_healthy: result.ruvectorHealthy,
    });

    // Print errors to stderr for debugging
    console.error('='.repeat(60));
    console.error('FATAL: STARTUP VALIDATION FAILED');
    console.error('='.repeat(60));
    for (const error of result.errors) {
      console.error(`  - ${error}`);
    }
    console.error('='.repeat(60));
    console.error('Service cannot start without valid configuration.');
    console.error('Ensure all required secrets are configured in Google Secret Manager.');
    console.error('='.repeat(60));

    // CRITICAL: Crash the container
    process.exit(1);
  }

  // Log successful startup
  structuredLog('agent_started', 'Service started successfully', result.identity, {
    ruvector_latency_ms: 'healthy',
  });

  return result.identity!;
}

// =============================================================================
// EXPORT IDENTITY GETTER (for use after validation)
// =============================================================================

let _cachedIdentity: AgentIdentityContext | null = null;

export function getAgentIdentity(): AgentIdentityContext {
  if (_cachedIdentity) {
    return _cachedIdentity;
  }

  // Fallback for cases where assertStartupRequirements wasn't called
  const envResult = validateEnvironment();
  if (!envResult.valid || !envResult.identity) {
    throw new Error('Agent identity not initialized. Call assertStartupRequirements() first.');
  }

  _cachedIdentity = envResult.identity;
  return _cachedIdentity;
}

export function setAgentIdentity(identity: AgentIdentityContext): void {
  _cachedIdentity = identity;
}
