/**
 * @module llm-shield-service
 * @description Unified LLM-Shield Service - Google Cloud Run Entry Point
 *
 * Phase 1 / Layer 1 - Foundational Tooling
 *
 * HARDENING REQUIREMENTS IMPLEMENTED:
 * 1. Mandatory startup validation (env vars, Ruvector health)
 * 2. Agent identity standardization (source_agent, domain, phase, layer)
 * 3. Performance boundaries (MAX_TOKENS, MAX_LATENCY_MS, MAX_CALLS_PER_RUN)
 * 4. Read-only caching (TTL 30-60s)
 * 5. Minimal observability (agent_started, decision_event_emitted, agent_abort)
 * 6. Contract assertions (Ruvector required, ≥1 DecisionEvent per run)
 *
 * CRITICAL:
 * - Ruvector is REQUIRED - service crashes if unavailable
 * - All secrets from Google Secret Manager (no inline secrets)
 * - Startup failures crash the container immediately
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { randomUUID } from 'crypto';
import { URL } from 'url';
import {
  assertStartupRequirements,
  getAgentIdentity,
  structuredLog,
  type AgentIdentityContext,
  PerformanceTracker,
  PERFORMANCE_LIMITS,
  checkTokenLimit,
  PerformanceBoundaryError,
  startCacheCleanup,
  stopCacheCleanup,
  ruvectorHealthCache,
  getOrCompute,
  createCacheKey,
  validateExecutionContext,
  createRepoSpan,
  createAgentSpan,
  attachArtifact,
  completeSpan,
  failSpan,
  finalizeRepoSpan,
  type ExecutionContext,
  type ExecutionSpan,
  type ExecutionOutput,
} from '@llm-shield/lib';

// =============================================================================
// SERVICE CONFIGURATION
// =============================================================================

const SERVICE_NAME = process.env.SERVICE_NAME || process.env.AGENT_NAME || 'llm-shield';
const SERVICE_VERSION = process.env.SERVICE_VERSION || '1.0.0';
const PORT = parseInt(process.env.PORT || '8080', 10);
const HOST = process.env.HOST || '0.0.0.0';

// =============================================================================
// EDGE REQUEST/RESPONSE INTERFACES
// =============================================================================

interface EdgeRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: unknown;
  json(): Promise<unknown>;
  performanceTracker?: PerformanceTracker;
}

interface EdgeResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

type EdgeHandler = (request: EdgeRequest) => Promise<EdgeResponse>;

// =============================================================================
// DYNAMIC HANDLER LOADING
// =============================================================================

/**
 * Dynamically load and adapt handlers from each agent
 * This avoids import-time errors and handles different handler signatures
 */
async function loadHandlers(): Promise<Map<string, EdgeHandler>> {
  const handlers = new Map<string, EdgeHandler>();

  // 1. Prompt Injection Detection - exports { handler }
  try {
    const mod = await import('../../prompt-injection-detection/dist/handler.js');
    handlers.set('prompt-injection', wrapHandler(mod.handler, 'prompt-injection'));
    console.log(`[${SERVICE_NAME}] Loaded: prompt-injection-detection`);
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load prompt-injection-detection:`, e);
  }

  // 2. PII Detection - exports class, need to adapt
  try {
    const mod = await import('../../pii-detection/dist/agent.js');
    const agent = new mod.PIIDetectionAgent({
      ruvectorServiceUrl: process.env.RUVECTOR_SERVICE_URL,
      telemetryEndpoint: process.env.TELEMETRY_ENDPOINT,
    });
    handlers.set('pii', wrapHandler(async (req: EdgeRequest): Promise<EdgeResponse> => {
      const input = await req.json();
      const result = await agent.detect(input as any);
      return { status: 200, headers: { 'Content-Type': 'application/json' }, body: result };
    }, 'pii'));
    console.log(`[${SERVICE_NAME}] Loaded: pii-detection`);
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load pii-detection:`, e);
  }

  // 3. Data Redaction - exports handleRequest
  try {
    const mod = await import('../../data-redaction/dist/index.js');
    handlers.set('redaction', wrapHandler(async (req: EdgeRequest): Promise<EdgeResponse> => {
      const input = await req.json();
      const request = new Request('http://localhost', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
      const response = await mod.handleRequest(request);
      const body = await response.json();
      return { status: response.status, headers: { 'Content-Type': 'application/json' }, body };
    }, 'redaction'));
    console.log(`[${SERVICE_NAME}] Loaded: data-redaction`);
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load data-redaction:`, e);
  }

  // 4. Secrets Leakage Detection - exports handleDetection
  try {
    const mod = await import('../../secrets-leakage-detection/dist/handler.js');
    handlers.set('secrets', wrapHandler(async (req: EdgeRequest): Promise<EdgeResponse> => {
      const input = await req.json();
      const result = await mod.handleDetection(input);
      return { status: 200, headers: { 'Content-Type': 'application/json' }, body: result };
    }, 'secrets'));
    console.log(`[${SERVICE_NAME}] Loaded: secrets-leakage-detection`);
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load secrets-leakage-detection:`, e);
  }

  // 5. Toxicity Detection - exports class
  try {
    const mod = await import('../../toxicity-detection/dist/agent.js');
    const agent = new mod.ToxicityDetectionAgent({
      ruvectorServiceUrl: process.env.RUVECTOR_SERVICE_URL,
      telemetryEndpoint: process.env.TELEMETRY_ENDPOINT,
    });
    handlers.set('toxicity', wrapHandler(async (req: EdgeRequest): Promise<EdgeResponse> => {
      const input = await req.json();
      const result = await agent.detect(input as any);
      return { status: 200, headers: { 'Content-Type': 'application/json' }, body: result };
    }, 'toxicity'));
    console.log(`[${SERVICE_NAME}] Loaded: toxicity-detection`);
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load toxicity-detection:`, e);
  }

  // 6. Safety Boundary - exports { handler }
  try {
    const mod = await import('../../safety-boundary/dist/handler.js');
    handlers.set('safety', wrapHandler(mod.handler, 'safety'));
    console.log(`[${SERVICE_NAME}] Loaded: safety-boundary`);
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load safety-boundary:`, e);
  }

  // 7. Content Moderation - exports { handler }
  try {
    const mod = await import('../../content-moderation/dist/handler.js');
    handlers.set('moderation', wrapHandler(mod.handler, 'moderation'));
    console.log(`[${SERVICE_NAME}] Loaded: content-moderation`);
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load content-moderation:`, e);
  }

  // 8. Model Abuse Detection - exports handleDetection
  try {
    const mod = await import('../../model-abuse-detection/dist/handler.js');
    handlers.set('abuse', wrapHandler(async (req: EdgeRequest): Promise<EdgeResponse> => {
      const input = await req.json();
      const result = await mod.handleDetection(input);
      return { status: 200, headers: { 'Content-Type': 'application/json' }, body: result };
    }, 'abuse'));
    console.log(`[${SERVICE_NAME}] Loaded: model-abuse-detection`);
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load model-abuse-detection:`, e);
  }

  // 9. Credential Exposure Detection - exports handleDetection
  try {
    const mod = await import('../../credential-exposure-detection/dist/handler.js');
    handlers.set('credentials', wrapHandler(async (req: EdgeRequest): Promise<EdgeResponse> => {
      const input = await req.json();
      const result = await mod.handleDetection(input);
      return { status: 200, headers: { 'Content-Type': 'application/json' }, body: result };
    }, 'credentials'));
    console.log(`[${SERVICE_NAME}] Loaded: credential-exposure-detection`);
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load credential-exposure-detection:`, e);
  }

  return handlers;
}

/**
 * Wrap handler with performance boundaries
 */
function wrapHandler(handler: EdgeHandler, agentKey: string): EdgeHandler {
  return async (req: EdgeRequest): Promise<EdgeResponse> => {
    const executionRef = `${agentKey}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const tracker = new PerformanceTracker(executionRef);

    try {
      // Check token limit if body contains content
      if (req.body && typeof req.body === 'object') {
        const body = req.body as Record<string, unknown>;
        if (typeof body.content === 'string') {
          const tokenCheck = checkTokenLimit(body.content);
          if (!tokenCheck.valid) {
            tracker.trackTokens(tokenCheck.tokenCount); // Will throw
          }
        }
      }

      // Execute handler
      const result = await handler({ ...req, performanceTracker: tracker });

      // Check latency
      tracker.checkLatency();

      return result;
    } catch (error) {
      if (error instanceof PerformanceBoundaryError) {
        return {
          status: 429,
          headers: { 'Content-Type': 'application/json' },
          body: {
            error: 'Performance Boundary Exceeded',
            type: error.violation.type,
            limit: error.violation.limit,
            actual: error.violation.actual,
            message: error.violation.message,
          },
        };
      }
      throw error;
    }
  };
}

// =============================================================================
// AGENT REGISTRY
// =============================================================================

interface AgentEndpoint {
  name: string;
  path: string;
  key: string;
  description: string;
  classification: 'DETECTION_ONLY' | 'REDACTION' | 'ENFORCEMENT';
}

const AGENT_REGISTRY: AgentEndpoint[] = [
  { name: 'prompt-injection-detection', path: '/agents/prompt-injection', key: 'prompt-injection', description: 'Detects prompt injection attempts', classification: 'DETECTION_ONLY' },
  { name: 'pii-detection', path: '/agents/pii', key: 'pii', description: 'Detects personally identifiable information', classification: 'DETECTION_ONLY' },
  { name: 'data-redaction', path: '/agents/redaction', key: 'redaction', description: 'Redacts sensitive data', classification: 'REDACTION' },
  { name: 'secrets-leakage-detection', path: '/agents/secrets', key: 'secrets', description: 'Detects API keys and secrets', classification: 'DETECTION_ONLY' },
  { name: 'toxicity-detection', path: '/agents/toxicity', key: 'toxicity', description: 'Detects toxic content', classification: 'DETECTION_ONLY' },
  { name: 'safety-boundary', path: '/agents/safety', key: 'safety', description: 'Enforces safety boundaries', classification: 'ENFORCEMENT' },
  { name: 'content-moderation', path: '/agents/moderation', key: 'moderation', description: 'Content moderation', classification: 'ENFORCEMENT' },
  { name: 'model-abuse-detection', path: '/agents/abuse', key: 'abuse', description: 'Detects model abuse', classification: 'DETECTION_ONLY' },
  { name: 'credential-exposure-detection', path: '/agents/credentials', key: 'credentials', description: 'Detects exposed credentials', classification: 'DETECTION_ONLY' },
];

// =============================================================================
// HTTP SERVER
// =============================================================================

async function parseBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      try {
        const body = Buffer.concat(chunks).toString();
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

async function toEdgeRequest(req: IncomingMessage, parsedUrl: URL): Promise<EdgeRequest> {
  const body = await parseBody(req);
  return toEdgeRequestFromBody(req, parsedUrl, body);
}

function toEdgeRequestFromBody(req: IncomingMessage, parsedUrl: URL, body: unknown): EdgeRequest {
  const headers: Record<string, string> = {};

  for (const [key, value] of Object.entries(req.headers)) {
    if (typeof value === 'string') {
      headers[key] = value;
    } else if (Array.isArray(value)) {
      headers[key] = value[0];
    }
  }

  return {
    method: req.method || 'GET',
    url: parsedUrl.pathname + parsedUrl.search,
    headers,
    body,
    json: async () => body,
  };
}

function sendJson(res: ServerResponse, data: unknown, status = 200, headers: Record<string, string> = {}): void {
  let identity: AgentIdentityContext | null = null;
  try {
    identity = getAgentIdentity();
  } catch {
    // Identity not available yet
  }

  res.writeHead(status, {
    'Content-Type': 'application/json',
    'X-Service-Name': SERVICE_NAME,
    'X-Service-Version': SERVICE_VERSION,
    ...(identity && {
      'X-Agent-Domain': identity.domain,
      'X-Agent-Phase': identity.phase,
      'X-Agent-Layer': identity.layer,
    }),
    ...headers,
  });
  res.end(JSON.stringify(data));
}

// =============================================================================
// CALLER TOKEN VALIDATION (LLM-Security-Core Gateway Enforcement)
// =============================================================================

interface CallerTokenFields {
  caller_id: string;
  signature: string;
  issued_at: string;
}

/**
 * Extract caller token from request body or headers.
 *
 * When GATEWAY_SHARED_SECRET is configured, all agent dispatch requests
 * must include a valid caller token. This ensures LLM-Shield is only
 * invoked via LLM-Security-Core.
 *
 * Headers: x-caller-id, x-caller-signature, x-caller-issued-at
 * Body fields: caller_id, caller_signature, caller_issued_at
 */
function extractCallerToken(
  body: unknown,
  headers: Record<string, string>,
): CallerTokenFields | null {
  const bodyObj = body && typeof body === 'object' ? body as Record<string, unknown> : {};

  const caller_id =
    (typeof bodyObj.caller_id === 'string' ? bodyObj.caller_id : '') ||
    headers['x-caller-id'] ||
    '';
  const signature =
    (typeof bodyObj.caller_signature === 'string' ? bodyObj.caller_signature : '') ||
    headers['x-caller-signature'] ||
    '';
  const issued_at =
    (typeof bodyObj.caller_issued_at === 'string' ? bodyObj.caller_issued_at : '') ||
    headers['x-caller-issued-at'] ||
    '';

  if (!caller_id || !signature || !issued_at) {
    return null;
  }

  return { caller_id, signature, issued_at };
}

/**
 * Validate a caller token's HMAC-SHA256 signature and expiry.
 *
 * @returns null if valid, error message string if invalid.
 */
function validateCallerToken(
  token: CallerTokenFields,
  sharedSecret: string,
  ttlSeconds: number = 300,
): string | null {
  // Compute expected signature: HMAC-SHA256(caller_id|issued_at, secret)
  const { createHmac, timingSafeEqual } = require('crypto');
  const payload = `${token.caller_id}|${token.issued_at}`;
  const expectedSignature: string = createHmac('sha256', sharedSecret)
    .update(payload)
    .digest('hex');

  // Constant-time comparison
  try {
    const sigBuffer = Buffer.from(token.signature, 'hex');
    const expectedBuffer = Buffer.from(expectedSignature, 'hex');
    if (sigBuffer.length !== expectedBuffer.length || !timingSafeEqual(sigBuffer, expectedBuffer)) {
      return 'Invalid caller token signature';
    }
  } catch {
    return 'Invalid caller token signature format';
  }

  // Check expiry
  const issuedAt = new Date(token.issued_at);
  if (isNaN(issuedAt.getTime())) {
    return 'Invalid issued_at timestamp';
  }

  const ageMs = Date.now() - issuedAt.getTime();
  if (ageMs > ttlSeconds * 1000) {
    return `Caller token expired (age: ${Math.round(ageMs / 1000)}s, TTL: ${ttlSeconds}s)`;
  }
  if (ageMs < -30_000) {
    return 'Caller token issued_at is in the future';
  }

  return null; // Valid
}

// =============================================================================
// EXECUTION CONTEXT EXTRACTION
// =============================================================================

/**
 * Extract execution context from request body or headers.
 *
 * The Agentics Core provides execution_id and parent_span_id.
 * These are required for all agent dispatch operations.
 * Body fields take precedence over headers.
 */
function extractExecutionContext(
  body: unknown,
  headers: Record<string, string>,
): ExecutionContext {
  const bodyObj = body && typeof body === 'object' ? body as Record<string, unknown> : {};

  const execution_id =
    (typeof bodyObj.execution_id === 'string' ? bodyObj.execution_id : '') ||
    headers['x-execution-id'] ||
    '';
  const parent_span_id =
    (typeof bodyObj.parent_span_id === 'string' ? bodyObj.parent_span_id : '') ||
    headers['x-parent-span-id'] ||
    '';

  return validateExecutionContext({ execution_id, parent_span_id });
}

// =============================================================================
// REQUEST HANDLERS
// =============================================================================

async function handleHealth(res: ServerResponse, handlers: Map<string, EdgeHandler>): Promise<void> {
  // Check Ruvector health with caching
  const ruvectorHealthy = await getOrCompute(
    ruvectorHealthCache,
    createCacheKey('ruvector', 'health'),
    async () => {
      try {
        const response = await fetch(`${process.env.RUVECTOR_SERVICE_URL}/health`, {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${process.env.RUVECTOR_API_KEY}` },
          signal: AbortSignal.timeout(2000),
        });
        return response.ok;
      } catch {
        return false;
      }
    }
  );

  let identity: AgentIdentityContext | null = null;
  try {
    identity = getAgentIdentity();
  } catch {
    // Identity not available
  }

  sendJson(res, {
    status: ruvectorHealthy ? 'healthy' : 'degraded',
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    timestamp: new Date().toISOString(),
    identity: identity ? {
      agent_name: identity.agent_name,
      domain: identity.domain,
      phase: identity.phase,
      layer: identity.layer,
    } : null,
    environment: process.env.PLATFORM_ENV || 'development',
    agents_loaded: handlers.size,
    ruvector_required: true,
    ruvector_healthy: ruvectorHealthy,
    performance_limits: PERFORMANCE_LIMITS,
    agents: AGENT_REGISTRY.map(a => ({
      name: a.name,
      path: a.path,
      loaded: handlers.has(a.key),
      classification: a.classification,
    })),
  });
}

function handleInfo(res: ServerResponse, handlers: Map<string, EdgeHandler>): void {
  let identity: AgentIdentityContext | null = null;
  try {
    identity = getAgentIdentity();
  } catch {
    // Identity not available
  }

  sendJson(res, {
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    description: 'LLM-Shield Unified Security Service - Phase 1 / Layer 1',
    identity: identity ? {
      agent_name: identity.agent_name,
      domain: identity.domain,
      phase: identity.phase,
      layer: identity.layer,
    } : null,
    environment: process.env.PLATFORM_ENV || 'development',
    hardening: {
      ruvector_required: true,
      performance_limits: PERFORMANCE_LIMITS,
      caching_enabled: true,
      cache_ttl_seconds: 30,
    },
    agents: AGENT_REGISTRY.map(a => ({
      name: a.name,
      path: a.path,
      description: a.description,
      classification: a.classification,
      loaded: handlers.has(a.key),
      endpoints: [
        { method: 'POST', path: `${a.path}/detect`, description: 'Execute detection' },
        { method: 'GET', path: `${a.path}/health`, description: 'Agent health' },
      ],
    })),
    integration: {
      ruvector_service: process.env.RUVECTOR_SERVICE_URL ? 'configured' : 'not configured',
      telemetry_endpoint: process.env.TELEMETRY_ENDPOINT ? 'configured' : 'not configured',
    },
  });
}

async function handleReady(res: ServerResponse, handlers: Map<string, EdgeHandler>): Promise<void> {
  const isReady = handlers.size > 0;

  // Also check Ruvector for full readiness
  const ruvectorHealthy = await getOrCompute(
    ruvectorHealthCache,
    createCacheKey('ruvector', 'health'),
    async () => {
      try {
        const response = await fetch(`${process.env.RUVECTOR_SERVICE_URL}/health`, {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${process.env.RUVECTOR_API_KEY}` },
          signal: AbortSignal.timeout(2000),
        });
        return response.ok;
      } catch {
        return false;
      }
    }
  );

  if (isReady && ruvectorHealthy) {
    sendJson(res, {
      ready: true,
      agents_loaded: handlers.size,
      ruvector_healthy: true,
      timestamp: new Date().toISOString(),
    });
  } else {
    sendJson(res, {
      ready: false,
      reason: !isReady ? 'No agents loaded' : 'Ruvector not healthy',
      agents_loaded: handlers.size,
      ruvector_healthy: ruvectorHealthy,
    }, 503);
  }
}

async function routeToAgent(
  req: IncomingMessage,
  res: ServerResponse,
  parsedUrl: URL,
  handlers: Map<string, EdgeHandler>,
  repoSpan: ExecutionSpan,
  parsedBody?: unknown,
): Promise<void> {
  const path = parsedUrl.pathname;

  // Find matching agent
  const agent = AGENT_REGISTRY.find(a => path.startsWith(a.path));

  if (!agent) {
    failSpan(repoSpan, `No agent found for path: ${path}`);
    sendJson(res, {
      error: 'Not Found',
      message: `No agent found for path: ${path}`,
      available_agents: AGENT_REGISTRY.map(a => a.path),
    }, 404);
    return;
  }

  const handler = handlers.get(agent.key);
  if (!handler) {
    failSpan(repoSpan, `Agent ${agent.name} failed to load`);
    sendJson(res, {
      error: 'Agent Not Loaded',
      message: `Agent ${agent.name} failed to load`,
    }, 503);
    return;
  }

  // Create agent-level execution span
  const agentSpan = createAgentSpan(repoSpan, agent.name, agent.key);

  try {
    const subPath = path.replace(agent.path, '') || '/detect';
    const fullUrl = `http://localhost${subPath}${parsedUrl.search}`;
    const subUrl = new URL(fullUrl, 'http://localhost');
    // Use pre-parsed body if available (body already consumed for execution context extraction)
    const edgeReq = parsedBody !== undefined
      ? toEdgeRequestFromBody(req, subUrl, parsedBody)
      : await toEdgeRequest(req, subUrl);
    const edgeRes = await handler(edgeReq);

    // Attach the agent's response as an artifact to the agent span
    attachArtifact(agentSpan, 'detection_signal', {
      status: edgeRes.status,
      body: edgeRes.body as Record<string, unknown>,
    });
    completeSpan(agentSpan);

    // Finalize repo span and build execution output
    const executionOutput = finalizeRepoSpan(repoSpan);

    // Envelope the response: existing body + execution spans
    sendJson(res, {
      result: edgeRes.body,
      execution: executionOutput,
    }, edgeRes.status, edgeRes.headers);
  } catch (error) {
    // Mark agent span as failed
    failSpan(agentSpan, error instanceof Error ? error.message : 'Unknown error');

    console.error(`[${SERVICE_NAME}] Agent error (${agent.name}):`, error);

    // Log abort for performance errors
    if (error instanceof PerformanceBoundaryError) {
      try {
        const identity = getAgentIdentity();
        structuredLog('agent_abort', `Performance boundary exceeded in ${agent.name}`, identity, {
          agent: agent.name,
          violation: error.violation,
        });
      } catch {
        // Identity not available
      }
    }

    // Mark repo span as failed but still return spans
    failSpan(repoSpan, error instanceof Error ? error.message : 'Unknown error');

    // Return error response with execution spans (failed spans are still valid output)
    sendJson(res, {
      result: {
        error: 'Internal Server Error',
        message: error instanceof Error ? error.message : 'Unknown error',
        agent: agent.name,
      },
      execution: {
        execution_id: repoSpan.execution_id,
        repo_span: repoSpan,
      },
    }, 500);
  }
}

// =============================================================================
// SERVER STARTUP
// =============================================================================

async function startServer(): Promise<void> {
  // ==========================================================================
  // MANDATORY STARTUP VALIDATION
  // ==========================================================================
  // This MUST be the first thing that happens.
  // If validation fails, the service WILL crash.
  // This is intentional - Ruvector is REQUIRED.
  // ==========================================================================

  console.log(`[${SERVICE_NAME}] Starting mandatory startup validation...`);

  let identity: AgentIdentityContext;
  try {
    identity = await assertStartupRequirements();
  } catch (error) {
    // assertStartupRequirements already calls process.exit(1)
    // This catch is just for TypeScript
    console.error('Startup validation failed:', error);
    process.exit(1);
  }

  console.log(`[${SERVICE_NAME}] Startup validation passed`);
  console.log(`[${SERVICE_NAME}]   Agent: ${identity.agent_name}`);
  console.log(`[${SERVICE_NAME}]   Domain: ${identity.domain}`);
  console.log(`[${SERVICE_NAME}]   Phase: ${identity.phase}`);
  console.log(`[${SERVICE_NAME}]   Layer: ${identity.layer}`);

  // Start cache cleanup
  startCacheCleanup();

  // Load agent handlers
  console.log(`[${SERVICE_NAME}] Loading agent handlers...`);
  const handlers = await loadHandlers();
  console.log(`[${SERVICE_NAME}] Loaded ${handlers.size}/${AGENT_REGISTRY.length} agents`);

  // Create HTTP server
  const server = createServer(async (req, res) => {
    const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const path = parsedUrl.pathname;

    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Execution-Id, X-Parent-Span-Id, X-Caller-Id, X-Caller-Signature, X-Caller-Issued-At');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    try {
      switch (path) {
        case '/':
        case '/info':
          handleInfo(res, handlers);
          break;
        case '/health':
          await handleHealth(res, handlers);
          break;
        case '/ready':
        case '/readiness':
          await handleReady(res, handlers);
          break;
        case '/api/v1/scan': {
          if (req.method !== 'POST') {
            sendJson(res, { error: 'Method Not Allowed' }, 405);
            break;
          }
          const scanBody = await parseBody(req) as Record<string, unknown> | null;
          const executionId = (scanBody && typeof scanBody === 'object' && typeof (scanBody as Record<string, unknown>).execution_id === 'string')
            ? (scanBody as Record<string, unknown>).execution_id as string
            : randomUUID();

          console.log(`[${SERVICE_NAME}] Inbound scan event: execution_id=${executionId} source=${(scanBody as Record<string, unknown>)?.source ?? 'unknown'} event_type=${(scanBody as Record<string, unknown>)?.event_type ?? 'unknown'}`);

          // Process asynchronously — fire and forget
          setImmediate(() => {
            try {
              console.log(`[${SERVICE_NAME}] Processing scan event ${executionId} asynchronously`);
              // Future: dispatch scan payload to agent pipeline
            } catch (err) {
              console.error(`[${SERVICE_NAME}] Async scan processing error for ${executionId}:`, err);
            }
          });

          sendJson(res, { status: 'accepted', execution_id: executionId }, 202);
          break;
        }
        default: {
          // Agent dispatch: extract execution context and create repo span
          // parent_span_id is REQUIRED -- reject 400 if missing
          let execCtx: ExecutionContext;
          let body: unknown;
          let edgeHeaders: Record<string, string> = {};
          try {
            body = await parseBody(req);
            for (const [k, v] of Object.entries(req.headers)) {
              if (typeof v === 'string') edgeHeaders[k] = v;
              else if (Array.isArray(v)) edgeHeaders[k] = v[0];
            }
            execCtx = extractExecutionContext(body, edgeHeaders);
          } catch (ctxError) {
            sendJson(res, {
              error: 'Missing Execution Context',
              message: 'execution_id and parent_span_id are required for all agent invocations. This repository MUST NOT execute silently.',
              code: 'EXECUTION_CONTEXT_REQUIRED',
            }, 400);
            return;
          }

          // LLM-Security-Core gateway enforcement:
          // When GATEWAY_SHARED_SECRET is configured, validate caller token.
          // This ensures LLM-Shield agents are ONLY invoked via LLM-Security-Core.
          const gatewaySecret = process.env.GATEWAY_SHARED_SECRET;
          if (gatewaySecret) {
            const callerToken = extractCallerToken(body, edgeHeaders);
            if (!callerToken) {
              sendJson(res, {
                error: 'Missing Caller Token',
                message: 'A valid caller token is required for all agent invocations. '
                  + 'Provide x-caller-id, x-caller-signature, x-caller-issued-at headers. '
                  + 'Direct calls to LLM-Shield are forbidden; use LLM-Security-Core.',
                code: 'CALLER_TOKEN_REQUIRED',
              }, 401);
              return;
            }

            const tokenError = validateCallerToken(callerToken, gatewaySecret);
            if (tokenError) {
              sendJson(res, {
                error: 'Invalid Caller Token',
                message: tokenError,
                code: 'INVALID_CALLER_TOKEN',
              }, 401);
              return;
            }
          }

          const repoSpan = createRepoSpan(execCtx);
          await routeToAgent(req, res, parsedUrl, handlers, repoSpan, body);
          break;
        }
      }
    } catch (error) {
      console.error(`[${SERVICE_NAME}] Request error:`, error);
      sendJson(res, {
        error: 'Internal Server Error',
        message: error instanceof Error ? error.message : 'Unknown error',
      }, 500);
    }
  });

  server.listen(PORT, HOST, () => {
    console.log(`
╔══════════════════════════════════════════════════════════════════╗
║           LLM-SHIELD UNIFIED SERVICE (HARDENED)                  ║
╠══════════════════════════════════════════════════════════════════╣
║  Service: ${SERVICE_NAME.padEnd(53)}║
║  Version: ${SERVICE_VERSION.padEnd(53)}║
║  Domain: ${identity.domain.padEnd(54)}║
║  Phase: ${identity.phase.padEnd(55)}║
║  Layer: ${identity.layer.padEnd(55)}║
║  Environment: ${(process.env.PLATFORM_ENV || 'development').padEnd(49)}║
║  Listening: http://${HOST}:${PORT}${' '.repeat(42 - HOST.length - String(PORT).length)}║
╠══════════════════════════════════════════════════════════════════╣
║  HARDENING STATUS:                                               ║
║    ✓ Ruvector Required: YES                                      ║
║    ✓ Startup Validation: PASSED                                  ║
║    ✓ Performance Limits: ACTIVE                                  ║
║    ✓ Read-Only Caching: ENABLED                                  ║
║    ✓ Minimal Logging: ENABLED                                    ║
╠══════════════════════════════════════════════════════════════════╣
║  Performance Limits:                                             ║
║    MAX_TOKENS: ${String(PERFORMANCE_LIMITS.MAX_TOKENS).padEnd(48)}║
║    MAX_LATENCY_MS: ${String(PERFORMANCE_LIMITS.MAX_LATENCY_MS).padEnd(44)}║
║    MAX_CALLS_PER_RUN: ${String(PERFORMANCE_LIMITS.MAX_CALLS_PER_RUN).padEnd(41)}║
╠══════════════════════════════════════════════════════════════════╣
║  Agents Loaded: ${String(handlers.size).padEnd(51)}║
${AGENT_REGISTRY.map(a => `║    ${handlers.has(a.key) ? '✓' : '✗'} ${a.name.padEnd(57)}║`).join('\n')}
╚══════════════════════════════════════════════════════════════════╝
`);

    // Log agent_started event
    structuredLog('agent_started', 'LLM-Shield service started successfully', identity, {
      agents_loaded: handlers.size,
      port: PORT,
      host: HOST,
    });
  });

  // Graceful shutdown
  const shutdown = (signal: string) => {
    console.log(`[${SERVICE_NAME}] ${signal} received, shutting down...`);

    // Stop cache cleanup
    stopCacheCleanup();

    server.close(() => {
      console.log(`[${SERVICE_NAME}] Server closed`);
      process.exit(0);
    });

    // Force exit after 10s
    setTimeout(() => {
      console.error(`[${SERVICE_NAME}] Forced exit after timeout`);
      process.exit(1);
    }, 10000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

// Start if run directly
startServer().catch((error) => {
  console.error(`[${SERVICE_NAME}] Fatal error:`, error);
  process.exit(1);
});

export { startServer, AGENT_REGISTRY };
