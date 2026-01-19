/**
 * @module llm-shield-service
 * @description Unified LLM-Shield Service - Google Cloud Run Entry Point
 *
 * This is the single unified service that exposes all 9 LLM-Shield detection agents.
 * All agents are deployed as part of this ONE service - no standalone deployments.
 *
 * Architecture:
 * - Stateless HTTP service
 * - All persistence via ruvector-service (NO direct SQL access)
 * - Telemetry to LLM-Observatory
 * - Environment-based configuration
 *
 * Agents Exposed:
 * 1. Prompt Injection Detection Agent
 * 2. PII Detection Agent
 * 3. Data Redaction Agent
 * 4. Secrets Leakage Detection Agent
 * 5. Toxicity Detection Agent
 * 6. Safety Boundary Agent
 * 7. Content Moderation Agent
 * 8. Model Abuse Detection Agent
 * 9. Credential Exposure Detection Agent
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { URL } from 'url';

// =============================================================================
// SERVICE CONFIGURATION
// =============================================================================

const SERVICE_NAME = process.env.SERVICE_NAME || 'llm-shield';
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
    handlers.set('prompt-injection', mod.handler);
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
    handlers.set('pii', async (req: EdgeRequest): Promise<EdgeResponse> => {
      try {
        const input = await req.json();
        const result = await agent.detect(input as any);
        return { status: 200, headers: { 'Content-Type': 'application/json' }, body: result };
      } catch (e: any) {
        return { status: 500, headers: { 'Content-Type': 'application/json' }, body: { error: e.message } };
      }
    });
    console.log(`[${SERVICE_NAME}] Loaded: pii-detection`);
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load pii-detection:`, e);
  }

  // 3. Data Redaction - exports handleRequest
  try {
    const mod = await import('../../data-redaction/dist/index.js');
    handlers.set('redaction', async (req: EdgeRequest): Promise<EdgeResponse> => {
      try {
        const input = await req.json();
        // Create a minimal Request-like object
        const request = new Request('http://localhost', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(input),
        });
        const response = await mod.handleRequest(request);
        const body = await response.json();
        return { status: response.status, headers: { 'Content-Type': 'application/json' }, body };
      } catch (e: any) {
        return { status: 500, headers: { 'Content-Type': 'application/json' }, body: { error: e.message } };
      }
    });
    console.log(`[${SERVICE_NAME}] Loaded: data-redaction`);
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load data-redaction:`, e);
  }

  // 4. Secrets Leakage Detection - exports edgeHandler (default)
  try {
    const mod = await import('../../secrets-leakage-detection/dist/handler.js');
    const edgeHandler = mod.default || mod.edgeHandler;
    if (edgeHandler && typeof edgeHandler.detect === 'function') {
      handlers.set('secrets', async (req: EdgeRequest): Promise<EdgeResponse> => {
        try {
          const input = await req.json();
          const result = await edgeHandler.detect(input);
          return { status: 200, headers: { 'Content-Type': 'application/json' }, body: result };
        } catch (e: any) {
          return { status: 500, headers: { 'Content-Type': 'application/json' }, body: { error: e.message } };
        }
      });
      console.log(`[${SERVICE_NAME}] Loaded: secrets-leakage-detection`);
    }
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
    handlers.set('toxicity', async (req: EdgeRequest): Promise<EdgeResponse> => {
      try {
        const input = await req.json();
        const result = await agent.detect(input as any);
        return { status: 200, headers: { 'Content-Type': 'application/json' }, body: result };
      } catch (e: any) {
        return { status: 500, headers: { 'Content-Type': 'application/json' }, body: { error: e.message } };
      }
    });
    console.log(`[${SERVICE_NAME}] Loaded: toxicity-detection`);
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load toxicity-detection:`, e);
  }

  // 6. Safety Boundary - exports { handler }
  try {
    const mod = await import('../../safety-boundary/dist/handler.js');
    handlers.set('safety', mod.handler);
    console.log(`[${SERVICE_NAME}] Loaded: safety-boundary`);
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load safety-boundary:`, e);
  }

  // 7. Content Moderation - exports { handler }
  try {
    const mod = await import('../../content-moderation/dist/handler.js');
    handlers.set('moderation', mod.handler);
    console.log(`[${SERVICE_NAME}] Loaded: content-moderation`);
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load content-moderation:`, e);
  }

  // 8. Model Abuse Detection - exports edgeHandler (default)
  try {
    const mod = await import('../../model-abuse-detection/dist/handler.js');
    const edgeHandler = mod.default || mod.edgeHandler;
    if (edgeHandler && typeof edgeHandler.detect === 'function') {
      handlers.set('abuse', async (req: EdgeRequest): Promise<EdgeResponse> => {
        try {
          const input = await req.json();
          const result = await edgeHandler.detect(input);
          return { status: 200, headers: { 'Content-Type': 'application/json' }, body: result };
        } catch (e: any) {
          return { status: 500, headers: { 'Content-Type': 'application/json' }, body: { error: e.message } };
        }
      });
      console.log(`[${SERVICE_NAME}] Loaded: model-abuse-detection`);
    }
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load model-abuse-detection:`, e);
  }

  // 9. Credential Exposure Detection - exports edgeHandler (default)
  try {
    const mod = await import('../../credential-exposure-detection/dist/handler.js');
    const edgeHandler = mod.default || mod.edgeHandler;
    if (edgeHandler && typeof edgeHandler.detect === 'function') {
      handlers.set('credentials', async (req: EdgeRequest): Promise<EdgeResponse> => {
        try {
          const input = await req.json();
          const result = await edgeHandler.detect(input);
          return { status: 200, headers: { 'Content-Type': 'application/json' }, body: result };
        } catch (e: any) {
          return { status: 500, headers: { 'Content-Type': 'application/json' }, body: { error: e.message } };
        }
      });
      console.log(`[${SERVICE_NAME}] Loaded: credential-exposure-detection`);
    }
  } catch (e) {
    console.error(`[${SERVICE_NAME}] Failed to load credential-exposure-detection:`, e);
  }

  return handlers;
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
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'X-Service-Name': SERVICE_NAME,
    'X-Service-Version': SERVICE_VERSION,
    ...headers,
  });
  res.end(JSON.stringify(data));
}

// =============================================================================
// REQUEST HANDLERS
// =============================================================================

function handleHealth(res: ServerResponse, handlers: Map<string, EdgeHandler>): void {
  sendJson(res, {
    status: 'healthy',
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    timestamp: new Date().toISOString(),
    environment: process.env.PLATFORM_ENV || 'development',
    agents_loaded: handlers.size,
    agents: AGENT_REGISTRY.map(a => ({
      name: a.name,
      path: a.path,
      loaded: handlers.has(a.key),
      classification: a.classification,
    })),
  });
}

function handleInfo(res: ServerResponse, handlers: Map<string, EdgeHandler>): void {
  sendJson(res, {
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    description: 'LLM-Shield Unified Security Service',
    environment: process.env.PLATFORM_ENV || 'development',
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

function handleReady(res: ServerResponse, handlers: Map<string, EdgeHandler>): void {
  const isReady = handlers.size > 0;
  if (isReady) {
    sendJson(res, { ready: true, agents_loaded: handlers.size, timestamp: new Date().toISOString() });
  } else {
    sendJson(res, { ready: false, reason: 'No agents loaded' }, 503);
  }
}

async function routeToAgent(
  req: IncomingMessage,
  res: ServerResponse,
  parsedUrl: URL,
  handlers: Map<string, EdgeHandler>
): Promise<void> {
  const path = parsedUrl.pathname;

  // Find matching agent
  const agent = AGENT_REGISTRY.find(a => path.startsWith(a.path));

  if (!agent) {
    sendJson(res, {
      error: 'Not Found',
      message: `No agent found for path: ${path}`,
      available_agents: AGENT_REGISTRY.map(a => a.path),
    }, 404);
    return;
  }

  const handler = handlers.get(agent.key);
  if (!handler) {
    sendJson(res, {
      error: 'Agent Not Loaded',
      message: `Agent ${agent.name} failed to load`,
    }, 503);
    return;
  }

  try {
    const subPath = path.replace(agent.path, '') || '/detect';
    const fullUrl = `http://localhost${subPath}${parsedUrl.search}`;
    const edgeReq = await toEdgeRequest(req, new URL(fullUrl, 'http://localhost'));
    const edgeRes = await handler(edgeReq);
    sendJson(res, edgeRes.body, edgeRes.status, edgeRes.headers);
  } catch (error) {
    console.error(`[${SERVICE_NAME}] Agent error (${agent.name}):`, error);
    sendJson(res, {
      error: 'Internal Server Error',
      message: error instanceof Error ? error.message : 'Unknown error',
      agent: agent.name,
    }, 500);
  }
}

// =============================================================================
// SERVER STARTUP
// =============================================================================

async function startServer(): Promise<void> {
  console.log(`[${SERVICE_NAME}] Loading agent handlers...`);
  const handlers = await loadHandlers();
  console.log(`[${SERVICE_NAME}] Loaded ${handlers.size}/${AGENT_REGISTRY.length} agents`);

  const server = createServer(async (req, res) => {
    const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const path = parsedUrl.pathname;

    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

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
          handleHealth(res, handlers);
          break;
        case '/ready':
        case '/readiness':
          handleReady(res, handlers);
          break;
        default:
          await routeToAgent(req, res, parsedUrl, handlers);
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
║                    LLM-SHIELD UNIFIED SERVICE                    ║
╠══════════════════════════════════════════════════════════════════╣
║  Service: ${SERVICE_NAME.padEnd(53)}║
║  Version: ${SERVICE_VERSION.padEnd(53)}║
║  Environment: ${(process.env.PLATFORM_ENV || 'development').padEnd(49)}║
║  Listening: http://${HOST}:${PORT}${' '.repeat(42 - HOST.length - String(PORT).length)}║
╠══════════════════════════════════════════════════════════════════╣
║  Agents Loaded: ${String(handlers.size).padEnd(51)}║
${AGENT_REGISTRY.map(a => `║    ${handlers.has(a.key) ? '✓' : '✗'} ${a.name.padEnd(57)}║`).join('\n')}
╚══════════════════════════════════════════════════════════════════╝
`);
  });

  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log(`[${SERVICE_NAME}] SIGTERM received, shutting down...`);
    server.close(() => {
      console.log(`[${SERVICE_NAME}] Server closed`);
      process.exit(0);
    });
  });

  process.on('SIGINT', () => {
    console.log(`[${SERVICE_NAME}] SIGINT received, shutting down...`);
    server.close(() => {
      console.log(`[${SERVICE_NAME}] Server closed`);
      process.exit(0);
    });
  });
}

// Start if run directly
startServer().catch((error) => {
  console.error(`[${SERVICE_NAME}] Fatal error:`, error);
  process.exit(1);
});

export { startServer, AGENT_REGISTRY };
