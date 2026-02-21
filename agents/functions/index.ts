/**
 * @module shield-agents
 * @description Cloud Function entry point for LLM-Shield agents.
 *
 * Domain: shield
 * Cloud Function: shield-agents
 * Deployed to: https://us-central1-agentics-dev.cloudfunctions.net/shield-agents
 *
 * Entry point: `api` (Express app)
 *
 * Routes:
 *   POST /v1/shield/prompt-injection
 *   POST /v1/shield/pii
 *   POST /v1/shield/redaction
 *   POST /v1/shield/secrets
 *   POST /v1/shield/toxicity
 *   POST /v1/shield/safety-boundary
 *   POST /v1/shield/moderation
 *   POST /v1/shield/abuse
 *   POST /v1/shield/credential-exposure
 *   GET  /health
 */

import express, { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';

// =============================================================================
// AGENT REGISTRY
// =============================================================================

interface AgentEntry {
  route: string;
  name: string;
  description: string;
  /** Factory that returns an async handler: (payload, context) => result */
  load: () => Promise<AgentHandler>;
}

type AgentHandler = (payload: unknown, context: unknown) => Promise<unknown>;

const AGENT_REGISTRY: AgentEntry[] = [
  {
    route: 'prompt-injection',
    name: 'Prompt Injection Detection',
    description: 'Detects prompt injection attempts in LLM input content',
    load: async () => {
      const mod = await import('../prompt-injection-detection/dist/agent.js');
      const agent = mod.createAgent();
      return async (payload: any, context: any) => {
        const input = {
          content: payload?.content ?? '',
          context: {
            execution_ref: context?.execution_ref ?? randomUUID(),
            timestamp: new Date().toISOString(),
            content_source: context?.content_source ?? 'user_input',
            ...context,
          },
          sensitivity: payload?.sensitivity,
          detect_categories: payload?.detect_categories,
        };
        const validated = agent.validateInput(input);
        return agent.detect(validated);
      };
    },
  },
  {
    route: 'pii',
    name: 'PII Detection',
    description: 'Detects personally identifiable information',
    load: async () => {
      const mod = await import('../pii-detection/dist/agent.js');
      const agent = new mod.PIIDetectionAgent({});
      return async (payload: any, _context: any) => agent.detect(payload);
    },
  },
  {
    route: 'redaction',
    name: 'Data Redaction',
    description: 'Redacts sensitive data from content',
    load: async () => {
      const mod = await import('../data-redaction/dist/index.js');
      const agent = new mod.DataRedactionAgent();
      return async (payload: any, context: any) => {
        const input = {
          content: payload?.content ?? '',
          context: {
            execution_ref: context?.execution_ref ?? randomUUID(),
            timestamp: new Date().toISOString(),
            content_source: context?.content_source ?? 'user_input',
            ...context,
          },
          sensitivity: payload?.sensitivity ?? 0.7,
          redaction_strategy: payload?.redaction_strategy,
          pii_types: payload?.pii_types,
          secret_types: payload?.secret_types,
          detect_pii: payload?.detect_pii ?? true,
          detect_secrets: payload?.detect_secrets ?? true,
          detect_credentials: payload?.detect_credentials ?? true,
          min_confidence_threshold: payload?.min_confidence_threshold ?? 0.8,
          return_redacted_content: payload?.return_redacted_content ?? true,
          partial_mask_chars: payload?.partial_mask_chars ?? 4,
        };
        return agent.process(input);
      };
    },
  },
  {
    route: 'secrets',
    name: 'Secrets Leakage',
    description: 'Detects API keys and secrets leakage',
    load: async () => {
      const mod = await import('../secrets-leakage-detection/dist/handler.js');
      return async (payload: any, _context: any) => mod.handleDetection(payload);
    },
  },
  {
    route: 'toxicity',
    name: 'Toxicity Detection',
    description: 'Detects toxic content',
    load: async () => {
      const mod = await import('../toxicity-detection/dist/agent.js');
      const agent = new mod.ToxicityDetectionAgent({});
      return async (payload: any, _context: any) => agent.detect(payload);
    },
  },
  {
    route: 'safety-boundary',
    name: 'Safety Boundary',
    description: 'Enforces safety boundaries',
    load: async () => {
      const mod = await import('../safety-boundary/dist/handler.js');
      return async (payload: any, _context: any) => {
        const edgeReq = {
          method: 'POST',
          url: '/detect',
          headers: { 'content-type': 'application/json' },
          body: payload,
          json: async () => payload,
        };
        const res = await mod.handler(edgeReq);
        return res.body;
      };
    },
  },
  {
    route: 'moderation',
    name: 'Content Moderation',
    description: 'Content moderation enforcement',
    load: async () => {
      const mod = await import('../content-moderation/dist/handler.js');
      return async (payload: any, _context: any) => {
        const edgeReq = {
          method: 'POST',
          url: '/detect',
          headers: { 'content-type': 'application/json' },
          body: payload,
          json: async () => payload,
        };
        const res = await mod.handler(edgeReq);
        return res.body;
      };
    },
  },
  {
    route: 'abuse',
    name: 'Model Abuse Detection',
    description: 'Detects model abuse patterns',
    load: async () => {
      const mod = await import('../model-abuse-detection/dist/handler.js');
      return async (payload: any, _context: any) => mod.handleDetection(payload);
    },
  },
  {
    route: 'credential-exposure',
    name: 'Credential Exposure',
    description: 'Detects exposed credentials',
    load: async () => {
      const mod = await import('../credential-exposure-detection/dist/handler.js');
      return async (payload: any, _context: any) => mod.handleDetection(payload);
    },
  },
];

// =============================================================================
// LAZY HANDLER CACHE
// =============================================================================

const handlerCache = new Map<string, AgentHandler>();

async function getHandler(entry: AgentEntry): Promise<AgentHandler> {
  const cached = handlerCache.get(entry.route);
  if (cached) return cached;

  const handler = await entry.load();
  handlerCache.set(entry.route, handler);
  return handler;
}

// =============================================================================
// EXECUTION METADATA HELPER
// =============================================================================

function buildExecutionMetadata(): {
  trace_id: string;
  timestamp: string;
  service: string;
} {
  return {
    trace_id: randomUUID(),
    timestamp: new Date().toISOString(),
    service: 'shield-agents',
  };
}

// =============================================================================
// EXPRESS APP
// =============================================================================

const app = express();

// Parse JSON bodies
app.use(express.json({ limit: '1mb' }));

// CORS middleware
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.set(
    'Access-Control-Allow-Headers',
    'X-Correlation-ID, X-API-Version, Content-Type, Authorization',
  );
  if (_req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
});

// -----------------------------------------------------------------------------
// GET /health
// -----------------------------------------------------------------------------
app.get('/health', (_req: Request, res: Response) => {
  res.json({
    healthy: true,
    service: 'shield-agents',
    agents: AGENT_REGISTRY.length,
  });
});

// -----------------------------------------------------------------------------
// POST /v1/shield/:agent  — unified agent dispatch
// -----------------------------------------------------------------------------
for (const entry of AGENT_REGISTRY) {
  app.post(`/v1/shield/${entry.route}`, async (req: Request, res: Response) => {
    const execution_metadata = buildExecutionMetadata();
    const layers_executed: string[] = ['input_validation'];

    try {
      // Expect { agent?, payload, context? } or treat entire body as payload
      const body = req.body ?? {};
      const payload = body.payload ?? body;
      const context = body.context ?? {};

      layers_executed.push('agent_dispatch');

      const handler = await getHandler(entry);
      const result = await handler(payload, context);

      layers_executed.push('response_envelope');

      res.json({
        result,
        execution_metadata,
        layers_executed,
      });
    } catch (error) {
      layers_executed.push('error_handling');

      const message = error instanceof Error ? error.message : 'Unknown error';
      res.status(500).json({
        error: message,
        execution_metadata,
        layers_executed,
      });
    }
  });
}

// 404 fallback
app.use((req: Request, res: Response) => {
  const execution_metadata = buildExecutionMetadata();
  res.status(404).json({
    error: 'Not Found',
    message: `No route for ${req.method} ${req.path}`,
    available_routes: AGENT_REGISTRY.map((e) => `POST /v1/shield/${e.route}`),
    execution_metadata,
    layers_executed: ['routing'],
  });
});

// =============================================================================
// EXPORT — Cloud Function entry point
// =============================================================================
export const api = app;
