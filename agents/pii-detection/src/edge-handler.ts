/**
 * PII Detection Agent - Google Cloud Edge Function Handler
 *
 * This is the entry point for the PII Detection Agent when deployed
 * as a Google Cloud Edge Function (Cloud Run, Cloud Functions, etc.)
 *
 * Deployment:
 *   - Deployed as part of the LLM-Shield unified GCP service
 *   - Stateless execution
 *   - Deterministic behavior
 *   - All persistence via ruvector-service only
 *
 * @module pii-detection-agent/edge-handler
 */

import { PIIDetectionAgent } from './agent.js';
import { AGENT_IDENTITY } from './types.js';
import {
  PIIDetectionInput as PIIDetectionInputSchema,
  AgentError,
} from '@llm-shield/agentics-contracts';

/**
 * HTTP request interface (compatible with various Edge runtimes)
 */
interface EdgeRequest {
  method: string;
  url: string;
  headers: Headers | Record<string, string>;
  json(): Promise<unknown>;
}

/**
 * HTTP response interface
 */
interface EdgeResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/**
 * Create Edge Function handler
 *
 * This factory creates a handler function that can be used with various
 * Edge runtimes including:
 *   - Google Cloud Functions (2nd gen)
 *   - Google Cloud Run
 *   - Cloudflare Workers
 *   - Vercel Edge Functions
 */
export function createEdgeHandler() {
  const agent = new PIIDetectionAgent();

  /**
   * Main handler function
   */
  return async function handler(request: EdgeRequest): Promise<EdgeResponse> {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return {
        status: 204,
        headers: getCorsHeaders(),
        body: '',
      };
    }

    // Only accept POST
    if (request.method !== 'POST') {
      return {
        status: 405,
        headers: { ...getCorsHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({
          error: 'Method Not Allowed',
          message: 'Only POST requests are accepted',
        }),
      };
    }

    try {
      // Parse request body
      const body = await request.json();

      // Validate input
      const validationResult = PIIDetectionInputSchema.safeParse(body);
      if (!validationResult.success) {
        return {
          status: 400,
          headers: { ...getCorsHeaders(), 'Content-Type': 'application/json' },
          body: JSON.stringify({
            code: 'INVALID_INPUT',
            message: 'Input validation failed',
            agent: AGENT_IDENTITY,
            timestamp: new Date().toISOString(),
            details: {
              errors: validationResult.error.errors.map(e => ({
                path: e.path.join('.'),
                message: e.message,
              })),
            },
          }),
        };
      }

      // Run detection
      const output = await agent.detect(validationResult.data);

      // Return success response
      return {
        status: 200,
        headers: { ...getCorsHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(output),
      };

    } catch (error) {
      console.error('PII Detection Agent error:', error);

      const err = error as Error & { code?: string };

      return {
        status: err.code === 'TIMEOUT' ? 504 : 500,
        headers: { ...getCorsHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code: err.code || 'INTERNAL_ERROR',
          message: err.message || 'Internal server error',
          agent: AGENT_IDENTITY,
          timestamp: new Date().toISOString(),
        }),
      };
    }
  };
}

/**
 * Get CORS headers
 */
function getCorsHeaders(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

/**
 * Health check handler
 */
export async function healthHandler(): Promise<EdgeResponse> {
  return {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      status: 'healthy',
      agent: AGENT_IDENTITY,
      timestamp: new Date().toISOString(),
    }),
  };
}

/**
 * Version handler
 */
export async function versionHandler(): Promise<EdgeResponse> {
  return {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      agent_id: AGENT_IDENTITY.agent_id,
      version: AGENT_IDENTITY.agent_version,
      classification: AGENT_IDENTITY.classification,
      decision_type: AGENT_IDENTITY.decision_type,
    }),
  };
}

// =============================================================================
// Google Cloud Functions (2nd gen) Entry Point
// =============================================================================

import type { HttpFunction } from '@google-cloud/functions-framework';

/**
 * Google Cloud Functions HTTP entry point
 */
export const piiDetection: HttpFunction = async (req, res) => {
  const handler = createEdgeHandler();

  // Convert express request to edge request
  const edgeRequest: EdgeRequest = {
    method: req.method,
    url: req.url,
    headers: req.headers as Record<string, string>,
    json: async () => req.body,
  };

  // Handle different paths
  const path = new URL(req.url, `http://${req.headers.host}`).pathname;

  let response: EdgeResponse;

  if (path === '/health' || path === '/healthz') {
    response = await healthHandler();
  } else if (path === '/version') {
    response = await versionHandler();
  } else {
    response = await handler(edgeRequest);
  }

  // Set response headers
  for (const [key, value] of Object.entries(response.headers)) {
    res.setHeader(key, value);
  }

  // Send response
  res.status(response.status).send(response.body);
};

// =============================================================================
// Cloudflare Workers Entry Point (for edge deployment)
// =============================================================================

/**
 * Cloudflare Workers fetch handler
 */
export default {
  async fetch(request: Request): Promise<Response> {
    const handler = createEdgeHandler();

    const url = new URL(request.url);
    const path = url.pathname;

    let response: EdgeResponse;

    if (path === '/health' || path === '/healthz') {
      response = await healthHandler();
    } else if (path === '/version') {
      response = await versionHandler();
    } else {
      const edgeRequest: EdgeRequest = {
        method: request.method,
        url: request.url,
        headers: request.headers,
        json: () => request.json(),
      };

      response = await handler(edgeRequest);
    }

    return new Response(response.body, {
      status: response.status,
      headers: response.headers,
    });
  },
};
