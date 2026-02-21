/**
 * HTTP Handler for Google Cloud Edge Function
 *
 * Provides HTTP endpoint for toxicity detection.
 * Designed for deployment as a Google Cloud Edge Function.
 *
 * @module toxicity-detection-agent/handler
 */

import { ToxicityDetectionAgent } from './agent.js';
import { AGENT_IDENTITY, type ToxicityDetectionInput, type ToxicityDetectionAgentOutput } from './types.js';
import { v4 as uuidv4 } from 'uuid';

/**
 * Request body schema
 */
interface HandlerRequest {
  /** Content to analyze */
  content: string;
  /** Content source */
  content_source?: 'user_input' | 'model_output' | 'tool_call' | 'system';
  /** Detection sensitivity (0.0 - 1.0) */
  sensitivity?: number;
  /** Detection threshold (0.0 - 1.0) */
  threshold?: number;
  /** Categories to detect */
  detect_categories?: string[];
  /** Session ID for correlation */
  session_id?: string;
  /** Caller ID */
  caller_id?: string;
  /** Policy references */
  policies?: Array<{
    policy_id: string;
    policy_version?: string;
    rule_ids?: string[];
  }>;
}

/**
 * Response body schema
 */
interface HandlerResponse {
  success: boolean;
  data?: ToxicityDetectionAgentOutput;
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
}

/**
 * Create the HTTP handler for Edge Function deployment
 */
export function createHandler() {
  const agent = new ToxicityDetectionAgent();

  return async (req: Request): Promise<Response> => {
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    // Only accept POST
    if (req.method !== 'POST') {
      return createErrorResponse(405, 'METHOD_NOT_ALLOWED', 'Only POST method is allowed');
    }

    try {
      // Parse request body
      const body = await req.json() as HandlerRequest;

      // Validate required fields
      if (!body.content || typeof body.content !== 'string') {
        return createErrorResponse(400, 'INVALID_INPUT', 'content field is required and must be a string');
      }

      // Build input
      const input: ToxicityDetectionInput = {
        content: body.content,
        context: {
          execution_ref: uuidv4(),
          timestamp: new Date().toISOString(),
          content_source: body.content_source || 'user_input',
          session_id: body.session_id,
          caller_id: body.caller_id,
          policies: body.policies,
        },
        sensitivity: body.sensitivity ?? 0.5,
        threshold: body.threshold ?? 0.7,
        detect_categories: body.detect_categories as any,
      };

      // Run detection
      const output = await agent.detect(input);

      // Return success response
      const response: HandlerResponse = {
        success: true,
        data: output,
      };

      return new Response(JSON.stringify(response), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'X-Agent-ID': AGENT_IDENTITY.agent_id,
          'X-Agent-Version': AGENT_IDENTITY.agent_version,
          'X-Execution-Ref': input.context.execution_ref,
        },
      });

    } catch (error) {
      const err = error as Error & { code?: string; details?: unknown };

      // Determine error code and status
      let status = 500;
      let code = 'INTERNAL_ERROR';

      if (err.code === 'VALIDATION_FAILED' || err.message.includes('validation')) {
        status = 400;
        code = 'VALIDATION_FAILED';
      } else if (err.code === 'TIMEOUT' || err.name === 'AbortError') {
        status = 408;
        code = 'TIMEOUT';
      }

      return createErrorResponse(status, code, err.message, err.details);
    }
  };
}

/**
 * Create an error response
 */
function createErrorResponse(
  status: number,
  code: string,
  message: string,
  details?: unknown
): Response {
  const response: HandlerResponse = {
    success: false,
    error: {
      code,
      message,
      details,
    },
  };

  return new Response(JSON.stringify(response), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'X-Agent-ID': AGENT_IDENTITY.agent_id,
      'X-Agent-Version': AGENT_IDENTITY.agent_version,
    },
  });
}

/**
 * Health check handler
 */
export function createHealthHandler() {
  return async (_req: Request): Promise<Response> => {
    return new Response(JSON.stringify({
      status: 'healthy',
      agent_id: AGENT_IDENTITY.agent_id,
      agent_version: AGENT_IDENTITY.agent_version,
      classification: AGENT_IDENTITY.classification,
      decision_type: AGENT_IDENTITY.decision_type,
      timestamp: new Date().toISOString(),
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  };
}

/**
 * Export default handler for Edge Function
 */
export default createHandler();
