/**
 * @module handler
 * @description Google Cloud Edge Function handler for Content Moderation Agent
 *
 * This handler is deployed as part of the LLM-Shield unified GCP service.
 * It provides HTTP endpoints for agent invocation.
 */
/**
 * HTTP Request interface (Edge Function compatible)
 */
export interface EdgeRequest {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: unknown;
    json(): Promise<unknown>;
}
/**
 * HTTP Response interface (Edge Function compatible)
 */
export interface EdgeResponse {
    status: number;
    headers: Record<string, string>;
    body: unknown;
}
/**
 * Edge Function handler
 *
 * Endpoints:
 * - POST /moderate - Execute moderation on content
 * - POST /cli - CLI invocation (test/simulate/inspect)
 * - GET /health - Health check
 * - GET /info - Agent information
 */
export declare function handler(request: EdgeRequest): Promise<EdgeResponse>;
/**
 * Export for Google Cloud Functions
 */
export declare const contentModeration: typeof handler;
