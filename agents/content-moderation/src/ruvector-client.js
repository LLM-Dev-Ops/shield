/**
 * @module ruvector-client
 * @description Client for persisting DecisionEvents to ruvector-service
 *
 * LLM-Shield agents NEVER connect directly to Google SQL.
 * All persistence occurs via ruvector-service API calls only.
 */
/**
 * Default configuration
 */
const DEFAULT_CONFIG = {
    baseUrl: process.env.RUVECTOR_SERVICE_URL || 'http://localhost:8080',
    timeout: 5000,
    retryEnabled: true,
    maxRetries: 3,
};
/**
 * Client for persisting DecisionEvents to ruvector-service
 *
 * This client handles:
 * - Event serialization
 * - HTTP transport
 * - Error handling
 * - Retry logic
 *
 * This client does NOT:
 * - Execute SQL queries
 * - Connect to databases directly
 * - Store raw content
 */
export class RuVectorClient {
    config;
    endpoint;
    constructor(config = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config };
        this.endpoint = `${this.config.baseUrl}/api/v1/events/decision`;
    }
    /**
     * Persist a ContentModerationDecisionEvent to ruvector-service
     *
     * @param event - The DecisionEvent to persist
     * @returns Response from ruvector-service
     */
    async persistDecisionEvent(event) {
        const headers = {
            'Content-Type': 'application/json',
            'X-Agent-ID': event.agent_id,
            'X-Agent-Version': event.agent_version,
            'X-Execution-Ref': event.execution_ref,
            'X-Decision-Type': event.decision_type,
        };
        if (this.config.apiKey) {
            headers['Authorization'] = `Bearer ${this.config.apiKey}`;
        }
        let lastError = null;
        const maxAttempts = this.config.retryEnabled ? this.config.maxRetries : 1;
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);
                const response = await fetch(this.endpoint, {
                    method: 'POST',
                    headers,
                    body: JSON.stringify(event),
                    signal: controller.signal,
                });
                clearTimeout(timeoutId);
                if (!response.ok) {
                    const errorBody = await response.text().catch(() => 'Unknown error');
                    throw new Error(`ruvector-service returned ${response.status}: ${errorBody}`);
                }
                const result = (await response.json());
                return {
                    ...result,
                    success: true,
                    timestamp: new Date().toISOString(),
                };
            }
            catch (error) {
                lastError = error instanceof Error ? error : new Error(String(error));
                // Don't retry on client errors (4xx)
                if (lastError.message.includes('returned 4')) {
                    break;
                }
                // Exponential backoff for retries
                if (attempt < maxAttempts) {
                    await this.delay(Math.pow(2, attempt) * 100);
                }
            }
        }
        // Return failure response (agent still completes)
        return {
            success: false,
            error: lastError?.message || 'Unknown error',
            timestamp: new Date().toISOString(),
        };
    }
    /**
     * Health check for ruvector-service
     */
    async healthCheck() {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 2000);
            const response = await fetch(`${this.config.baseUrl}/health`, {
                method: 'GET',
                signal: controller.signal,
            });
            clearTimeout(timeoutId);
            return response.ok;
        }
        catch {
            return false;
        }
    }
    delay(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }
}
/**
 * Create a mock client for testing
 */
export function createMockRuVectorClient() {
    const client = new RuVectorClient({ baseUrl: 'http://mock' });
    // Override persistDecisionEvent for testing
    client.persistDecisionEvent = async (event) => ({
        success: true,
        event_id: `mock-${event.execution_ref}`,
        timestamp: new Date().toISOString(),
    });
    return client;
}
//# sourceMappingURL=ruvector-client.js.map