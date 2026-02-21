/**
 * @module ruvector-client
 * @description Client for persisting DecisionEvents to ruvector-service
 *
 * CRITICAL: This is the ONLY module that communicates with ruvector-service.
 * All persistence of decisions, detections, and outcomes happens through this client.
 * LLM-Shield NEVER connects directly to Google SQL.
 */
/**
 * Default configuration values
 */
const DEFAULT_CONFIG = {
    endpoint: 'http://localhost:8080',
    timeout: 5000,
    retry: false,
    maxRetries: 3,
};
/**
 * RuVector client for decision event persistence
 */
export class RuVectorClient {
    config;
    constructor(config) {
        this.config = {
            ...DEFAULT_CONFIG,
            ...config,
            endpoint: config.endpoint || DEFAULT_CONFIG.endpoint,
            timeout: config.timeout ?? DEFAULT_CONFIG.timeout,
            retry: config.retry ?? DEFAULT_CONFIG.retry,
            maxRetries: config.maxRetries ?? DEFAULT_CONFIG.maxRetries,
            apiKey: config.apiKey ?? '',
        };
    }
    /**
     * Persist a decision event to ruvector-service
     *
     * This is an async, non-blocking operation.
     * The agent does NOT wait for persistence confirmation before returning.
     */
    async persistDecisionEvent(event) {
        const url = `${this.config.endpoint}/api/v1/decisions`;
        let attempts = 0;
        const maxAttempts = this.config.retry ? this.config.maxRetries : 1;
        while (attempts < maxAttempts) {
            attempts++;
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);
                const response = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...(this.config.apiKey && {
                            Authorization: `Bearer ${this.config.apiKey}`,
                        }),
                        'X-Agent-ID': event.agent_id,
                        'X-Agent-Version': event.agent_version,
                        'X-Execution-Ref': event.execution_ref,
                    },
                    body: JSON.stringify(event),
                    signal: controller.signal,
                });
                clearTimeout(timeoutId);
                if (!response.ok) {
                    const errorBody = await response.text().catch(() => 'Unknown error');
                    // Don't retry client errors
                    if (response.status >= 400 && response.status < 500) {
                        return {
                            success: false,
                            error: `HTTP ${response.status}: ${errorBody}`,
                        };
                    }
                    // Retry server errors
                    if (attempts < maxAttempts) {
                        continue;
                    }
                    return {
                        success: false,
                        error: `HTTP ${response.status}: ${errorBody}`,
                    };
                }
                const data = await response.json();
                return {
                    success: true,
                    event_id: data.event_id,
                    persisted_at: data.persisted_at || new Date().toISOString(),
                };
            }
            catch (error) {
                if (error instanceof Error && error.name === 'AbortError') {
                    if (attempts < maxAttempts) {
                        continue;
                    }
                    return {
                        success: false,
                        error: 'Request timeout',
                    };
                }
                if (attempts < maxAttempts) {
                    continue;
                }
                return {
                    success: false,
                    error: error instanceof Error ? error.message : 'Unknown error',
                };
            }
        }
        return {
            success: false,
            error: 'Max retries exceeded',
        };
    }
    /**
     * Retrieve a decision event by execution reference
     */
    async getDecisionEvent(executionRef) {
        const url = `${this.config.endpoint}/api/v1/decisions/${executionRef}`;
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    ...(this.config.apiKey && {
                        Authorization: `Bearer ${this.config.apiKey}`,
                    }),
                },
                signal: controller.signal,
            });
            clearTimeout(timeoutId);
            if (!response.ok) {
                return null;
            }
            const data = await response.json();
            return data;
        }
        catch {
            return null;
        }
    }
    /**
     * Health check for ruvector-service
     */
    async healthCheck() {
        const url = `${this.config.endpoint}/health`;
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 2000);
            const response = await fetch(url, {
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
}
/**
 * Create RuVector client from environment variables
 */
export function createClientFromEnv() {
    const endpoint = process.env.RUVECTOR_ENDPOINT || 'http://localhost:8080';
    const apiKey = process.env.RUVECTOR_API_KEY;
    const timeout = parseInt(process.env.RUVECTOR_TIMEOUT || '5000', 10);
    return new RuVectorClient({
        endpoint,
        apiKey,
        timeout,
        retry: process.env.RUVECTOR_RETRY === 'true',
        maxRetries: parseInt(process.env.RUVECTOR_MAX_RETRIES || '3', 10),
    });
}
/**
 * Create a no-op client for testing/simulation
 */
export function createNoOpClient() {
    // Create a mock client that always succeeds but doesn't persist
    const mockClient = {
        config: {
            endpoint: 'noop://localhost',
            apiKey: '',
            timeout: 0,
            retry: false,
            maxRetries: 0,
        },
        persistDecisionEvent: async () => ({
            success: true,
            event_id: `noop-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`,
            persisted_at: new Date().toISOString(),
        }),
        getDecisionEvent: async () => null,
        healthCheck: async () => true,
    };
    return mockClient;
}
//# sourceMappingURL=ruvector-client.js.map