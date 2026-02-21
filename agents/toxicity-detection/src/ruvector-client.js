/**
 * ruvector-service Client
 *
 * Client for persisting DecisionEvents to ruvector-service.
 * All database persistence MUST go through this client.
 *
 * CRITICAL: This is the ONLY path for data persistence.
 * The agent MUST NOT connect directly to Google SQL or any database.
 *
 * @module toxicity-detection-agent/ruvector-client
 */
/**
 * Default configuration for ruvector-service client
 */
const DEFAULT_CONFIG = {
    endpoint: process.env.RUVECTOR_SERVICE_ENDPOINT || 'http://localhost:8080',
    timeout: 5000,
    retryAttempts: 3,
};
/**
 * Create a ruvector-service client
 */
export function createRuvectorClient(config) {
    const finalConfig = {
        ...DEFAULT_CONFIG,
        ...config,
    };
    return new RuvectorClientImpl(finalConfig);
}
/**
 * ruvector-service client implementation
 */
class RuvectorClientImpl {
    config;
    constructor(config) {
        this.config = config;
    }
    /**
     * Persist a DecisionEvent to ruvector-service
     *
     * CRITICAL: This method sends ONLY sanitized data.
     * Raw content, toxic text, and sensitive data MUST NOT be included.
     */
    async persistDecisionEvent(event) {
        const url = `${this.config.endpoint}/api/v1/decisions`;
        // Validate event before sending
        this.validateEvent(event);
        let lastError = null;
        for (let attempt = 1; attempt <= (this.config.retryAttempts || 1); attempt++) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), this.config.timeout || 5000);
                const response = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...(this.config.apiKey && { 'Authorization': `Bearer ${this.config.apiKey}` }),
                    },
                    body: JSON.stringify(event),
                    signal: controller.signal,
                });
                clearTimeout(timeoutId);
                if (!response.ok) {
                    throw new Error(`ruvector-service returned ${response.status}: ${response.statusText}`);
                }
                return; // Success
            }
            catch (error) {
                lastError = error;
                // Don't retry on abort (timeout)
                if (error.name === 'AbortError') {
                    throw new Error(`ruvector-service request timed out after ${this.config.timeout}ms`);
                }
                // Wait before retry (exponential backoff)
                if (attempt < (this.config.retryAttempts || 1)) {
                    await this.delay(Math.pow(2, attempt - 1) * 100);
                }
            }
        }
        throw new Error(`Failed to persist DecisionEvent after ${this.config.retryAttempts} attempts: ${lastError?.message}`);
    }
    /**
     * Check if ruvector-service is healthy
     */
    async isHealthy() {
        try {
            const url = `${this.config.endpoint}/health`;
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
    /**
     * Validate event before sending
     */
    validateEvent(event) {
        // Validate required fields
        if (!event.agent_id || event.agent_id !== 'toxicity-detection-agent') {
            throw new Error('Invalid agent_id in DecisionEvent');
        }
        if (!event.execution_ref) {
            throw new Error('Missing execution_ref in DecisionEvent');
        }
        if (!event.inputs_hash || !/^[a-f0-9]{64}$/.test(event.inputs_hash)) {
            throw new Error('Invalid inputs_hash in DecisionEvent');
        }
        // Ensure no raw content is included (paranoid check)
        const eventStr = JSON.stringify(event);
        if (eventStr.length > 10000) {
            throw new Error('DecisionEvent payload too large - possible raw content inclusion');
        }
        // Check for potential toxic content leak (shouldn't contain common toxic patterns)
        const suspiciousPatterns = [
            /\bkill\s+you\b/i,
            /\bhurt\s+you\b/i,
            /\bidiot\b/i,
            /\bstupid\b/i,
        ];
        for (const pattern of suspiciousPatterns) {
            if (pattern.test(eventStr)) {
                throw new Error('DecisionEvent may contain toxic content - blocked for safety');
            }
        }
    }
    /**
     * Delay helper for retry backoff
     */
    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}
/**
 * SHA-256 hash function for content
 *
 * Used to create inputs_hash for DecisionEvent.
 * The actual content is NEVER persisted, only the hash.
 */
export async function sha256(content) {
    // Use Web Crypto API (available in Node.js 18+, browsers, Edge Functions)
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    // Check if we're in Node.js or browser/Edge environment
    if (typeof crypto !== 'undefined' && crypto.subtle) {
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    // Fallback for environments without Web Crypto
    throw new Error('SHA-256 not available - requires Web Crypto API');
}
/**
 * Create a DecisionEvent from agent output
 */
export function createDecisionEvent(params) {
    return {
        agent_id: 'toxicity-detection-agent',
        agent_version: params.agentVersion,
        decision_type: 'toxicity_detection',
        inputs_hash: params.inputsHash,
        outputs: params.outputs,
        confidence: params.confidence,
        constraints_applied: params.constraintsApplied,
        execution_ref: params.executionRef,
        timestamp: params.timestamp,
        duration_ms: params.durationMs,
        telemetry: params.telemetry,
    };
}
//# sourceMappingURL=ruvector-client.js.map