/**
 * @module types
 * @description LLM-Security-Core gateway types
 */

/**
 * HMAC-signed caller identity token.
 * Required for all scanning operations through the gateway.
 */
export interface CallerToken {
  /** Unique caller identifier (e.g., "agentics-core", "my-service") */
  caller_id: string;
  /** HMAC-SHA256 signature of `caller_id + "|" + issued_at` using the shared secret */
  signature: string;
  /** Token creation timestamp (ISO 8601). Tokens older than TTL are rejected. */
  issued_at: string;
}

/**
 * Execution context required for all gateway operations.
 * Combines Agentics execution context with caller authentication.
 */
export interface GatewayContext {
  /** Execution ID from the Agentics Core */
  execution_id: string;
  /** Parent span ID from the calling Core */
  parent_span_id: string;
  /** Authenticated caller token */
  caller: CallerToken;
}

/**
 * Configuration for the SecurityCore gateway.
 */
export interface SecurityCoreConfig {
  /** Shared secret for CallerToken HMAC validation */
  sharedSecret: string;
  /** Shield preset to use (default: 'standard') */
  preset?: 'standard' | 'strict' | 'permissive';
  /** Custom policy implementation (default: allow all) */
  policy?: CentralizedPolicy;
  /** Token time-to-live in seconds (default: 300) */
  tokenTtlSeconds?: number;
}

/**
 * Centralized policy interface for authorization decisions.
 * Implement this to add custom access control logic.
 */
export interface CentralizedPolicy {
  /** Check if a scan operation is allowed given the caller and context. */
  authorize(context: GatewayContext, operation: string): Promise<PolicyDecision>;
}

/**
 * Result of a policy authorization check.
 */
export interface PolicyDecision {
  allowed: boolean;
  reason?: string;
}
