/**
 * @module errors
 * @description Error types for LLM-Security-Core gateway
 */

/**
 * Base error class for all gateway errors.
 */
export class GatewayError extends Error {
  public readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'GatewayError';
    this.code = code;
  }
}

/**
 * Thrown when a CallerToken is invalid or expired.
 */
export class CallerTokenError extends GatewayError {
  constructor(message: string) {
    super(message, 'INVALID_CALLER_TOKEN');
    this.name = 'CallerTokenError';
  }
}

/**
 * Thrown when Shield is called directly without going through SecurityCore.
 */
export class DirectAccessError extends GatewayError {
  constructor(message?: string) {
    super(
      message ?? 'Direct call to Shield is forbidden. Use @llm-shield/security-core SecurityCore instead.',
      'DIRECT_ACCESS_FORBIDDEN',
    );
    this.name = 'DirectAccessError';
  }
}

/**
 * Thrown when a centralized policy denies an operation.
 */
export class PolicyDeniedError extends GatewayError {
  constructor(reason?: string) {
    super(
      reason ? `Policy denied: ${reason}` : 'Operation denied by centralized policy',
      'POLICY_DENIED',
    );
    this.name = 'PolicyDeniedError';
  }
}

/**
 * Thrown when required execution context fields are missing.
 */
export class MissingExecutionContextError extends GatewayError {
  constructor(field: string) {
    super(
      `Missing required execution context field: ${field}`,
      'MISSING_EXECUTION_CONTEXT',
    );
    this.name = 'MissingExecutionContextError';
  }
}
