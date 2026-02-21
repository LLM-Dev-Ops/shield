/**
 * Internal types for PII Detection Agent
 *
 * @module pii-detection-agent/types
 */
/**
 * Agent identity constant
 */
export const AGENT_IDENTITY = {
    agent_id: 'pii-detection-agent',
    agent_version: '1.0.0',
    classification: 'DETECTION_ONLY',
    decision_type: 'pii_detection',
};
/**
 * Severity weights for risk calculation
 */
export const SEVERITY_WEIGHTS = {
    none: 0,
    low: 0.25,
    medium: 0.5,
    high: 0.75,
    critical: 1.0,
};
/**
 * Default PII types to detect when not specified
 */
export const DEFAULT_PII_TYPES = [
    'email',
    'phone',
    'ssn',
    'credit_card',
    'ip_address',
    'passport',
    'drivers_license',
];
/**
 * Default countries when not specified
 */
export const DEFAULT_COUNTRIES = ['US'];
//# sourceMappingURL=types.js.map