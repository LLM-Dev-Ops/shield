/**
 * Internal types for Toxicity Detection Agent
 *
 * @module toxicity-detection-agent/types
 */
/**
 * Agent identity constant
 */
export const AGENT_IDENTITY = {
    agent_id: 'toxicity-detection-agent',
    agent_version: '1.0.0',
    classification: 'DETECTION_ONLY',
    decision_type: 'toxicity_detection',
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
 * Default toxicity categories to detect when not specified
 */
export const DEFAULT_TOXICITY_CATEGORIES = [
    'toxic',
    'severe_toxic',
    'obscene',
    'threat',
    'insult',
    'identity_hate',
];
/**
 * Default detection threshold
 */
export const DEFAULT_THRESHOLD = 0.7;
/**
 * Default sensitivity
 */
export const DEFAULT_SENSITIVITY = 0.5;
//# sourceMappingURL=types.js.map