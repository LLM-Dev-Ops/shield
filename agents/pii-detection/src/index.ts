/**
 * PII Detection Agent
 *
 * Classification: DETECTION_ONLY
 * Decision Type: pii_detection
 *
 * Detects Personally Identifiable Information (PII) within prompts,
 * outputs, or tool payloads. This agent ONLY detects PII - it does NOT
 * modify, redact, or enforce decisions on the content.
 *
 * @module pii-detection-agent
 */

export { PIIDetectionAgent } from './agent.js';
export { PIIDetector } from './detector.js';
export { createRuvectorClient } from './ruvector-client.js';
export { TelemetryEmitter } from './telemetry.js';
export * from './types.js';
export * from './patterns.js';
