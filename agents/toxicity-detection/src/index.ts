/**
 * Toxicity Detection Agent
 *
 * Classification: DETECTION_ONLY
 * Decision Type: toxicity_detection
 *
 * Detects abusive, hateful, or toxic language within prompts,
 * outputs, or tool payloads. This agent ONLY detects toxicity - it does NOT
 * modify, redact, or enforce decisions on the content.
 *
 * @module toxicity-detection-agent
 */

export { ToxicityDetectionAgent } from './agent.js';
export { ToxicityDetector } from './detector.js';
export { createRuvectorClient } from './ruvector-client.js';
export { TelemetryEmitter } from './telemetry.js';
export * from './types.js';
export * from './patterns.js';
