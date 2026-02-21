/**
 * PII Detection Agent
 *
 * Main agent implementation that orchestrates PII detection.
 *
 * Classification: DETECTION_ONLY
 * Decision Type: pii_detection
 *
 * This agent:
 * - Inspects prompts, outputs, and tool calls
 * - Detects PII patterns with validation
 * - Calculates confidence scores
 * - Emits DecisionEvents to ruvector-service
 *
 * This agent does NOT:
 * - Modify, sanitize, or redact content
 * - Block or allow content
 * - Orchestrate workflows
 * - Trigger retries or escalations
 * - Connect directly to databases
 *
 * @module pii-detection-agent/agent
 */
import { PIIDetector } from './detector.js';
import { createRuvectorClient, sha256, createDecisionEvent } from './ruvector-client.js';
import { TelemetryEmitter, getTelemetryEmitter } from './telemetry.js';
import { AGENT_IDENTITY, } from './types.js';
// Import contracts for validation
import { PIIDetectionInput as PIIDetectionInputSchema, } from '@llm-shield/agentics-contracts';
/**
 * PII Detection Agent
 *
 * Stateless agent that detects PII in content.
 * Each invocation produces exactly one DecisionEvent.
 */
export class PIIDetectionAgent {
    detector;
    ruvectorClient;
    telemetryEmitter;
    persistEvents;
    emitTelemetry;
    constructor(config = {}) {
        this.detector = new PIIDetector();
        this.ruvectorClient = config.ruvectorClient || createRuvectorClient();
        this.telemetryEmitter = config.telemetryEmitter || getTelemetryEmitter();
        this.persistEvents = config.persistEvents ?? true;
        this.emitTelemetry = config.emitTelemetry ?? true;
    }
    /**
     * Detect PII in content
     *
     * Main entry point for PII detection. Validates input, runs detection,
     * and emits DecisionEvent.
     *
     * @param input - Detection input following PIIDetectionInput schema
     * @returns Agent output with detection results
     */
    async detect(input) {
        const startTime = performance.now();
        try {
            // Validate input
            const validatedInput = this.validateInput(input);
            // Create detection config
            const config = PIIDetector.createDefaultConfig({
                sensitivity: validatedInput.sensitivity,
                detect_types: validatedInput.detect_types,
                countries: validatedInput.countries,
            });
            // Run detection
            const matches = this.detector.detect(validatedInput.content, config);
            // Calculate results
            const durationMs = Math.round(performance.now() - startTime);
            const result = this.createResult(matches, durationMs);
            // Create output
            const output = {
                agent: AGENT_IDENTITY,
                result,
                duration_ms: durationMs,
                cached: false,
            };
            // Persist DecisionEvent (async, non-blocking)
            if (this.persistEvents) {
                this.persistDecisionEvent(validatedInput, output).catch(err => {
                    console.error('Failed to persist DecisionEvent:', err);
                });
            }
            // Emit telemetry (async, non-blocking)
            if (this.emitTelemetry) {
                this.emitTelemetryEvent(validatedInput, output);
            }
            return output;
        }
        catch (error) {
            const durationMs = Math.round(performance.now() - startTime);
            throw this.createAgentError(error, input, durationMs);
        }
    }
    /**
     * Validate input against schema
     */
    validateInput(input) {
        try {
            return PIIDetectionInputSchema.parse(input);
        }
        catch (error) {
            const err = error;
            throw new ValidationError('Input validation failed', err.errors?.map(e => `${e.path.join('.')}: ${e.message}`) || []);
        }
    }
    /**
     * Create detection result from matches
     */
    createResult(matches, durationMs) {
        // Convert matches to entities (WITHOUT raw values)
        const entities = matches.map(match => ({
            pii_type: match.pattern.type,
            category: match.pattern.type,
            start: match.start,
            end: match.end,
            confidence: match.confidence,
            pattern_id: match.pattern.id,
            severity: match.pattern.severity,
            validation_method: match.pattern.validationMethod,
            validation_passed: match.validationPassed,
        }));
        // Create risk factors
        const riskFactors = this.createRiskFactors(matches);
        // Calculate type counts
        const typeCounts = {};
        for (const match of matches) {
            typeCounts[match.pattern.type] = (typeCounts[match.pattern.type] || 0) + 1;
        }
        // Get unique detected types
        const detectedTypes = [...new Set(matches.map(m => m.pattern.type))];
        // Calculate risk score and severity
        const riskScore = this.detector.calculateRiskScore(matches);
        const severity = this.detector.getMaxSeverity(matches);
        // Calculate overall confidence
        const confidence = matches.length > 0
            ? matches.reduce((sum, m) => sum + m.confidence, 0) / matches.length
            : 1.0;
        return {
            pii_detected: matches.length > 0,
            risk_score: riskScore,
            severity,
            confidence: Math.round(confidence * 100) / 100,
            entities,
            risk_factors: riskFactors,
            pattern_match_count: matches.length,
            detected_types: detectedTypes,
            type_counts: typeCounts,
        };
    }
    /**
     * Create risk factors from matches
     */
    createRiskFactors(matches) {
        // Group matches by type
        const byType = new Map();
        for (const match of matches) {
            const existing = byType.get(match.pattern.type) || [];
            existing.push(match);
            byType.set(match.pattern.type, existing);
        }
        // Create risk factors for each type
        const riskFactors = [];
        for (const [type, typeMatches] of byType) {
            const count = typeMatches.length;
            const maxSeverity = this.detector.getMaxSeverity(typeMatches);
            const avgConfidence = typeMatches.reduce((sum, m) => sum + m.confidence, 0) / count;
            riskFactors.push({
                factor_id: `pii-${type}`,
                category: 'pii',
                description: `Detected ${count} ${type}(s)`,
                severity: maxSeverity,
                score_contribution: this.getSeverityWeight(maxSeverity) * avgConfidence,
                confidence: avgConfidence,
            });
        }
        return riskFactors;
    }
    /**
     * Get severity weight
     */
    getSeverityWeight(severity) {
        const weights = {
            none: 0,
            low: 0.25,
            medium: 0.5,
            high: 0.75,
            critical: 1.0,
        };
        return weights[severity];
    }
    /**
     * Persist DecisionEvent to ruvector-service
     */
    async persistDecisionEvent(input, output) {
        // Create content hash (NEVER persist raw content)
        const inputsHash = await sha256(input.content);
        const event = createDecisionEvent({
            agentVersion: AGENT_IDENTITY.agent_version,
            executionRef: input.context.execution_ref,
            timestamp: input.context.timestamp,
            inputsHash,
            outputs: {
                pii_detected: output.result.pii_detected,
                risk_score: output.result.risk_score,
                severity: output.result.severity,
                confidence: output.result.confidence,
                pattern_match_count: output.result.pattern_match_count,
                detected_types: output.result.detected_types,
                entity_count: output.result.entities.length,
                type_counts: output.result.type_counts,
            },
            confidence: output.result.confidence,
            constraintsApplied: input.context.policies || [],
            durationMs: output.duration_ms,
            telemetry: {
                content_length: input.content.length,
                content_source: input.context.content_source,
                session_id: input.context.session_id,
                caller_id: input.context.caller_id,
                countries_checked: input.countries,
                types_checked: input.detect_types,
            },
        });
        await this.ruvectorClient.persistDecisionEvent(event);
    }
    /**
     * Emit telemetry event
     */
    emitTelemetryEvent(input, output) {
        const event = TelemetryEmitter.createEvent({
            agentId: AGENT_IDENTITY.agent_id,
            agentVersion: AGENT_IDENTITY.agent_version,
            executionRef: input.context.execution_ref,
            timestamp: input.context.timestamp,
            durationMs: output.duration_ms,
            contentLength: input.content.length,
            contentSource: input.context.content_source,
            piiDetected: output.result.pii_detected,
            entityCount: output.result.entities.length,
            detectedTypes: output.result.detected_types,
            riskScore: output.result.risk_score,
            severity: output.result.severity,
            sessionId: input.context.session_id,
            callerId: input.context.caller_id,
        });
        this.telemetryEmitter.emit(event);
    }
    /**
     * Create an AgentError from an exception
     */
    createAgentError(error, input, durationMs) {
        const err = error;
        let code = 'INTERNAL_ERROR';
        let message = err.message || 'Unknown error';
        if (err instanceof ValidationError) {
            code = 'VALIDATION_FAILED';
            message = err.message;
        }
        else if (err.name === 'AbortError') {
            code = 'TIMEOUT';
            message = 'Detection timed out';
        }
        return {
            code,
            message,
            agent: AGENT_IDENTITY,
            execution_ref: input.context?.execution_ref,
            timestamp: new Date().toISOString(),
            details: {
                duration_ms: durationMs,
            },
        };
    }
}
/**
 * Validation error class
 */
class ValidationError extends Error {
    details;
    constructor(message, details) {
        super(message);
        this.name = 'ValidationError';
        this.details = details;
    }
}
//# sourceMappingURL=agent.js.map