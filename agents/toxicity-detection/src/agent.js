/**
 * Toxicity Detection Agent
 *
 * Main agent implementation that orchestrates toxicity detection.
 *
 * Classification: DETECTION_ONLY
 * Decision Type: toxicity_detection
 *
 * This agent:
 * - Inspects prompts, outputs, and tool calls
 * - Detects toxicity patterns with confidence scoring
 * - Classifies toxicity by category
 * - Emits DecisionEvents to ruvector-service
 *
 * This agent does NOT:
 * - Modify, sanitize, or redact content
 * - Block or allow content
 * - Orchestrate workflows
 * - Trigger retries or escalations
 * - Connect directly to databases
 *
 * @module toxicity-detection-agent/agent
 */
import { ToxicityDetector } from './detector.js';
import { createRuvectorClient, sha256, createDecisionEvent } from './ruvector-client.js';
import { TelemetryEmitter, getTelemetryEmitter } from './telemetry.js';
import { AGENT_IDENTITY, } from './types.js';
// Import contracts for validation
import { ToxicityDetectionInput as ToxicityDetectionInputSchema, } from '@llm-shield/agentics-contracts';
/**
 * Toxicity Detection Agent
 *
 * Stateless agent that detects toxic content.
 * Each invocation produces exactly one DecisionEvent.
 */
export class ToxicityDetectionAgent {
    detector;
    ruvectorClient;
    telemetryEmitter;
    persistEvents;
    emitTelemetry;
    constructor(config = {}) {
        this.detector = new ToxicityDetector();
        this.ruvectorClient = config.ruvectorClient || createRuvectorClient();
        this.telemetryEmitter = config.telemetryEmitter || getTelemetryEmitter();
        this.persistEvents = config.persistEvents ?? true;
        this.emitTelemetry = config.emitTelemetry ?? true;
    }
    /**
     * Detect toxicity in content
     *
     * Main entry point for toxicity detection. Validates input, runs detection,
     * and emits DecisionEvent.
     *
     * @param input - Detection input following ToxicityDetectionInput schema
     * @returns Agent output with detection results
     */
    async detect(input) {
        const startTime = performance.now();
        try {
            // Validate input
            const validatedInput = this.validateInput(input);
            // Create detection config
            const config = ToxicityDetector.createDefaultConfig({
                sensitivity: validatedInput.sensitivity,
                threshold: validatedInput.threshold,
                detect_categories: validatedInput.detect_categories,
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
            return ToxicityDetectionInputSchema.parse(input);
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
            toxicity_category: match.pattern.category,
            category: match.pattern.category,
            start: match.start,
            end: match.end,
            confidence: match.confidence,
            pattern_id: match.pattern.id,
            severity: match.pattern.severity,
            indicator_count: match.indicatorCount,
        }));
        // Create risk factors
        const riskFactors = this.createRiskFactors(matches);
        // Calculate category counts
        const categoryCounts = {};
        for (const match of matches) {
            categoryCounts[match.pattern.category] = (categoryCounts[match.pattern.category] || 0) + 1;
        }
        // Get unique detected categories
        const detectedCategories = [...new Set(matches.map(m => m.pattern.category))];
        // Calculate risk score and severity
        const riskScore = this.detector.calculateRiskScore(matches);
        const severity = this.detector.getMaxSeverity(matches);
        // Calculate overall confidence
        const confidence = matches.length > 0
            ? matches.reduce((sum, m) => sum + m.confidence, 0) / matches.length
            : 1.0;
        return {
            toxicity_detected: matches.length > 0,
            risk_score: riskScore,
            severity,
            confidence: Math.round(confidence * 100) / 100,
            entities,
            risk_factors: riskFactors,
            pattern_match_count: matches.length,
            detected_categories: detectedCategories,
            category_counts: categoryCounts,
        };
    }
    /**
     * Create risk factors from matches
     */
    createRiskFactors(matches) {
        // Group matches by category
        const byCategory = new Map();
        for (const match of matches) {
            const existing = byCategory.get(match.pattern.category) || [];
            existing.push(match);
            byCategory.set(match.pattern.category, existing);
        }
        // Create risk factors for each category
        const riskFactors = [];
        for (const [category, categoryMatches] of byCategory) {
            const count = categoryMatches.length;
            const maxSeverity = this.detector.getMaxSeverity(categoryMatches);
            const avgConfidence = categoryMatches.reduce((sum, m) => sum + m.confidence, 0) / count;
            riskFactors.push({
                factor_id: `toxicity-${category}`,
                category: 'toxicity',
                description: `Detected ${count} ${category} indicator(s)`,
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
                toxicity_detected: output.result.toxicity_detected,
                risk_score: output.result.risk_score,
                severity: output.result.severity,
                confidence: output.result.confidence,
                pattern_match_count: output.result.pattern_match_count,
                detected_categories: output.result.detected_categories,
                entity_count: output.result.entities.length,
                category_counts: output.result.category_counts,
            },
            confidence: output.result.confidence,
            constraintsApplied: input.context.policies || [],
            durationMs: output.duration_ms,
            telemetry: {
                content_length: input.content.length,
                content_source: input.context.content_source,
                session_id: input.context.session_id,
                caller_id: input.context.caller_id,
                threshold_used: input.threshold,
                categories_checked: input.detect_categories,
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
            toxicityDetected: output.result.toxicity_detected,
            entityCount: output.result.entities.length,
            detectedCategories: output.result.detected_categories,
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