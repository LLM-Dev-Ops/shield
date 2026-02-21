/**
 * Redaction logic for the Data Redaction Agent
 *
 * This module handles the detection and redaction of sensitive data.
 * It produces sanitized output with no raw sensitive data exposed.
 */
import { createHash } from 'crypto';
import { PII_PATTERNS, SECRET_PATTERNS, CREDENTIAL_PATTERNS, } from './patterns.js';
// =============================================================================
// REDACTION ENGINE
// =============================================================================
/**
 * Main redaction engine
 */
export class Redactor {
    config;
    constructor(config) {
        this.config = config;
    }
    /**
     * Redact sensitive data from content
     *
     * @param content - The content to redact
     * @returns Redaction result with sanitized output
     */
    redact(content) {
        // Get applicable patterns based on config
        const patterns = this.getApplicablePatterns();
        // Detect all matches
        const matches = this.detectMatches(content, patterns);
        // Filter by confidence threshold
        const validMatches = matches.filter(m => m.confidence >= this.config.minConfidence);
        // Sort by position (descending) for replacement
        validMatches.sort((a, b) => b.start - a.start);
        // Perform redaction
        let redactedContent = content;
        const entities = [];
        const positionAdjustments = [];
        for (const match of validMatches) {
            const placeholder = this.getPlaceholder(match);
            const originalLength = match.end - match.start;
            const newLength = placeholder.length;
            // Calculate redacted positions
            let redactedStart = match.start;
            let redactedEnd = match.start + newLength;
            // Adjust for previous replacements
            for (const adj of positionAdjustments) {
                if (match.start > adj.start) {
                    const adjustment = adj.newLength - adj.originalLength;
                    redactedStart += adjustment;
                    redactedEnd += adjustment;
                }
            }
            // Perform replacement
            redactedContent =
                redactedContent.slice(0, match.start) +
                    placeholder +
                    redactedContent.slice(match.end);
            // Track adjustment
            positionAdjustments.push({
                start: match.start,
                originalLength,
                newLength,
            });
            // Record entity (NO raw data)
            entities.push({
                entityType: match.pattern.type,
                category: match.pattern.category,
                originalStart: match.start,
                originalEnd: match.end,
                redactedStart,
                redactedEnd,
                confidence: match.confidence,
                severity: match.pattern.severity,
                patternId: match.pattern.id,
                strategyApplied: this.config.strategy,
                originalLength,
                redactedPlaceholder: placeholder,
            });
        }
        // Reverse entities to match original order
        entities.reverse();
        // Calculate aggregates
        const categoryCounts = this.countBy(entities, e => e.category);
        const severityCounts = this.countBy(entities, e => e.severity);
        const entityTypeCounts = this.countBy(entities, e => e.entityType);
        const detectedCategories = [...new Set(entities.map(e => e.category))];
        const severity = this.calculateMaxSeverity(entities);
        const confidence = this.calculateAverageConfidence(entities);
        const riskScore = this.calculateRiskScore(entities);
        return {
            dataRedacted: entities.length > 0,
            redactionCount: entities.length,
            originalRiskScore: riskScore,
            severity,
            confidence,
            redactedEntities: entities,
            redactedContent: this.config.returnRedactedContent ? redactedContent : undefined,
            detectedCategories,
            categoryCounts,
            severityCounts,
            entityTypeCounts,
        };
    }
    /**
     * Get applicable patterns based on config
     */
    getApplicablePatterns() {
        const patterns = [];
        if (this.config.detectPii) {
            let piiPatterns = PII_PATTERNS;
            if (this.config.piiTypes && this.config.piiTypes.length > 0) {
                piiPatterns = PII_PATTERNS.filter(p => this.config.piiTypes.includes(p.type));
            }
            patterns.push(...piiPatterns);
        }
        if (this.config.detectSecrets) {
            let secretPatterns = SECRET_PATTERNS;
            if (this.config.secretTypes && this.config.secretTypes.length > 0) {
                secretPatterns = SECRET_PATTERNS.filter(p => this.config.secretTypes.includes(p.type));
            }
            patterns.push(...secretPatterns);
        }
        if (this.config.detectCredentials) {
            patterns.push(...CREDENTIAL_PATTERNS);
        }
        return patterns;
    }
    /**
     * Detect all matches in content
     */
    detectMatches(content, patterns) {
        const matches = [];
        const seen = new Set(); // Avoid duplicate matches at same position
        for (const pattern of patterns) {
            // Create a fresh regex instance
            const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
            let match;
            while ((match = regex.exec(content)) !== null) {
                const key = `${match.index}-${match.index + match[0].length}`;
                if (seen.has(key))
                    continue;
                // Calculate confidence with sensitivity adjustment
                let confidence = pattern.baseConfidence;
                // Apply validation if available
                if (pattern.validate) {
                    if (!pattern.validate(match[0])) {
                        confidence *= 0.5; // Reduce confidence for failed validation
                    }
                }
                // Adjust by sensitivity (higher sensitivity = more matches accepted)
                confidence = confidence * (0.5 + this.config.sensitivity * 0.5);
                matches.push({
                    pattern,
                    matchText: match[0], // Internal use only
                    start: match.index,
                    end: match.index + match[0].length,
                    confidence: Math.min(1.0, confidence),
                    placeholder: '', // Will be set later
                });
                seen.add(key);
            }
        }
        return matches;
    }
    /**
     * Get placeholder for a match based on strategy
     */
    getPlaceholder(match) {
        const { strategy, customPlaceholder, partialMaskChars } = this.config;
        switch (strategy) {
            case 'mask':
                return customPlaceholder || `[${match.pattern.type.toUpperCase()}]`;
            case 'hash': {
                const hash = createHash('sha256')
                    .update(match.matchText)
                    .digest('hex')
                    .substring(0, 16);
                return `[HASH:${hash}]`;
            }
            case 'pseudonymize':
                return this.pseudonymize(match);
            case 'remove':
                return '';
            case 'partial_mask':
                return this.partialMask(match.matchText, partialMaskChars);
            default:
                return customPlaceholder || `[${match.pattern.type.toUpperCase()}]`;
        }
    }
    /**
     * Generate pseudonymized replacement
     */
    pseudonymize(match) {
        // Use hash to generate consistent pseudonym
        const hash = createHash('sha256')
            .update(match.matchText)
            .digest('hex');
        switch (match.pattern.type) {
            case 'email':
                return `user_${hash.substring(0, 8)}@example.com`;
            case 'phone_number':
                return `+1-555-${hash.substring(0, 3)}-${hash.substring(3, 7)}`;
            case 'ssn':
                return `XXX-XX-${hash.substring(0, 4)}`;
            case 'credit_card':
                return `****-****-****-${hash.substring(0, 4)}`;
            case 'ip_address':
                return `192.0.2.${parseInt(hash.substring(0, 2), 16) % 256}`;
            default:
                return `[REDACTED-${hash.substring(0, 8)}]`;
        }
    }
    /**
     * Apply partial masking
     */
    partialMask(text, preserveChars) {
        if (text.length <= preserveChars * 2) {
            return '*'.repeat(text.length);
        }
        const start = text.substring(0, preserveChars);
        const end = text.substring(text.length - preserveChars);
        const maskLength = text.length - preserveChars * 2;
        return start + '*'.repeat(maskLength) + end;
    }
    /**
     * Count entities by a key
     */
    countBy(items, keyFn) {
        const counts = {};
        for (const item of items) {
            const key = keyFn(item);
            counts[key] = (counts[key] || 0) + 1;
        }
        return counts;
    }
    /**
     * Calculate maximum severity
     */
    calculateMaxSeverity(entities) {
        const order = ['none', 'low', 'medium', 'high', 'critical'];
        let maxIndex = 0;
        for (const entity of entities) {
            const index = order.indexOf(entity.severity);
            if (index > maxIndex)
                maxIndex = index;
        }
        return order[maxIndex];
    }
    /**
     * Calculate average confidence
     */
    calculateAverageConfidence(entities) {
        if (entities.length === 0)
            return 0;
        const sum = entities.reduce((acc, e) => acc + e.confidence, 0);
        return sum / entities.length;
    }
    /**
     * Calculate risk score
     */
    calculateRiskScore(entities) {
        if (entities.length === 0)
            return 0;
        const severityWeights = {
            none: 0,
            low: 0.25,
            medium: 0.5,
            high: 0.75,
            critical: 1.0,
        };
        let totalScore = 0;
        for (const entity of entities) {
            totalScore += severityWeights[entity.severity] * entity.confidence;
        }
        return Math.min(1, totalScore / entities.length);
    }
}
/**
 * Compute SHA-256 hash of content
 */
export function hashContent(content) {
    return createHash('sha256').update(content).digest('hex');
}
//# sourceMappingURL=redactor.js.map