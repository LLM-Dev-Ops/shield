/**
 * PII Detector
 *
 * Core detection logic for the PII Detection Agent.
 * Handles pattern matching, validation, and confidence calculation.
 *
 * @module pii-detection-agent/detector
 */
import { PII_PATTERNS } from './patterns.js';
import { DEFAULT_PII_TYPES, DEFAULT_COUNTRIES } from './types.js';
/**
 * PII Detector class
 *
 * Detects PII in text content using pattern matching and validation.
 * This class is stateless and can be reused across invocations.
 */
export class PIIDetector {
    patterns;
    constructor() {
        this.patterns = PII_PATTERNS;
    }
    /**
     * Detect PII in content
     *
     * @param content - Text content to analyze
     * @param config - Detection configuration
     * @returns Array of pattern matches
     */
    detect(content, config) {
        const matches = [];
        // Filter patterns based on config
        const applicablePatterns = this.filterPatterns(config);
        for (const pattern of applicablePatterns) {
            // Create new regex instance to reset lastIndex
            const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
            let match;
            while ((match = regex.exec(content)) !== null) {
                const matchedText = match[0];
                const start = match.index;
                const end = start + matchedText.length;
                // Validate the match
                const validationPassed = this.validate(matchedText, pattern);
                // Calculate confidence based on validation and sensitivity
                const confidence = this.calculateConfidence(pattern, validationPassed, config.sensitivity);
                // Only include if confidence meets threshold
                if (confidence >= this.getConfidenceThreshold(config.sensitivity)) {
                    matches.push({
                        pattern,
                        start,
                        end,
                        matchedText, // Only for internal use, NOT persisted
                        validationPassed,
                        confidence,
                    });
                }
            }
        }
        // Remove overlapping matches, keeping highest confidence
        return this.deduplicateMatches(matches);
    }
    /**
     * Filter patterns based on configuration
     */
    filterPatterns(config) {
        return this.patterns.filter(pattern => {
            // Check if type is in detect types
            if (!config.detectTypes.includes(pattern.type)) {
                return false;
            }
            // Check if pattern applies to configured countries
            if (pattern.countries && pattern.countries.length > 0) {
                const hasMatchingCountry = pattern.countries.some(c => config.countries.includes(c));
                if (!hasMatchingCountry) {
                    return false;
                }
            }
            return true;
        });
    }
    /**
     * Validate a matched value
     */
    validate(value, pattern) {
        switch (pattern.validationMethod) {
            case 'luhn':
                return this.luhnCheck(value);
            case 'area_check':
                return this.ssnAreaCheck(value);
            case 'format':
                return this.formatCheck(value, pattern);
            case 'checksum':
                return true; // Generic checksum validation
            default:
                return true; // No validation required
        }
    }
    /**
     * Luhn algorithm for credit card validation
     */
    luhnCheck(value) {
        const digits = value.replace(/\D/g, '');
        if (digits.length < 13 || digits.length > 19) {
            return false;
        }
        let sum = 0;
        let isEven = false;
        for (let i = digits.length - 1; i >= 0; i--) {
            let digit = parseInt(digits[i], 10);
            if (isEven) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }
            sum += digit;
            isEven = !isEven;
        }
        return sum % 10 === 0;
    }
    /**
     * SSN area number validation
     * - Area numbers 000, 666, and 900-999 are invalid
     * - Group number 00 is invalid
     * - Serial number 0000 is invalid
     */
    ssnAreaCheck(value) {
        const digits = value.replace(/\D/g, '');
        if (digits.length !== 9) {
            return false;
        }
        const area = parseInt(digits.substring(0, 3), 10);
        const group = parseInt(digits.substring(3, 5), 10);
        const serial = parseInt(digits.substring(5, 9), 10);
        // Invalid area numbers
        if (area === 0 || area === 666 || area >= 900) {
            return false;
        }
        // Invalid group number
        if (group === 0) {
            return false;
        }
        // Invalid serial number
        if (serial === 0) {
            return false;
        }
        return true;
    }
    /**
     * Basic format validation
     */
    formatCheck(value, pattern) {
        switch (pattern.type) {
            case 'email':
                return value.includes('@') && value.includes('.');
            case 'ip_address':
                return this.validateIPAddress(value);
            default:
                return true;
        }
    }
    /**
     * Validate IP address ranges
     */
    validateIPAddress(value) {
        // IPv4 validation
        if (value.includes('.')) {
            const parts = value.split('.');
            if (parts.length !== 4)
                return false;
            for (const part of parts) {
                const num = parseInt(part, 10);
                if (isNaN(num) || num < 0 || num > 255)
                    return false;
            }
            return true;
        }
        // IPv6 validation (simplified)
        if (value.includes(':')) {
            const parts = value.split(':').filter(p => p.length > 0);
            return parts.length >= 2 && parts.length <= 8;
        }
        return false;
    }
    /**
     * Calculate confidence based on pattern, validation, and sensitivity
     */
    calculateConfidence(pattern, validationPassed, sensitivity) {
        let confidence = pattern.baseConfidence;
        // Adjust confidence based on validation
        if (pattern.validationMethod) {
            if (validationPassed) {
                confidence = Math.min(1.0, confidence + 0.05); // Boost for valid
            }
            else {
                confidence = Math.max(0, confidence - 0.20); // Penalty for invalid
            }
        }
        // Adjust based on sensitivity (higher sensitivity = more lenient)
        const sensitivityAdjustment = (sensitivity - 0.5) * 0.1;
        confidence = Math.min(1.0, Math.max(0, confidence + sensitivityAdjustment));
        return Math.round(confidence * 100) / 100; // Round to 2 decimal places
    }
    /**
     * Get confidence threshold based on sensitivity
     */
    getConfidenceThreshold(sensitivity) {
        // Lower sensitivity = higher threshold (fewer matches)
        // Higher sensitivity = lower threshold (more matches)
        return Math.max(0.3, 0.7 - sensitivity * 0.4);
    }
    /**
     * Remove overlapping matches, keeping highest confidence
     */
    deduplicateMatches(matches) {
        if (matches.length <= 1)
            return matches;
        // Sort by start position, then by confidence (descending)
        const sorted = [...matches].sort((a, b) => {
            if (a.start !== b.start)
                return a.start - b.start;
            return b.confidence - a.confidence;
        });
        const result = [];
        let lastEnd = -1;
        for (const match of sorted) {
            // Skip if this match overlaps with a previous one
            if (match.start < lastEnd) {
                continue;
            }
            result.push(match);
            lastEnd = match.end;
        }
        return result;
    }
    /**
     * Calculate overall risk score from matches
     */
    calculateRiskScore(matches) {
        if (matches.length === 0)
            return 0;
        const severityWeights = {
            none: 0,
            low: 0.25,
            medium: 0.5,
            high: 0.75,
            critical: 1.0,
        };
        let totalScore = 0;
        let maxSeverityWeight = 0;
        for (const match of matches) {
            const weight = severityWeights[match.pattern.severity];
            totalScore += weight * match.confidence;
            maxSeverityWeight = Math.max(maxSeverityWeight, weight);
        }
        // Combine average score with max severity influence
        const avgScore = totalScore / matches.length;
        const riskScore = avgScore * 0.6 + maxSeverityWeight * 0.4;
        return Math.min(1.0, Math.round(riskScore * 100) / 100);
    }
    /**
     * Get maximum severity from matches
     */
    getMaxSeverity(matches) {
        if (matches.length === 0)
            return 'none';
        const severityOrder = ['none', 'low', 'medium', 'high', 'critical'];
        let maxIndex = 0;
        for (const match of matches) {
            const index = severityOrder.indexOf(match.pattern.severity);
            if (index > maxIndex) {
                maxIndex = index;
            }
        }
        return severityOrder[maxIndex];
    }
    /**
     * Create default detection configuration
     */
    static createDefaultConfig(input) {
        return {
            sensitivity: input.sensitivity ?? 0.5,
            detectTypes: input.detect_types ?? DEFAULT_PII_TYPES,
            countries: input.countries ?? DEFAULT_COUNTRIES,
        };
    }
}
//# sourceMappingURL=detector.js.map