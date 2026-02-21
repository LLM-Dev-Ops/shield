/**
 * Toxicity Detector
 *
 * Core detection logic for the Toxicity Detection Agent.
 * Handles pattern matching, scoring, and confidence calculation.
 *
 * @module toxicity-detection-agent/detector
 */
import { TOXICITY_PATTERNS, normalizeText, expandCensoredPattern, } from './patterns.js';
import { DEFAULT_TOXICITY_CATEGORIES, DEFAULT_THRESHOLD, DEFAULT_SENSITIVITY, } from './types.js';
/**
 * Toxicity Detector class
 *
 * Detects toxic content in text using pattern matching and heuristics.
 * This class is stateless and can be reused across invocations.
 */
export class ToxicityDetector {
    patterns;
    constructor() {
        this.patterns = TOXICITY_PATTERNS;
    }
    /**
     * Detect toxicity in content
     *
     * @param content - Text content to analyze
     * @param config - Detection configuration
     * @returns Array of pattern matches
     */
    detect(content, config) {
        const matches = [];
        const normalizedContent = normalizeText(content);
        // Filter patterns based on config
        const applicablePatterns = this.filterPatterns(config);
        for (const pattern of applicablePatterns) {
            const patternMatches = this.matchPattern(content, normalizedContent, pattern, config);
            matches.push(...patternMatches);
        }
        // Remove overlapping matches, keeping highest confidence
        const deduplicatedMatches = this.deduplicateMatches(matches);
        // Filter by threshold
        return deduplicatedMatches.filter(m => m.confidence >= config.threshold);
    }
    /**
     * Match a single pattern against content
     */
    matchPattern(originalContent, normalizedContent, pattern, config) {
        const matches = [];
        const contentToSearch = pattern.caseSensitive ? originalContent : normalizedContent;
        // Check for keyword matches
        for (const keyword of pattern.keywords) {
            const normalizedKeyword = pattern.caseSensitive ? keyword : keyword.toLowerCase();
            // Handle censored patterns (containing asterisks)
            if (keyword.includes('*')) {
                const regex = expandCensoredPattern(normalizedKeyword);
                let match;
                while ((match = regex.exec(contentToSearch)) !== null) {
                    const contextValid = this.checkContext(contentToSearch, match.index, pattern);
                    if (contextValid) {
                        matches.push({
                            pattern,
                            start: match.index,
                            end: match.index + match[0].length,
                            matchedText: match[0], // For internal scoring only
                            confidence: this.calculateConfidence(pattern, config.sensitivity, 1),
                            indicatorCount: 1,
                        });
                    }
                }
            }
            else {
                // Direct keyword search
                let searchIndex = 0;
                while (true) {
                    const index = contentToSearch.indexOf(normalizedKeyword, searchIndex);
                    if (index === -1)
                        break;
                    // Check for word boundaries
                    const beforeChar = index > 0 ? contentToSearch[index - 1] : ' ';
                    const afterChar = index + normalizedKeyword.length < contentToSearch.length
                        ? contentToSearch[index + normalizedKeyword.length]
                        : ' ';
                    const isWordBoundary = !/\w/.test(beforeChar) && !/\w/.test(afterChar);
                    if (isWordBoundary) {
                        const contextValid = this.checkContext(contentToSearch, index, pattern);
                        if (contextValid) {
                            matches.push({
                                pattern,
                                start: index,
                                end: index + normalizedKeyword.length,
                                matchedText: originalContent.substring(index, index + normalizedKeyword.length),
                                confidence: this.calculateConfidence(pattern, config.sensitivity, 1),
                                indicatorCount: 1,
                            });
                        }
                    }
                    searchIndex = index + 1;
                }
            }
        }
        // Check regex pattern if present
        if (pattern.pattern) {
            const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
            let match;
            while ((match = regex.exec(contentToSearch)) !== null) {
                const contextValid = this.checkContext(contentToSearch, match.index, pattern);
                if (contextValid) {
                    matches.push({
                        pattern,
                        start: match.index,
                        end: match.index + match[0].length,
                        matchedText: match[0],
                        confidence: this.calculateConfidence(pattern, config.sensitivity, 1),
                        indicatorCount: 1,
                    });
                }
            }
        }
        return matches;
    }
    /**
     * Check if required context is present
     */
    checkContext(content, matchIndex, pattern) {
        if (!pattern.contextRequired || pattern.contextRequired.length === 0) {
            return true;
        }
        // Look for context words within a window around the match
        const windowSize = 50;
        const start = Math.max(0, matchIndex - windowSize);
        const end = Math.min(content.length, matchIndex + windowSize);
        const window = content.substring(start, end).toLowerCase();
        return pattern.contextRequired.some(ctx => window.includes(ctx.toLowerCase()));
    }
    /**
     * Filter patterns based on configuration
     */
    filterPatterns(config) {
        return this.patterns.filter(pattern => config.detectCategories.includes(pattern.category));
    }
    /**
     * Calculate confidence based on pattern, sensitivity, and indicators
     */
    calculateConfidence(pattern, sensitivity, indicatorCount) {
        let confidence = pattern.baseConfidence;
        // Adjust based on indicator count (more indicators = higher confidence)
        if (indicatorCount > 1) {
            confidence = Math.min(1.0, confidence + (indicatorCount - 1) * 0.05);
        }
        // Adjust based on sensitivity (higher sensitivity = more lenient)
        const sensitivityAdjustment = (sensitivity - 0.5) * 0.1;
        confidence = Math.min(1.0, Math.max(0, confidence + sensitivityAdjustment));
        return Math.round(confidence * 100) / 100;
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
                // But aggregate indicator count if same pattern category
                const existing = result[result.length - 1];
                if (existing && existing.pattern.category === match.pattern.category) {
                    existing.indicatorCount++;
                    existing.confidence = Math.min(1.0, existing.confidence + 0.05);
                }
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
            sensitivity: input.sensitivity ?? DEFAULT_SENSITIVITY,
            threshold: input.threshold ?? DEFAULT_THRESHOLD,
            detectCategories: input.detect_categories ?? DEFAULT_TOXICITY_CATEGORIES,
        };
    }
}
//# sourceMappingURL=detector.js.map