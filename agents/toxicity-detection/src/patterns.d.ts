/**
 * Toxicity Detection Patterns
 *
 * Defines patterns for detecting various categories of toxic content.
 * These patterns are used for heuristic-based detection.
 *
 * IMPORTANT: This file contains examples of toxic language for detection purposes only.
 * These patterns are necessary for content moderation and safety.
 *
 * @module toxicity-detection-agent/patterns
 */
import type { ToxicityPattern } from './types.js';
/**
 * All toxicity patterns combined
 */
export declare const TOXICITY_PATTERNS: ToxicityPattern[];
/**
 * Get patterns by category
 */
export declare function getPatternsByCategory(category: string): ToxicityPattern[];
/**
 * Get all pattern categories
 */
export declare function getAllCategories(): string[];
/**
 * Normalize text for matching (lowercase, remove extra whitespace)
 */
export declare function normalizeText(text: string): string;
/**
 * Expand asterisk censoring for matching
 * e.g., "f***" matches "fuck", "f*ck" matches "fuck"
 */
export declare function expandCensoredPattern(pattern: string): RegExp;
