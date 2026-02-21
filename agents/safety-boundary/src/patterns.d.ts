/**
 * @module patterns
 * @description Safety boundary detection patterns
 *
 * These patterns detect content that violates safety boundaries.
 * Pattern IDs follow format: sb-{category}-{number}
 */
import type { SafetyBoundaryCategory } from '@llm-shield/agentics-contracts';
import type { SafetyPattern } from './types.js';
/**
 * All safety categories
 */
export declare const SAFETY_CATEGORIES: SafetyBoundaryCategory[];
/**
 * Safety boundary detection patterns
 */
export declare const SAFETY_PATTERNS: SafetyPattern[];
/**
 * Get patterns for specific categories
 */
export declare function getPatternsForCategories(categories: SafetyBoundaryCategory[]): SafetyPattern[];
/**
 * Get all patterns
 */
export declare function getAllPatterns(): SafetyPattern[];
/**
 * Get pattern by ID
 */
export declare function getPatternById(id: string): SafetyPattern | undefined;
/**
 * Pattern count by category
 */
export declare function getPatternCountByCategory(): Record<string, number>;
