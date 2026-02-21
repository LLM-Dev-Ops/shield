/**
 * @module patterns
 * @description Content moderation detection patterns
 *
 * These patterns detect content that violates moderation policies.
 * Pattern IDs follow format: cm-{category}-{number}
 */
import type { ContentModerationCategory } from '@llm-shield/agentics-contracts';
import type { ModerationPattern } from './types.js';
/**
 * All moderation categories
 */
export declare const MODERATION_CATEGORIES: ContentModerationCategory[];
/**
 * Content moderation detection patterns
 */
export declare const MODERATION_PATTERNS: ModerationPattern[];
/**
 * Get patterns for specific categories
 */
export declare function getPatternsForCategories(categories: ContentModerationCategory[]): ModerationPattern[];
/**
 * Get all patterns
 */
export declare function getAllPatterns(): ModerationPattern[];
/**
 * Get pattern by ID
 */
export declare function getPatternById(id: string): ModerationPattern | undefined;
/**
 * Pattern count by category
 */
export declare function getPatternCountByCategory(): Record<string, number>;
