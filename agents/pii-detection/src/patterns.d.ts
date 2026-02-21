/**
 * PII Detection Patterns
 *
 * Contains all pattern definitions for detecting various types of PII.
 * Patterns are organized by PII type and include validation methods
 * where applicable.
 *
 * @module pii-detection-agent/patterns
 */
import type { PIIPattern } from './types.js';
/**
 * All PII patterns organized for export
 */
export declare const PII_PATTERNS: PIIPattern[];
/**
 * Get patterns by PII type
 */
export declare function getPatternsByType(type: string): PIIPattern[];
/**
 * Get patterns by country
 */
export declare function getPatternsByCountry(country: string): PIIPattern[];
/**
 * Get pattern by ID
 */
export declare function getPatternById(id: string): PIIPattern | undefined;
