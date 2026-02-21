/**
 * @module secrets-leakage-detection/entropy
 * @description Shannon entropy calculation for generic secret detection
 */
/**
 * Calculate Shannon entropy of a string
 * Higher entropy indicates more randomness (likely a secret)
 *
 * @param str - The string to analyze
 * @returns Entropy value (0.0 - 8.0 for ASCII)
 */
export declare function calculateEntropy(str: string): number;
/**
 * Find high-entropy substrings in content
 * These are candidates for generic secret detection
 */
export interface EntropyCandidate {
    /** The high-entropy substring */
    value: string;
    /** Start position in original content */
    start: number;
    /** End position in original content */
    end: number;
    /** Calculated entropy value */
    entropy: number;
}
/**
 * Find high-entropy candidates in content
 *
 * @param content - Content to analyze
 * @param threshold - Minimum entropy threshold (default: 4.5)
 * @param minLength - Minimum string length to consider (default: 16)
 * @returns Array of entropy candidates
 */
export declare function findEntropySecrets(content: string, threshold?: number, minLength?: number): EntropyCandidate[];
/**
 * Check if a string looks like a potential secret based on character distribution
 *
 * @param str - String to check
 * @returns True if the string has characteristics of a secret
 */
export declare function looksLikeSecret(str: string): boolean;
