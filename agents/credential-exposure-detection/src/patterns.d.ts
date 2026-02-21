/**
 * @module credential-exposure-detection/patterns
 * @description Credential detection patterns for the Credential Exposure Detection Agent
 *
 * These patterns detect accidental exposure of usernames, passwords, access keys,
 * or authentication artifacts in LLM inputs/outputs.
 *
 * IMPORTANT: These patterns are designed for DETECTION ONLY.
 * Raw credentials are NEVER stored or transmitted.
 */
import type { CredentialType } from '@llm-shield/agentics-contracts';
/**
 * Credential pattern interface
 */
export interface CredentialPattern {
    /** Unique pattern identifier */
    pattern_id: string;
    /** Regular expression for matching */
    regex: RegExp;
    /** Category of credential */
    category: CredentialType;
    /** Default severity for matches */
    severity: 'low' | 'medium' | 'high' | 'critical';
    /** Base confidence for pattern matches */
    confidence: number;
    /** Human-readable description */
    description: string;
    /** Whether this pattern detects a credential pair (username + password) */
    is_pair: boolean;
    /** Whether this pattern detects usernames */
    detects_username: boolean;
    /** Whether this pattern detects passwords/secrets */
    detects_password: boolean;
    /** Context hint for the detection */
    context_hint?: string;
}
/**
 * Built-in credential detection patterns organized by category
 */
export declare const CREDENTIAL_PATTERNS: ReadonlyArray<CredentialPattern>;
/**
 * Get patterns filtered by category
 */
export declare function getPatternsByCategory(categories?: CredentialType[]): CredentialPattern[];
/**
 * Get patterns that detect credential pairs only
 */
export declare function getPairPatterns(): CredentialPattern[];
/**
 * Get patterns that detect passwords only (not pairs)
 */
export declare function getPasswordOnlyPatterns(): CredentialPattern[];
/**
 * Get patterns that detect usernames only (not pairs)
 */
export declare function getUsernameOnlyPatterns(): CredentialPattern[];
/**
 * Get auth header patterns
 */
export declare function getAuthHeaderPatterns(): CredentialPattern[];
/**
 * Create custom pattern from user input
 */
export declare function createCustomPattern(patternId: string, regexStr: string, category?: CredentialType): CredentialPattern | null;
