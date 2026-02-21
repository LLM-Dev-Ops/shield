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
export function calculateEntropy(str) {
    if (!str || str.length === 0) {
        return 0;
    }
    // Count character frequencies
    const freq = new Map();
    for (const char of str) {
        freq.set(char, (freq.get(char) || 0) + 1);
    }
    // Calculate Shannon entropy
    const len = str.length;
    let entropy = 0;
    for (const count of freq.values()) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}
/**
 * Token patterns that might contain secrets
 */
const TOKEN_PATTERNS = [
    // Key=value assignments
    /(?:api[_-]?key|secret|token|password|passwd|pwd|auth|credential|access[_-]?key)["']?\s*[:=]\s*["']?([a-zA-Z0-9+/=_-]{16,})/gi,
    // Environment variable style
    /(?:[A-Z_]+(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL))=([a-zA-Z0-9+/=_-]{16,})/g,
    // Quoted long random strings
    /["']([a-zA-Z0-9+/=_-]{32,})["']/g,
    // Bearer tokens
    /Bearer\s+([a-zA-Z0-9._-]{20,})/gi,
    // Basic auth
    /Basic\s+([a-zA-Z0-9+/=]{16,})/gi,
];
/**
 * Find high-entropy candidates in content
 *
 * @param content - Content to analyze
 * @param threshold - Minimum entropy threshold (default: 4.5)
 * @param minLength - Minimum string length to consider (default: 16)
 * @returns Array of entropy candidates
 */
export function findEntropySecrets(content, threshold = 4.5, minLength = 16) {
    const candidates = [];
    const seen = new Set();
    for (const pattern of TOKEN_PATTERNS) {
        // Reset regex state
        const regex = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = regex.exec(content)) !== null) {
            const value = match[1] || match[0];
            // Skip if already seen or too short
            if (seen.has(value) || value.length < minLength) {
                continue;
            }
            seen.add(value);
            const entropy = calculateEntropy(value);
            if (entropy >= threshold) {
                // Find actual position in content
                const valueIndex = content.indexOf(value, match.index);
                candidates.push({
                    value,
                    start: valueIndex >= 0 ? valueIndex : match.index,
                    end: (valueIndex >= 0 ? valueIndex : match.index) + value.length,
                    entropy,
                });
            }
        }
    }
    // Sort by entropy (highest first)
    return candidates.sort((a, b) => b.entropy - a.entropy);
}
/**
 * Check if a string looks like a potential secret based on character distribution
 *
 * @param str - String to check
 * @returns True if the string has characteristics of a secret
 */
export function looksLikeSecret(str) {
    if (str.length < 16) {
        return false;
    }
    // Check for mixed character types (indicator of randomness)
    const hasLower = /[a-z]/.test(str);
    const hasUpper = /[A-Z]/.test(str);
    const hasDigit = /[0-9]/.test(str);
    const hasSpecial = /[+/=_-]/.test(str);
    // At least 3 character types for short strings, 2 for longer
    const typeCount = [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length;
    if (str.length < 32) {
        return typeCount >= 3;
    }
    return typeCount >= 2;
}
//# sourceMappingURL=entropy.js.map