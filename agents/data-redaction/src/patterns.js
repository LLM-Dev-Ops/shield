/**
 * Detection patterns for the Data Redaction Agent
 *
 * IMPORTANT: These patterns are used for DETECTION only.
 * Raw matched content is NEVER persisted to ruvector-service.
 */
// =============================================================================
// PII PATTERNS
// =============================================================================
export const PII_PATTERNS = [
    // Email addresses
    {
        id: 'pii-email',
        category: 'pii',
        type: 'email',
        pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
        severity: 'medium',
        baseConfidence: 0.95,
        validate: (match) => match.includes('@') && match.includes('.'),
    },
    // Phone numbers (US format)
    {
        id: 'pii-phone-us',
        category: 'pii',
        type: 'phone_number',
        pattern: /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
        severity: 'medium',
        baseConfidence: 0.85,
    },
    // Phone numbers (UK format)
    {
        id: 'pii-phone-uk',
        category: 'pii',
        type: 'phone_number',
        pattern: /\b\+44\s?[0-9]{4}\s?[0-9]{6}\b/g,
        severity: 'medium',
        baseConfidence: 0.85,
    },
    // Phone numbers (international)
    {
        id: 'pii-phone-intl',
        category: 'pii',
        type: 'phone_number',
        pattern: /\b\+[1-9]\d{1,14}\b/g,
        severity: 'medium',
        baseConfidence: 0.75,
    },
    // SSN (dashed format)
    {
        id: 'pii-ssn-dashed',
        category: 'pii',
        type: 'ssn',
        pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
        severity: 'critical',
        baseConfidence: 0.95,
        validate: (match) => {
            const cleaned = match.replace(/\D/g, '');
            if (cleaned.length !== 9)
                return false;
            const area = parseInt(cleaned.substring(0, 3));
            return area !== 0 && area !== 666 && area < 900;
        },
    },
    // SSN (spaced format)
    {
        id: 'pii-ssn-spaced',
        category: 'pii',
        type: 'ssn',
        pattern: /\b\d{3}\s\d{2}\s\d{4}\b/g,
        severity: 'critical',
        baseConfidence: 0.90,
        validate: (match) => {
            const cleaned = match.replace(/\D/g, '');
            if (cleaned.length !== 9)
                return false;
            const area = parseInt(cleaned.substring(0, 3));
            return area !== 0 && area !== 666 && area < 900;
        },
    },
    // Credit Card - Visa
    {
        id: 'pii-cc-visa',
        category: 'pii',
        type: 'credit_card',
        pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/g,
        severity: 'critical',
        baseConfidence: 0.99,
        validate: luhnCheck,
    },
    // Credit Card - Mastercard
    {
        id: 'pii-cc-mastercard',
        category: 'pii',
        type: 'credit_card',
        pattern: /\b5[1-5][0-9]{14}\b/g,
        severity: 'critical',
        baseConfidence: 0.99,
        validate: luhnCheck,
    },
    // Credit Card - Amex
    {
        id: 'pii-cc-amex',
        category: 'pii',
        type: 'credit_card',
        pattern: /\b3[47][0-9]{13}\b/g,
        severity: 'critical',
        baseConfidence: 0.99,
        validate: luhnCheck,
    },
    // Credit Card - Discover
    {
        id: 'pii-cc-discover',
        category: 'pii',
        type: 'credit_card',
        pattern: /\b6(?:011|5[0-9]{2})[0-9]{12}\b/g,
        severity: 'critical',
        baseConfidence: 0.99,
        validate: luhnCheck,
    },
    // IPv4 Address
    {
        id: 'pii-ipv4',
        category: 'pii',
        type: 'ip_address',
        pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
        severity: 'low',
        baseConfidence: 0.90,
    },
    // IPv6 Address
    {
        id: 'pii-ipv6',
        category: 'pii',
        type: 'ip_address',
        pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
        severity: 'low',
        baseConfidence: 0.90,
    },
    // US Passport
    {
        id: 'pii-passport-us',
        category: 'pii',
        type: 'passport',
        pattern: /\b[A-Z][0-9]{8}\b/g,
        severity: 'high',
        baseConfidence: 0.80,
    },
    // Driver's License (general US pattern)
    {
        id: 'pii-drivers-license',
        category: 'pii',
        type: 'drivers_license',
        pattern: /\b[A-Z][0-9]{7,8}\b/g,
        severity: 'high',
        baseConfidence: 0.70,
    },
    // Date of Birth patterns
    {
        id: 'pii-dob-iso',
        category: 'pii',
        type: 'date_of_birth',
        pattern: /\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b/g,
        severity: 'medium',
        baseConfidence: 0.70,
    },
    {
        id: 'pii-dob-us',
        category: 'pii',
        type: 'date_of_birth',
        pattern: /\b(?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])[-/](?:19|20)\d{2}\b/g,
        severity: 'medium',
        baseConfidence: 0.70,
    },
    // Bank Account (routing + account)
    {
        id: 'pii-bank-routing',
        category: 'pii',
        type: 'bank_account',
        pattern: /\b\d{9}\s*[-–]\s*\d{10,12}\b/g,
        severity: 'critical',
        baseConfidence: 0.85,
    },
];
// =============================================================================
// SECRET PATTERNS
// =============================================================================
export const SECRET_PATTERNS = [
    // AWS Access Key ID
    {
        id: 'secret-aws-access-key',
        category: 'secret',
        type: 'aws_credentials',
        pattern: /AKIA[0-9A-Z]{16}/g,
        severity: 'critical',
        baseConfidence: 0.99,
    },
    // AWS Secret Access Key
    {
        id: 'secret-aws-secret',
        category: 'secret',
        type: 'aws_credentials',
        pattern: /aws[_-]?secret[_-]?access[_-]?key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}/gi,
        severity: 'critical',
        baseConfidence: 0.95,
    },
    // GitHub Personal Access Token
    {
        id: 'secret-github-pat',
        category: 'secret',
        type: 'github_token',
        pattern: /ghp_[a-zA-Z0-9]{36}/g,
        severity: 'high',
        baseConfidence: 0.99,
    },
    // GitHub OAuth Token
    {
        id: 'secret-github-oauth',
        category: 'secret',
        type: 'github_token',
        pattern: /gho_[a-zA-Z0-9]{36}/g,
        severity: 'high',
        baseConfidence: 0.99,
    },
    // GitHub App Token
    {
        id: 'secret-github-app',
        category: 'secret',
        type: 'github_token',
        pattern: /ghs_[a-zA-Z0-9]{36}/g,
        severity: 'high',
        baseConfidence: 0.99,
    },
    // GitHub Refresh Token
    {
        id: 'secret-github-refresh',
        category: 'secret',
        type: 'github_token',
        pattern: /ghr_[a-zA-Z0-9]{36}/g,
        severity: 'high',
        baseConfidence: 0.99,
    },
    // GitHub Fine-grained PAT
    {
        id: 'secret-github-fine-pat',
        category: 'secret',
        type: 'github_token',
        pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g,
        severity: 'high',
        baseConfidence: 0.99,
    },
    // Stripe Live Secret Key
    {
        id: 'secret-stripe-live',
        category: 'secret',
        type: 'stripe_key',
        pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
        severity: 'critical',
        baseConfidence: 0.99,
    },
    // Stripe Test Secret Key
    {
        id: 'secret-stripe-test',
        category: 'secret',
        type: 'stripe_key',
        pattern: /sk_test_[0-9a-zA-Z]{24,}/g,
        severity: 'medium',
        baseConfidence: 0.99,
    },
    // Stripe Live Publishable Key
    {
        id: 'secret-stripe-pub',
        category: 'secret',
        type: 'stripe_key',
        pattern: /pk_live_[0-9a-zA-Z]{24,}/g,
        severity: 'low',
        baseConfidence: 0.99,
    },
    // Stripe Restricted Key
    {
        id: 'secret-stripe-restricted',
        category: 'secret',
        type: 'stripe_key',
        pattern: /rk_live_[0-9a-zA-Z]{24,}/g,
        severity: 'high',
        baseConfidence: 0.99,
    },
    // OpenAI API Key
    {
        id: 'secret-openai',
        category: 'secret',
        type: 'openai_key',
        pattern: /sk-[a-zA-Z0-9]{48}/g,
        severity: 'high',
        baseConfidence: 0.95,
    },
    // OpenAI Project API Key
    {
        id: 'secret-openai-project',
        category: 'secret',
        type: 'openai_key',
        pattern: /sk-proj-[a-zA-Z0-9]{48}/g,
        severity: 'high',
        baseConfidence: 0.99,
    },
    // Anthropic API Key
    {
        id: 'secret-anthropic',
        category: 'secret',
        type: 'anthropic_key',
        pattern: /sk-ant-[a-zA-Z0-9-]{32,}/g,
        severity: 'high',
        baseConfidence: 0.99,
    },
    // Slack Token
    {
        id: 'secret-slack-token',
        category: 'secret',
        type: 'slack_token',
        pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g,
        severity: 'high',
        baseConfidence: 0.99,
    },
    // Slack Webhook URL
    {
        id: 'secret-slack-webhook',
        category: 'secret',
        type: 'slack_token',
        pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,}\/B[a-zA-Z0-9_]{8,}\/[a-zA-Z0-9_]{24}/g,
        severity: 'high',
        baseConfidence: 0.99,
    },
    // Google API Key
    {
        id: 'secret-google-api',
        category: 'secret',
        type: 'google_api_key',
        pattern: /AIza[0-9A-Za-z\-_]{35}/g,
        severity: 'high',
        baseConfidence: 0.99,
    },
    // Google OAuth Client ID
    {
        id: 'secret-google-oauth',
        category: 'secret',
        type: 'google_api_key',
        pattern: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
        severity: 'medium',
        baseConfidence: 0.95,
    },
    // Private Key (PEM format)
    {
        id: 'secret-private-key',
        category: 'secret',
        type: 'private_key',
        pattern: /-----BEGIN (RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/g,
        severity: 'critical',
        baseConfidence: 0.99,
    },
    // Encrypted Private Key
    {
        id: 'secret-encrypted-key',
        category: 'secret',
        type: 'private_key',
        pattern: /-----BEGIN ENCRYPTED PRIVATE KEY-----/g,
        severity: 'high',
        baseConfidence: 0.99,
    },
    // JWT Token
    {
        id: 'secret-jwt',
        category: 'secret',
        type: 'jwt_token',
        pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
        severity: 'high',
        baseConfidence: 0.95,
    },
    // Generic API Key
    {
        id: 'secret-generic-apikey',
        category: 'secret',
        type: 'generic_api_key',
        pattern: /api[_-]?key["']?\s*[:=]\s*["']?[a-zA-Z0-9]{32,}/gi,
        severity: 'medium',
        baseConfidence: 0.80,
    },
    // Generic Secret
    {
        id: 'secret-generic-secret',
        category: 'secret',
        type: 'generic_secret',
        pattern: /secret["']?\s*[:=]\s*["']?[a-zA-Z0-9]{32,}/gi,
        severity: 'medium',
        baseConfidence: 0.75,
    },
    // Generic Token
    {
        id: 'secret-generic-token',
        category: 'secret',
        type: 'generic_secret',
        pattern: /token["']?\s*[:=]\s*["']?[a-zA-Z0-9-_]{20,}/gi,
        severity: 'medium',
        baseConfidence: 0.70,
    },
];
// =============================================================================
// CREDENTIAL PATTERNS
// =============================================================================
export const CREDENTIAL_PATTERNS = [
    // Password in assignment
    {
        id: 'cred-password',
        category: 'credential',
        type: 'password',
        pattern: /password["']?\s*[:=]\s*["']?[^\s'"]{8,}/gi,
        severity: 'high',
        baseConfidence: 0.85,
    },
    // PostgreSQL URL
    {
        id: 'cred-postgres-url',
        category: 'credential',
        type: 'database_url',
        pattern: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^/]+\/[^\s'"]+/gi,
        severity: 'critical',
        baseConfidence: 0.95,
    },
    // MySQL URL
    {
        id: 'cred-mysql-url',
        category: 'credential',
        type: 'database_url',
        pattern: /mysql:\/\/[^:]+:[^@]+@[^/]+\/[^\s'"]+/gi,
        severity: 'critical',
        baseConfidence: 0.95,
    },
    // MongoDB URL
    {
        id: 'cred-mongodb-url',
        category: 'credential',
        type: 'database_url',
        pattern: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^/]+/gi,
        severity: 'critical',
        baseConfidence: 0.95,
    },
    // Redis URL
    {
        id: 'cred-redis-url',
        category: 'credential',
        type: 'database_url',
        pattern: /redis:\/\/[^:]+:[^@]+@[^/]+/gi,
        severity: 'critical',
        baseConfidence: 0.95,
    },
    // MSSQL Connection String
    {
        id: 'cred-mssql-conn',
        category: 'credential',
        type: 'connection_string',
        pattern: /Server=[^;]+;.*Password=[^;]+/gi,
        severity: 'critical',
        baseConfidence: 0.90,
    },
    // JDBC Connection String
    {
        id: 'cred-jdbc-conn',
        category: 'credential',
        type: 'connection_string',
        pattern: /jdbc:[a-z]+:\/\/[^:]+:[^@]+@[^/]+/gi,
        severity: 'critical',
        baseConfidence: 0.90,
    },
];
// =============================================================================
// ALL PATTERNS
// =============================================================================
export const ALL_PATTERNS = [
    ...PII_PATTERNS,
    ...SECRET_PATTERNS,
    ...CREDENTIAL_PATTERNS,
];
// =============================================================================
// VALIDATION HELPERS
// =============================================================================
/**
 * Luhn algorithm for credit card validation
 */
function luhnCheck(num) {
    const digits = num.replace(/\D/g, '');
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
 * Get patterns by category
 */
export function getPatternsByCategory(category) {
    return ALL_PATTERNS.filter(p => p.category === category);
}
/**
 * Get patterns by type
 */
export function getPatternsByType(type) {
    return ALL_PATTERNS.filter(p => p.type === type);
}
/**
 * Get pattern by ID
 */
export function getPatternById(id) {
    return ALL_PATTERNS.find(p => p.id === id);
}
//# sourceMappingURL=patterns.js.map