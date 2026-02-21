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
/**
 * Built-in credential detection patterns organized by category
 */
export const CREDENTIAL_PATTERNS = [
    // ==========================================================================
    // USERNAME + PASSWORD PAIRS (Critical - Most dangerous exposure)
    // ==========================================================================
    {
        pattern_id: 'username-password-pair-json',
        regex: /["']?(?:user(?:name)?|login|email)["']?\s*[:=]\s*["']?([^"'\s,}]+)["']?\s*[,;}\n].*?["']?(?:pass(?:word)?|pwd|secret)["']?\s*[:=]\s*["']?([^"'\s,}]{6,})["']?/gis,
        category: 'username_password',
        severity: 'critical',
        confidence: 0.95,
        description: 'Username and password pair in JSON/config format',
        is_pair: true,
        detects_username: true,
        detects_password: true,
        context_hint: 'credential pair in configuration',
    },
    {
        pattern_id: 'username-password-pair-inline',
        regex: /(?:user(?:name)?|login)\s*[=:]\s*["']?([^\s"']+)["']?\s+(?:pass(?:word)?|pwd)\s*[=:]\s*["']?([^\s"']{6,})["']?/gi,
        category: 'username_password',
        severity: 'critical',
        confidence: 0.90,
        description: 'Username and password on same line',
        is_pair: true,
        detects_username: true,
        detects_password: true,
        context_hint: 'inline credential pair',
    },
    {
        pattern_id: 'credential-url',
        regex: /(?:https?|ftp|ssh|sftp|mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis):\/\/([^:]+):([^@]+)@[^\/\s]+/gi,
        category: 'database_credential',
        severity: 'critical',
        confidence: 0.98,
        description: 'Credentials embedded in URL',
        is_pair: true,
        detects_username: true,
        detects_password: true,
        context_hint: 'credentials in connection URL',
    },
    // ==========================================================================
    // AUTHENTICATION HEADERS
    // ==========================================================================
    {
        pattern_id: 'basic-auth-header',
        regex: /Authorization\s*[:=]\s*["']?Basic\s+[A-Za-z0-9+/=]{20,}["']?/gi,
        category: 'basic_auth',
        severity: 'critical',
        confidence: 0.98,
        description: 'Basic Authentication header',
        is_pair: true,
        detects_username: true,
        detects_password: true,
        context_hint: 'HTTP Basic Auth header',
    },
    {
        pattern_id: 'basic-auth-decoded',
        regex: /(?:basic\s+)?([a-zA-Z0-9._+-]+):([^\s]{6,})(?=\s|$|["'])/gi,
        category: 'basic_auth',
        severity: 'high',
        confidence: 0.70,
        description: 'Decoded Basic Auth credentials (username:password format)',
        is_pair: true,
        detects_username: true,
        detects_password: true,
        context_hint: 'decoded auth credentials',
    },
    {
        pattern_id: 'bearer-token-header',
        regex: /Authorization\s*[:=]\s*["']?Bearer\s+[A-Za-z0-9._\-+=\/]{20,}["']?/gi,
        category: 'bearer_token',
        severity: 'high',
        confidence: 0.95,
        description: 'Bearer token in Authorization header',
        is_pair: false,
        detects_username: false,
        detects_password: true,
        context_hint: 'Bearer token in header',
    },
    // ==========================================================================
    // PASSWORD PATTERNS
    // ==========================================================================
    {
        pattern_id: 'password-assignment-quoted',
        regex: /(?:pass(?:word)?|pwd|secret|passwd|credentials?)["']?\s*[:=]\s*["']([^"']{6,})["']/gi,
        category: 'generic_credential',
        severity: 'high',
        confidence: 0.85,
        description: 'Password assignment with quoted value',
        is_pair: false,
        detects_username: false,
        detects_password: true,
        context_hint: 'password in quotes',
    },
    {
        pattern_id: 'password-assignment-unquoted',
        regex: /(?:pass(?:word)?|pwd|secret|passwd)["']?\s*[:=]\s*([^\s"',;}{]{6,})/gi,
        category: 'generic_credential',
        severity: 'high',
        confidence: 0.75,
        description: 'Password assignment with unquoted value',
        is_pair: false,
        detects_username: false,
        detects_password: true,
        context_hint: 'unquoted password',
    },
    {
        pattern_id: 'admin-password',
        regex: /(?:admin|root|superuser|administrator)["']?\s*[:=]\s*["']?([^\s"',;}{]{6,})["']?/gi,
        category: 'admin_credential',
        severity: 'critical',
        confidence: 0.85,
        description: 'Admin/root password assignment',
        is_pair: false,
        detects_username: false,
        detects_password: true,
        context_hint: 'admin credential',
    },
    // ==========================================================================
    // API CREDENTIALS
    // ==========================================================================
    {
        pattern_id: 'api-key-credential',
        regex: /(?:api[_-]?(?:key|secret|password))["']?\s*[:=]\s*["']?([a-zA-Z0-9_\-+=\/]{20,})["']?/gi,
        category: 'api_credential',
        severity: 'high',
        confidence: 0.85,
        description: 'API key or secret',
        is_pair: false,
        detects_username: false,
        detects_password: true,
        context_hint: 'API credential',
    },
    {
        pattern_id: 'client-id-secret-pair',
        regex: /client[_-]?id["']?\s*[:=]\s*["']?([^\s"',;}{]+)["']?\s*[,;\n].*?client[_-]?secret["']?\s*[:=]\s*["']?([^\s"',;}{]{8,})["']?/gis,
        category: 'oauth_credential',
        severity: 'high',
        confidence: 0.90,
        description: 'OAuth client ID and secret pair',
        is_pair: true,
        detects_username: true,
        detects_password: true,
        context_hint: 'OAuth credentials',
    },
    // ==========================================================================
    // DATABASE CREDENTIALS
    // ==========================================================================
    {
        pattern_id: 'db-user-password',
        regex: /(?:db|database)[_-]?(?:user(?:name)?|login)["']?\s*[:=]\s*["']?([^\s"',;}{]+)["']?\s*[,;\n].*?(?:db|database)[_-]?(?:pass(?:word)?|pwd)["']?\s*[:=]\s*["']?([^\s"',;}{]{6,})["']?/gis,
        category: 'database_credential',
        severity: 'critical',
        confidence: 0.95,
        description: 'Database username and password pair',
        is_pair: true,
        detects_username: true,
        detects_password: true,
        context_hint: 'database credentials',
    },
    {
        pattern_id: 'mysql-credential',
        regex: /mysql[_-]?(?:user|login)["']?\s*[:=]\s*["']?([^\s"',;}{]+)["']?.*?mysql[_-]?(?:pass(?:word)?|pwd)["']?\s*[:=]\s*["']?([^\s"',;}{]{6,})["']?/gis,
        category: 'database_credential',
        severity: 'critical',
        confidence: 0.95,
        description: 'MySQL credentials',
        is_pair: true,
        detects_username: true,
        detects_password: true,
        context_hint: 'MySQL database credentials',
    },
    {
        pattern_id: 'postgres-credential',
        regex: /(?:postgres|pg)[_-]?(?:user|login)["']?\s*[:=]\s*["']?([^\s"',;}{]+)["']?.*?(?:postgres|pg)[_-]?(?:pass(?:word)?|pwd)["']?\s*[:=]\s*["']?([^\s"',;}{]{6,})["']?/gis,
        category: 'database_credential',
        severity: 'critical',
        confidence: 0.95,
        description: 'PostgreSQL credentials',
        is_pair: true,
        detects_username: true,
        detects_password: true,
        context_hint: 'PostgreSQL database credentials',
    },
    {
        pattern_id: 'mongodb-credential',
        regex: /mongo(?:db)?[_-]?(?:user|login)["']?\s*[:=]\s*["']?([^\s"',;}{]+)["']?.*?mongo(?:db)?[_-]?(?:pass(?:word)?|pwd)["']?\s*[:=]\s*["']?([^\s"',;}{]{6,})["']?/gis,
        category: 'database_credential',
        severity: 'critical',
        confidence: 0.95,
        description: 'MongoDB credentials',
        is_pair: true,
        detects_username: true,
        detects_password: true,
        context_hint: 'MongoDB database credentials',
    },
    // ==========================================================================
    // SSH/FTP CREDENTIALS
    // ==========================================================================
    {
        pattern_id: 'ssh-password',
        regex: /ssh[_-]?(?:pass(?:word)?|pwd)["']?\s*[:=]\s*["']?([^\s"',;}{]{6,})["']?/gi,
        category: 'ssh_credential',
        severity: 'critical',
        confidence: 0.90,
        description: 'SSH password',
        is_pair: false,
        detects_username: false,
        detects_password: true,
        context_hint: 'SSH credential',
    },
    {
        pattern_id: 'ftp-credential',
        regex: /ftp[_-]?(?:user(?:name)?|login)["']?\s*[:=]\s*["']?([^\s"',;}{]+)["']?.*?ftp[_-]?(?:pass(?:word)?|pwd)["']?\s*[:=]\s*["']?([^\s"',;}{]{6,})["']?/gis,
        category: 'ftp_credential',
        severity: 'high',
        confidence: 0.90,
        description: 'FTP/SFTP credentials',
        is_pair: true,
        detects_username: true,
        detects_password: true,
        context_hint: 'FTP credentials',
    },
    // ==========================================================================
    // SMTP/EMAIL CREDENTIALS
    // ==========================================================================
    {
        pattern_id: 'smtp-credential',
        regex: /(?:smtp|mail)[_-]?(?:user(?:name)?|login)["']?\s*[:=]\s*["']?([^\s"',;}{]+)["']?.*?(?:smtp|mail)[_-]?(?:pass(?:word)?|pwd)["']?\s*[:=]\s*["']?([^\s"',;}{]{6,})["']?/gis,
        category: 'smtp_credential',
        severity: 'high',
        confidence: 0.90,
        description: 'SMTP/Email server credentials',
        is_pair: true,
        detects_username: true,
        detects_password: true,
        context_hint: 'SMTP credentials',
    },
    // ==========================================================================
    // LDAP/AD CREDENTIALS
    // ==========================================================================
    {
        pattern_id: 'ldap-credential',
        regex: /(?:ldap|ad|active[_-]?directory)[_-]?(?:bind[_-]?)?(?:user(?:name)?|dn)["']?\s*[:=]\s*["']?([^\s"',;}{]+)["']?.*?(?:ldap|ad|active[_-]?directory)[_-]?(?:bind[_-]?)?(?:pass(?:word)?|pwd|secret)["']?\s*[:=]\s*["']?([^\s"',;}{]{6,})["']?/gis,
        category: 'ldap_credential',
        severity: 'critical',
        confidence: 0.90,
        description: 'LDAP/Active Directory credentials',
        is_pair: true,
        detects_username: true,
        detects_password: true,
        context_hint: 'LDAP/AD credentials',
    },
    // ==========================================================================
    // SERVICE ACCOUNT CREDENTIALS
    // ==========================================================================
    {
        pattern_id: 'service-account-key',
        regex: /(?:service[_-]?account|sa)[_-]?(?:key|secret|password)["']?\s*[:=]\s*["']?([^\s"',;}{]{20,})["']?/gi,
        category: 'service_account',
        severity: 'critical',
        confidence: 0.85,
        description: 'Service account key or secret',
        is_pair: false,
        detects_username: false,
        detects_password: true,
        context_hint: 'service account credential',
    },
    // ==========================================================================
    // ENVIRONMENT VARIABLE PATTERNS
    // ==========================================================================
    {
        pattern_id: 'env-password-export',
        regex: /export\s+(?:[A-Z_]*(?:PASS(?:WORD)?|PWD|SECRET|KEY|TOKEN|CREDENTIAL)[A-Z_]*)=["']?([^\s"']+)["']?/gi,
        category: 'environment_credential',
        severity: 'high',
        confidence: 0.85,
        description: 'Password/secret in environment variable export',
        is_pair: false,
        detects_username: false,
        detects_password: true,
        context_hint: 'env variable credential',
    },
    {
        pattern_id: 'dotenv-credential',
        regex: /^[A-Z_]*(?:PASS(?:WORD)?|PWD|SECRET|KEY|TOKEN|CREDENTIAL)[A-Z_]*=["']?([^\s"']+)["']?$/gim,
        category: 'environment_credential',
        severity: 'high',
        confidence: 0.80,
        description: 'Credential in .env format',
        is_pair: false,
        detects_username: false,
        detects_password: true,
        context_hint: 'dotenv credential',
    },
    // ==========================================================================
    // HARDCODED CREDENTIALS
    // ==========================================================================
    {
        pattern_id: 'hardcoded-password-const',
        regex: /(?:const|let|var|final)\s+(?:[a-zA-Z_]*(?:pass(?:word)?|pwd|secret|credential)[a-zA-Z_]*)\s*=\s*["']([^"']{6,})["']/gi,
        category: 'hardcoded_credential',
        severity: 'high',
        confidence: 0.80,
        description: 'Hardcoded password in variable declaration',
        is_pair: false,
        detects_username: false,
        detects_password: true,
        context_hint: 'hardcoded credential in code',
    },
    {
        pattern_id: 'hardcoded-password-string',
        regex: /private\s+(?:static\s+)?(?:final\s+)?String\s+(?:[a-zA-Z_]*(?:PASS(?:WORD)?|PWD|SECRET)[a-zA-Z_]*)\s*=\s*"([^"]{6,})"/gi,
        category: 'hardcoded_credential',
        severity: 'high',
        confidence: 0.85,
        description: 'Hardcoded password in Java/Kotlin string',
        is_pair: false,
        detects_username: false,
        detects_password: true,
        context_hint: 'hardcoded credential in Java code',
    },
    // ==========================================================================
    // GENERIC USERNAME PATTERNS
    // ==========================================================================
    {
        pattern_id: 'username-assignment',
        regex: /(?:user(?:name)?|login|email|account)["']?\s*[:=]\s*["']?([a-zA-Z0-9._@+-]{3,})["']?/gi,
        category: 'generic_credential',
        severity: 'low',
        confidence: 0.50,
        description: 'Username/login assignment',
        is_pair: false,
        detects_username: true,
        detects_password: false,
        context_hint: 'username assignment',
    },
];
/**
 * Get patterns filtered by category
 */
export function getPatternsByCategory(categories) {
    if (!categories || categories.length === 0) {
        return [...CREDENTIAL_PATTERNS];
    }
    return CREDENTIAL_PATTERNS.filter((p) => categories.includes(p.category));
}
/**
 * Get patterns that detect credential pairs only
 */
export function getPairPatterns() {
    return CREDENTIAL_PATTERNS.filter((p) => p.is_pair);
}
/**
 * Get patterns that detect passwords only (not pairs)
 */
export function getPasswordOnlyPatterns() {
    return CREDENTIAL_PATTERNS.filter((p) => p.detects_password && !p.is_pair);
}
/**
 * Get patterns that detect usernames only (not pairs)
 */
export function getUsernameOnlyPatterns() {
    return CREDENTIAL_PATTERNS.filter((p) => p.detects_username && !p.is_pair);
}
/**
 * Get auth header patterns
 */
export function getAuthHeaderPatterns() {
    return CREDENTIAL_PATTERNS.filter((p) => p.category === 'basic_auth' ||
        p.category === 'bearer_token');
}
/**
 * Create custom pattern from user input
 */
export function createCustomPattern(patternId, regexStr, category = 'generic_credential') {
    try {
        const regex = new RegExp(regexStr, 'gi');
        return {
            pattern_id: `custom-${patternId}`,
            regex,
            category,
            severity: 'medium',
            confidence: 0.70,
            description: `Custom pattern: ${patternId}`,
            is_pair: false,
            detects_username: false,
            detects_password: true,
            context_hint: 'custom pattern match',
        };
    }
    catch {
        return null;
    }
}
//# sourceMappingURL=patterns.js.map