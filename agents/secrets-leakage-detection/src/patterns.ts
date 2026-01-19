/**
 * @module secrets-leakage-detection/patterns
 * @description Secret detection patterns for the Secrets Leakage Detection Agent
 */

import type { SecretTypeCategory } from '../../contracts/index.js';

export interface SecretPattern {
  /** Unique pattern identifier */
  pattern_id: string;
  /** Regular expression for matching */
  regex: RegExp;
  /** Category of secret */
  category: SecretTypeCategory;
  /** Default severity for matches */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Base confidence for pattern matches */
  confidence: number;
  /** Human-readable description */
  description: string;
}

/**
 * Built-in secret detection patterns organized by category
 */
export const SECRET_PATTERNS: ReadonlyArray<SecretPattern> = [
  // AWS Credentials
  {
    pattern_id: 'aws-access-key-id',
    regex: /AKIA[0-9A-Z]{16}/g,
    category: 'aws_credentials',
    severity: 'critical',
    confidence: 0.95,
    description: 'AWS Access Key ID',
  },
  {
    pattern_id: 'aws-secret-access-key',
    regex: /aws[_-]?secret[_-]?access[_-]?key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}/gi,
    category: 'aws_credentials',
    severity: 'critical',
    confidence: 0.95,
    description: 'AWS Secret Access Key',
  },
  {
    pattern_id: 'aws-session-token',
    regex: /aws[_-]?session[_-]?token["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{100,}/gi,
    category: 'aws_credentials',
    severity: 'critical',
    confidence: 0.90,
    description: 'AWS Session Token',
  },

  // GitHub Tokens
  {
    pattern_id: 'github-pat',
    regex: /ghp_[a-zA-Z0-9]{36}/g,
    category: 'github_token',
    severity: 'high',
    confidence: 0.98,
    description: 'GitHub Personal Access Token',
  },
  {
    pattern_id: 'github-oauth',
    regex: /gho_[a-zA-Z0-9]{36}/g,
    category: 'github_token',
    severity: 'high',
    confidence: 0.98,
    description: 'GitHub OAuth Token',
  },
  {
    pattern_id: 'github-app',
    regex: /ghs_[a-zA-Z0-9]{36}/g,
    category: 'github_token',
    severity: 'high',
    confidence: 0.98,
    description: 'GitHub App Token',
  },
  {
    pattern_id: 'github-refresh',
    regex: /ghr_[a-zA-Z0-9]{36}/g,
    category: 'github_token',
    severity: 'high',
    confidence: 0.98,
    description: 'GitHub Refresh Token',
  },
  {
    pattern_id: 'github-fine-grained-pat',
    regex: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g,
    category: 'github_token',
    severity: 'high',
    confidence: 0.99,
    description: 'GitHub Fine-grained PAT',
  },

  // Stripe Keys
  {
    pattern_id: 'stripe-live-secret',
    regex: /sk_live_[0-9a-zA-Z]{24,}/g,
    category: 'stripe_key',
    severity: 'critical',
    confidence: 0.98,
    description: 'Stripe Live Secret Key',
  },
  {
    pattern_id: 'stripe-test-secret',
    regex: /sk_test_[0-9a-zA-Z]{24,}/g,
    category: 'stripe_key',
    severity: 'medium',
    confidence: 0.98,
    description: 'Stripe Test Secret Key',
  },
  {
    pattern_id: 'stripe-live-publishable',
    regex: /pk_live_[0-9a-zA-Z]{24,}/g,
    category: 'stripe_key',
    severity: 'low',
    confidence: 0.95,
    description: 'Stripe Live Publishable Key',
  },
  {
    pattern_id: 'stripe-restricted',
    regex: /rk_live_[0-9a-zA-Z]{24,}/g,
    category: 'stripe_key',
    severity: 'high',
    confidence: 0.98,
    description: 'Stripe Restricted Key',
  },

  // OpenAI Keys
  {
    pattern_id: 'openai-api-key',
    regex: /sk-[a-zA-Z0-9]{48}/g,
    category: 'openai_key',
    severity: 'high',
    confidence: 0.90,
    description: 'OpenAI API Key',
  },
  {
    pattern_id: 'openai-project-key',
    regex: /sk-proj-[a-zA-Z0-9]{48}/g,
    category: 'openai_key',
    severity: 'high',
    confidence: 0.95,
    description: 'OpenAI Project API Key',
  },

  // Anthropic Keys
  {
    pattern_id: 'anthropic-api-key',
    regex: /sk-ant-[a-zA-Z0-9-]{32,}/g,
    category: 'anthropic_key',
    severity: 'high',
    confidence: 0.98,
    description: 'Anthropic API Key',
  },

  // Slack Tokens
  {
    pattern_id: 'slack-token',
    regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g,
    category: 'slack_token',
    severity: 'high',
    confidence: 0.98,
    description: 'Slack Token',
  },
  {
    pattern_id: 'slack-webhook',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,}\/B[a-zA-Z0-9_]{8,}\/[a-zA-Z0-9_]{24}/g,
    category: 'slack_token',
    severity: 'high',
    confidence: 0.99,
    description: 'Slack Webhook URL',
  },

  // Google API Keys
  {
    pattern_id: 'google-api-key',
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    category: 'google_api_key',
    severity: 'high',
    confidence: 0.95,
    description: 'Google API Key',
  },
  {
    pattern_id: 'google-oauth-client',
    regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
    category: 'google_api_key',
    severity: 'medium',
    confidence: 0.90,
    description: 'Google OAuth Client ID',
  },

  // Private Keys
  {
    pattern_id: 'rsa-private-key',
    regex: /-----BEGIN RSA PRIVATE KEY-----/g,
    category: 'private_key',
    severity: 'critical',
    confidence: 0.99,
    description: 'RSA Private Key',
  },
  {
    pattern_id: 'ec-private-key',
    regex: /-----BEGIN EC PRIVATE KEY-----/g,
    category: 'private_key',
    severity: 'critical',
    confidence: 0.99,
    description: 'EC Private Key',
  },
  {
    pattern_id: 'openssh-private-key',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    category: 'private_key',
    severity: 'critical',
    confidence: 0.99,
    description: 'OpenSSH Private Key',
  },
  {
    pattern_id: 'pgp-private-key',
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
    category: 'private_key',
    severity: 'critical',
    confidence: 0.99,
    description: 'PGP Private Key',
  },
  {
    pattern_id: 'dsa-private-key',
    regex: /-----BEGIN DSA PRIVATE KEY-----/g,
    category: 'private_key',
    severity: 'critical',
    confidence: 0.99,
    description: 'DSA Private Key',
  },
  {
    pattern_id: 'encrypted-private-key',
    regex: /-----BEGIN ENCRYPTED PRIVATE KEY-----/g,
    category: 'private_key',
    severity: 'high',
    confidence: 0.95,
    description: 'Encrypted Private Key',
  },
  {
    pattern_id: 'generic-private-key',
    regex: /-----BEGIN PRIVATE KEY-----/g,
    category: 'private_key',
    severity: 'critical',
    confidence: 0.99,
    description: 'Private Key (PKCS#8)',
  },

  // JWT Tokens
  {
    pattern_id: 'jwt-token',
    regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
    category: 'jwt_token',
    severity: 'high',
    confidence: 0.85,
    description: 'JWT Token',
  },

  // Database URLs
  {
    pattern_id: 'postgres-url',
    regex: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^/]+\/[^\s"']+/gi,
    category: 'database_url',
    severity: 'critical',
    confidence: 0.95,
    description: 'PostgreSQL Connection URL',
  },
  {
    pattern_id: 'mysql-url',
    regex: /mysql:\/\/[^:]+:[^@]+@[^/]+\/[^\s"']+/gi,
    category: 'database_url',
    severity: 'critical',
    confidence: 0.95,
    description: 'MySQL Connection URL',
  },
  {
    pattern_id: 'mongodb-url',
    regex: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^/]+\/[^\s"']+/gi,
    category: 'database_url',
    severity: 'critical',
    confidence: 0.95,
    description: 'MongoDB Connection URL',
  },
  {
    pattern_id: 'redis-url',
    regex: /redis:\/\/[^:]*:[^@]+@[^/]+/gi,
    category: 'database_url',
    severity: 'high',
    confidence: 0.90,
    description: 'Redis Connection URL',
  },

  // Generic API Keys
  {
    pattern_id: 'generic-api-key-assignment',
    regex: /api[_-]?key["']?\s*[:=]\s*["']?[a-zA-Z0-9]{32,}/gi,
    category: 'generic_api_key',
    severity: 'medium',
    confidence: 0.70,
    description: 'Generic API Key Assignment',
  },

  // Generic Secrets
  {
    pattern_id: 'generic-secret-assignment',
    regex: /secret["']?\s*[:=]\s*["']?[a-zA-Z0-9]{32,}/gi,
    category: 'generic_secret',
    severity: 'medium',
    confidence: 0.65,
    description: 'Generic Secret Assignment',
  },
  {
    pattern_id: 'generic-token-assignment',
    regex: /token["']?\s*[:=]\s*["']?[a-zA-Z0-9-_]{20,}/gi,
    category: 'generic_secret',
    severity: 'medium',
    confidence: 0.60,
    description: 'Generic Token Assignment',
  },

  // Passwords
  {
    pattern_id: 'password-assignment',
    regex: /password["']?\s*[:=]\s*["']?[^\s'"]{8,}/gi,
    category: 'password',
    severity: 'high',
    confidence: 0.75,
    description: 'Password Assignment',
  },
  {
    pattern_id: 'passwd-assignment',
    regex: /passwd["']?\s*[:=]\s*["']?[^\s'"]{8,}/gi,
    category: 'password',
    severity: 'high',
    confidence: 0.75,
    description: 'Passwd Assignment',
  },

  // Connection Strings
  {
    pattern_id: 'sqlserver-connection-string',
    regex: /Server=[^;]+;.*Password=[^;]+/gi,
    category: 'connection_string',
    severity: 'critical',
    confidence: 0.90,
    description: 'SQL Server Connection String',
  },
  {
    pattern_id: 'odbc-connection-string',
    regex: /Driver=[^;]+;.*PWD=[^;]+/gi,
    category: 'connection_string',
    severity: 'critical',
    confidence: 0.90,
    description: 'ODBC Connection String',
  },
];

/**
 * Get patterns filtered by category
 */
export function getPatternsByCategory(
  categories?: SecretTypeCategory[]
): SecretPattern[] {
  if (!categories || categories.length === 0) {
    return [...SECRET_PATTERNS];
  }
  return SECRET_PATTERNS.filter((p) => categories.includes(p.category));
}

/**
 * Create custom pattern from user input
 */
export function createCustomPattern(
  patternId: string,
  regexStr: string,
  category: SecretTypeCategory = 'generic_secret'
): SecretPattern | null {
  try {
    const regex = new RegExp(regexStr, 'g');
    return {
      pattern_id: `custom-${patternId}`,
      regex,
      category,
      severity: 'medium',
      confidence: 0.70,
      description: `Custom pattern: ${patternId}`,
    };
  } catch {
    return null;
  }
}
