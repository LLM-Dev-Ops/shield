/**
 * @module secrets-leakage-detection/tests/handler
 * @description Tests for Secrets Leakage Detection Agent handler
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { handleDetection, type HandlerConfig } from '../src/handler.js';
import { createNoOpClient } from '../src/ruvector-client.js';
import { NoOpTelemetryEmitter } from '../src/telemetry.js';

/**
 * Test configuration that skips persistence
 */
const testConfig: HandlerConfig = {
  ruvectorClient: createNoOpClient(),
  telemetryEmitter: new NoOpTelemetryEmitter(),
  skipPersistence: true,
};

/**
 * Helper to create valid input
 */
function createInput(content: string, overrides: Record<string, unknown> = {}) {
  return {
    content,
    context: {
      execution_ref: '123e4567-e89b-12d3-a456-426614174000',
      timestamp: new Date().toISOString(),
      content_source: 'user_input' as const,
    },
    ...overrides,
  };
}

describe('Secrets Leakage Detection Agent', () => {
  describe('Agent Identity', () => {
    it('should return correct agent identity', async () => {
      const result = await handleDetection(
        createInput('test content'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('agent' in result) {
        expect(result.agent.agent_id).toBe('secrets-leakage-detection-agent');
        expect(result.agent.agent_version).toBe('1.0.0');
        expect(result.agent.classification).toBe('DETECTION_ONLY');
        expect(result.agent.decision_type).toBe('secret_detection');
      }
    });
  });

  describe('Input Validation', () => {
    it('should reject invalid input', async () => {
      const result = await handleDetection({}, testConfig);

      expect(result).toHaveProperty('code', 'INVALID_INPUT');
    });

    it('should reject missing content', async () => {
      const result = await handleDetection(
        {
          context: {
            execution_ref: '123e4567-e89b-12d3-a456-426614174000',
            timestamp: new Date().toISOString(),
            content_source: 'user_input',
          },
        },
        testConfig
      );

      expect(result).toHaveProperty('code', 'INVALID_INPUT');
    });

    it('should accept valid input', async () => {
      const result = await handleDetection(
        createInput('test content'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
    });
  });

  describe('AWS Credentials Detection', () => {
    it('should detect AWS access key ID', async () => {
      const result = await handleDetection(
        createInput('AKIAIOSFODNN7EXAMPLE'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        expect(result.result.threats_detected).toBe(true);
        expect(result.result.detected_categories).toContain('aws_credentials');
        expect(result.result.severity).toBe('critical');
        expect(result.result.entities[0].secret_type).toBe('aws_credentials');
      }
    });

    it('should detect AWS secret access key assignment', async () => {
      const result = await handleDetection(
        createInput('aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        expect(result.result.threats_detected).toBe(true);
        expect(result.result.detected_categories).toContain('aws_credentials');
      }
    });
  });

  describe('GitHub Token Detection', () => {
    it('should detect GitHub personal access token', async () => {
      const result = await handleDetection(
        createInput('ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        expect(result.result.threats_detected).toBe(true);
        expect(result.result.detected_categories).toContain('github_token');
        expect(result.result.severity).toBe('high');
      }
    });

    it('should detect GitHub fine-grained PAT', async () => {
      const result = await handleDetection(
        createInput('github_pat_1234567890123456789012_1234567890123456789012345678901234567890123456789012345678'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        expect(result.result.threats_detected).toBe(true);
        expect(result.result.detected_categories).toContain('github_token');
      }
    });
  });

  describe('Private Key Detection', () => {
    it('should detect RSA private key', async () => {
      const result = await handleDetection(
        createInput('-----BEGIN RSA PRIVATE KEY-----'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        expect(result.result.threats_detected).toBe(true);
        expect(result.result.detected_categories).toContain('private_key');
        expect(result.result.severity).toBe('critical');
      }
    });

    it('should detect generic private key', async () => {
      const result = await handleDetection(
        createInput('-----BEGIN PRIVATE KEY-----'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        expect(result.result.threats_detected).toBe(true);
        expect(result.result.severity).toBe('critical');
      }
    });
  });

  describe('Stripe Key Detection', () => {
    it('should detect Stripe live secret key', async () => {
      const result = await handleDetection(
        createInput('sk_live_EXAMPLE_TEST_KEY_1234567890'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        expect(result.result.threats_detected).toBe(true);
        expect(result.result.detected_categories).toContain('stripe_key');
        expect(result.result.severity).toBe('critical');
      }
    });

    it('should detect Stripe test key with lower severity', async () => {
      const result = await handleDetection(
        createInput('sk_test_12345678901234567890123456'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        expect(result.result.threats_detected).toBe(true);
        expect(result.result.severity).toBe('medium');
      }
    });
  });

  describe('JWT Token Detection', () => {
    it('should detect JWT token', async () => {
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      const result = await handleDetection(createInput(jwt), testConfig);

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        expect(result.result.threats_detected).toBe(true);
        expect(result.result.detected_categories).toContain('jwt_token');
      }
    });
  });

  describe('Database URL Detection', () => {
    it('should detect PostgreSQL connection URL', async () => {
      const result = await handleDetection(
        createInput('postgresql://user:password@localhost/dbname'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        expect(result.result.threats_detected).toBe(true);
        expect(result.result.detected_categories).toContain('database_url');
        expect(result.result.severity).toBe('critical');
      }
    });

    it('should detect MongoDB connection URL', async () => {
      const result = await handleDetection(
        createInput('mongodb+srv://user:password@cluster.mongodb.net/dbname'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        expect(result.result.threats_detected).toBe(true);
        expect(result.result.detected_categories).toContain('database_url');
      }
    });
  });

  describe('Clean Input', () => {
    it('should not detect threats in clean input', async () => {
      const result = await handleDetection(
        createInput('Hello, this is a normal message without any secrets.'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        expect(result.result.threats_detected).toBe(false);
        expect(result.result.entities.length).toBe(0);
        expect(result.result.severity).toBe('none');
        expect(result.result.risk_score).toBe(0);
      }
    });
  });

  describe('Category Filtering', () => {
    it('should only detect specified categories', async () => {
      const content = 'AKIAIOSFODNN7EXAMPLE and ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const result = await handleDetection(
        createInput(content, { detect_categories: ['aws_credentials'] }),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        expect(result.result.threats_detected).toBe(true);
        expect(result.result.detected_categories).toContain('aws_credentials');
        expect(result.result.detected_categories).not.toContain('github_token');
      }
    });
  });

  describe('Entropy Detection', () => {
    it('should detect high-entropy strings', async () => {
      const result = await handleDetection(
        createInput('token=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        // Should detect either via pattern or entropy
        expect(result.result.threats_detected).toBe(true);
      }
    });

    it('should respect entropy_detection=false', async () => {
      const result = await handleDetection(
        createInput('token=randomstringwithonlyletters', {
          entropy_detection: false,
          detect_categories: [], // Empty to skip pattern detection
        }),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      // With both disabled, should not detect
    });
  });

  describe('Sensitivity', () => {
    it('should affect confidence scores', async () => {
      const content = 'secret=abc12345678901234567890';

      const lowSensitivity = await handleDetection(
        createInput(content, { sensitivity: 0.3 }),
        testConfig
      );

      const highSensitivity = await handleDetection(
        createInput(content, { sensitivity: 0.9 }),
        testConfig
      );

      if ('result' in lowSensitivity && 'result' in highSensitivity) {
        // Both should detect (if pattern matches)
        // High sensitivity should have higher confidence
        if (highSensitivity.result.entities.length > 0 && lowSensitivity.result.entities.length > 0) {
          expect(highSensitivity.result.entities[0].confidence).toBeGreaterThanOrEqual(
            lowSensitivity.result.entities[0].confidence
          );
        }
      }
    });
  });

  describe('Multiple Secrets', () => {
    it('should detect multiple secrets in same content', async () => {
      const content = `
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        DATABASE_URL=postgresql://user:pass@localhost/db
      `;

      const result = await handleDetection(createInput(content), testConfig);

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        expect(result.result.threats_detected).toBe(true);
        expect(result.result.entities.length).toBeGreaterThanOrEqual(3);
        expect(result.result.detected_categories).toContain('aws_credentials');
        expect(result.result.detected_categories).toContain('github_token');
        expect(result.result.detected_categories).toContain('database_url');
      }
    });
  });

  describe('Redaction', () => {
    it('should redact secrets in entity preview', async () => {
      const result = await handleDetection(
        createInput('AKIAIOSFODNN7EXAMPLE'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('result' in result && result.result.entities.length > 0) {
        const entity = result.result.entities[0];
        expect(entity.redacted_preview).toMatch(/^AKIA\*{4}PLE$/);
        // Should NOT contain full secret
        expect(entity.redacted_preview).not.toBe('AKIAIOSFODNN7EXAMPLE');
      }
    });
  });

  describe('Duration Tracking', () => {
    it('should track execution duration', async () => {
      const result = await handleDetection(
        createInput('test content'),
        testConfig
      );

      expect(result).not.toHaveProperty('code');
      if ('result' in result) {
        expect(result.duration_ms).toBeGreaterThan(0);
        expect(result.duration_ms).toBeLessThan(1000); // Should be fast
      }
    });
  });
});
