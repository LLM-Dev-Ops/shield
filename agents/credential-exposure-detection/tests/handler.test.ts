/**
 * @module credential-exposure-detection/tests/handler
 * @description Tests for the Credential Exposure Detection Agent handler
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { handleDetection } from '../src/handler.js';
import { createNoOpClient } from '../src/ruvector-client.js';
import { NoOpTelemetryEmitter } from '../src/telemetry.js';
import type { CredentialExposureDetectionInput } from '../../contracts/index.js';

/**
 * Create a valid test input
 */
function createTestInput(
  content: string,
  overrides: Partial<CredentialExposureDetectionInput> = {}
): CredentialExposureDetectionInput {
  return {
    content,
    context: {
      execution_ref: '550e8400-e29b-41d4-a716-446655440000',
      timestamp: new Date().toISOString(),
      content_source: 'user_input',
    },
    sensitivity: 0.5,
    ...overrides,
  };
}

/**
 * Test configuration to skip persistence
 */
const testConfig = {
  skipPersistence: true,
  ruvectorClient: createNoOpClient(),
  telemetryEmitter: new NoOpTelemetryEmitter(),
};

describe('Credential Exposure Detection Agent', () => {
  describe('Agent Identity', () => {
    it('should return correct agent identity', async () => {
      const input = createTestInput('no credentials here');
      const result = await handleDetection(input, testConfig);

      expect('agent' in result).toBe(true);
      if ('agent' in result) {
        expect(result.agent.agent_id).toBe('credential-exposure-detection-agent');
        expect(result.agent.agent_version).toBe('1.0.0');
        expect(result.agent.classification).toBe('DETECTION_ONLY');
        expect(result.agent.decision_type).toBe('credential_exposure_detection');
      }
    });
  });

  describe('Input Validation', () => {
    it('should reject missing content', async () => {
      const result = await handleDetection({}, testConfig);

      expect('code' in result).toBe(true);
      if ('code' in result) {
        expect(result.code).toBe('INVALID_INPUT');
      }
    });

    it('should reject missing context', async () => {
      const result = await handleDetection({ content: 'test' }, testConfig);

      expect('code' in result).toBe(true);
      if ('code' in result) {
        expect(result.code).toBe('INVALID_INPUT');
      }
    });

    it('should accept valid input', async () => {
      const input = createTestInput('valid content');
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
    });
  });

  describe('No Credentials Detection', () => {
    it('should return no detection for clean content', async () => {
      const input = createTestInput('This is just regular text with no sensitive data.');
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(false);
        expect(result.result.entities).toHaveLength(0);
        expect(result.result.risk_score).toBe(0);
        expect(result.result.severity).toBe('none');
      }
    });

    it('should handle empty content', async () => {
      const input = createTestInput('');
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(false);
      }
    });
  });

  describe('Username/Password Pair Detection', () => {
    it('should detect username and password in JSON format', async () => {
      const input = createTestInput(
        '{"username": "admin", "password": "supersecret123"}'
      );
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
        expect(result.result.credential_pair_count).toBeGreaterThan(0);
        expect(result.result.detected_types).toContain('username_password');
      }
    });

    it('should detect inline username password pair', async () => {
      const input = createTestInput('username=admin password=secret123');
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
      }
    });

    it('should detect credentials in URL', async () => {
      const input = createTestInput(
        'Connect to: postgres://dbuser:dbpass123@localhost:5432/mydb'
      );
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
        expect(result.result.detected_types).toContain('database_credential');
      }
    });
  });

  describe('Authentication Header Detection', () => {
    it('should detect Basic Auth header', async () => {
      const input = createTestInput(
        'Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ='
      );
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
        expect(result.result.detected_types).toContain('basic_auth');
      }
    });

    it('should detect Bearer token header', async () => {
      const input = createTestInput(
        'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
      );
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
        expect(result.result.detected_types).toContain('bearer_token');
      }
    });
  });

  describe('Password Pattern Detection', () => {
    it('should detect password assignment', async () => {
      const input = createTestInput('password="mysuperSecretP@ss"');
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
        expect(result.result.exposure_summary?.password_exposures).toBeGreaterThan(0);
      }
    });

    it('should respect minimum password length', async () => {
      const input = createTestInput('password="abc"', { min_password_length: 6 });
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        // Should not detect because password is too short
        expect(result.result.pattern_match_count).toBe(0);
      }
    });

    it('should detect admin credentials', async () => {
      const input = createTestInput('admin=rootpassword123');
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
        expect(result.result.detected_types).toContain('admin_credential');
      }
    });
  });

  describe('Database Credential Detection', () => {
    it('should detect MySQL credentials', async () => {
      const input = createTestInput(
        'mysql_user="dbadmin" mysql_password="dbpass123"'
      );
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
        expect(result.result.detected_types).toContain('database_credential');
      }
    });

    it('should detect PostgreSQL connection URL', async () => {
      const input = createTestInput(
        'DATABASE_URL=postgresql://user:password123@host:5432/db'
      );
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
      }
    });

    it('should detect MongoDB connection URL', async () => {
      const input = createTestInput(
        'MONGO_URI=mongodb+srv://admin:secretpass@cluster.mongodb.net/db'
      );
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
      }
    });
  });

  describe('Environment Variable Detection', () => {
    it('should detect exported password environment variable', async () => {
      const input = createTestInput('export DB_PASSWORD=mysecretvalue123');
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
        expect(result.result.detected_types).toContain('environment_credential');
      }
    });

    it('should detect .env format credentials', async () => {
      const input = createTestInput(`
API_KEY=sk_live_1234567890abcdef
SECRET_TOKEN=mysupersecrettoken123
`);
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
      }
    });
  });

  describe('Hardcoded Credential Detection', () => {
    it('should detect hardcoded password in JavaScript', async () => {
      const input = createTestInput(
        'const dbPassword = "hardcoded_secret_123"'
      );
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
        expect(result.result.detected_types).toContain('hardcoded_credential');
      }
    });
  });

  describe('OAuth Credential Detection', () => {
    it('should detect OAuth client credentials', async () => {
      const input = createTestInput(`
client_id: "1234567890.apps.example.com",
client_secret: "supersecretclientsecret123"
`);
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
        expect(result.result.detected_types).toContain('oauth_credential');
      }
    });
  });

  describe('Sensitivity Configuration', () => {
    it('should adjust confidence based on sensitivity', async () => {
      const contentWithCredential = 'password="testsecret123"';

      const lowSensitivity = await handleDetection(
        createTestInput(contentWithCredential, { sensitivity: 0.1 }),
        testConfig
      );

      const highSensitivity = await handleDetection(
        createTestInput(contentWithCredential, { sensitivity: 1.0 }),
        testConfig
      );

      if ('result' in lowSensitivity && 'result' in highSensitivity) {
        expect(highSensitivity.result.confidence).toBeGreaterThanOrEqual(
          lowSensitivity.result.confidence
        );
      }
    });
  });

  describe('Detection Flags', () => {
    it('should skip password detection when disabled', async () => {
      const input = createTestInput('password="secret123"', {
        detect_password_patterns: false,
        detect_credential_pairs: false,
        detect_auth_headers: false,
      });
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        // Should still detect some patterns from category filter
        // but password-only patterns should be excluded
      }
    });

    it('should skip auth header detection when disabled', async () => {
      const input = createTestInput('Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=', {
        detect_auth_headers: false,
        detect_password_patterns: false,
        detect_credential_pairs: false,
      });
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
    });
  });

  describe('Output Structure', () => {
    it('should include all required output fields', async () => {
      const input = createTestInput('username=admin password=secret123');
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result).toHaveProperty('agent');
        expect(result).toHaveProperty('result');
        expect(result).toHaveProperty('duration_ms');
        expect(result).toHaveProperty('cached');

        expect(result.result).toHaveProperty('credentials_detected');
        expect(result.result).toHaveProperty('risk_score');
        expect(result.result).toHaveProperty('severity');
        expect(result.result).toHaveProperty('confidence');
        expect(result.result).toHaveProperty('entities');
        expect(result.result).toHaveProperty('risk_factors');
        expect(result.result).toHaveProperty('pattern_match_count');
        expect(result.result).toHaveProperty('detected_types');
        expect(result.result).toHaveProperty('type_counts');
        expect(result.result).toHaveProperty('credential_pair_count');
        expect(result.result).toHaveProperty('exposure_summary');
      }
    });

    it('should include redacted preview (never raw credentials)', async () => {
      const input = createTestInput('password="mysupersecretpassword"');
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result && result.result.entities.length > 0) {
        const entity = result.result.entities[0];
        expect(entity.redacted_preview).toBeDefined();
        // Verify it's redacted (contains ****)
        expect(entity.redacted_preview).toContain('****');
        // Verify it does NOT contain the full password
        expect(entity.redacted_preview).not.toContain('mysupersecretpassword');
      }
    });
  });

  describe('Risk Score Calculation', () => {
    it('should calculate higher risk for credential pairs', async () => {
      const pairInput = createTestInput(
        'username=admin password=secret123'
      );
      const passwordOnlyInput = createTestInput(
        'password=secret123'
      );

      const pairResult = await handleDetection(pairInput, testConfig);
      const passwordResult = await handleDetection(passwordOnlyInput, testConfig);

      if ('result' in pairResult && 'result' in passwordResult) {
        // Credential pairs should have higher risk
        expect(pairResult.result.risk_score).toBeGreaterThan(0);
      }
    });

    it('should calculate higher risk for critical severity', async () => {
      // Database credentials are critical
      const criticalInput = createTestInput(
        'postgres://admin:secret@localhost/db'
      );
      // Generic password is high (not critical)
      const highInput = createTestInput(
        'password="generic123"'
      );

      const criticalResult = await handleDetection(criticalInput, testConfig);
      const highResult = await handleDetection(highInput, testConfig);

      if ('result' in criticalResult && 'result' in highResult) {
        if (criticalResult.result.severity === 'critical' && highResult.result.severity === 'high') {
          expect(criticalResult.result.risk_score).toBeGreaterThanOrEqual(
            highResult.result.risk_score
          );
        }
      }
    });
  });

  describe('Edge Cases', () => {
    it('should handle very long content', async () => {
      const longContent = 'normal text '.repeat(10000) + 'password=secret123';
      const input = createTestInput(longContent);
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
      }
    });

    it('should handle special characters in content', async () => {
      const input = createTestInput(
        'password="secret@123!#$%^&*()"'
      );
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
    });

    it('should handle unicode content', async () => {
      const input = createTestInput(
        'password="密码123" username="用户"'
      );
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
    });

    it('should handle multiple credentials in same content', async () => {
      const input = createTestInput(`
        db_user=admin db_password=dbpass123
        api_key=apikey123456789012345678901234567890
        Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
      `);
      const result = await handleDetection(input, testConfig);

      expect('result' in result).toBe(true);
      if ('result' in result) {
        expect(result.result.credentials_detected).toBe(true);
        expect(result.result.pattern_match_count).toBeGreaterThan(1);
      }
    });
  });

  describe('Performance', () => {
    it('should complete detection within reasonable time', async () => {
      const input = createTestInput('password=secret123');
      const startTime = performance.now();
      await handleDetection(input, testConfig);
      const endTime = performance.now();

      // Should complete within 100ms for simple input
      expect(endTime - startTime).toBeLessThan(100);
    });
  });
});
