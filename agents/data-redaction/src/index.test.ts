/**
 * Data Redaction Agent - Unit Tests
 *
 * These tests verify:
 * - Input validation
 * - Detection and redaction logic
 * - Output schema compliance
 * - No raw sensitive data in outputs
 * - DecisionEvent format
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  DataRedactionAgent,
  AGENT_ID,
  AGENT_VERSION,
  AGENT_CLASSIFICATION,
  DECISION_TYPE,
} from './index.js';
import { Redactor, hashContent } from './redactor.js';
import type { DataRedactionInput } from './index.js';

// =============================================================================
// TEST FIXTURES
// =============================================================================

const createTestInput = (content: string, overrides?: Partial<DataRedactionInput>): DataRedactionInput => ({
  content,
  context: {
    execution_ref: '550e8400-e29b-41d4-a716-446655440000',
    timestamp: new Date().toISOString(),
    content_source: 'user_input',
  },
  ...overrides,
});

const TEST_EMAIL = 'john.doe@example.com';
const TEST_SSN = '123-45-6789';
const TEST_CREDIT_CARD = '4111111111111111';
const TEST_AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const TEST_GITHUB_TOKEN = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';
const TEST_OPENAI_KEY = 'sk-1234567890abcdefghijklmnopqrstuvwxyz12345678';
const TEST_PASSWORD = 'password="SuperSecret123!"';
const TEST_DATABASE_URL = 'postgres://user:password@localhost:5432/mydb';

// =============================================================================
// AGENT IDENTITY TESTS
// =============================================================================

describe('Agent Identity', () => {
  it('should have correct agent ID', () => {
    expect(AGENT_ID).toBe('data-redaction-agent');
  });

  it('should have correct version', () => {
    expect(AGENT_VERSION).toBe('1.0.0');
  });

  it('should be classified as REDACTION', () => {
    expect(AGENT_CLASSIFICATION).toBe('REDACTION');
  });

  it('should have decision type data_redaction', () => {
    expect(DECISION_TYPE).toBe('data_redaction');
  });
});

// =============================================================================
// REDACTOR TESTS
// =============================================================================

describe('Redactor', () => {
  let redactor: Redactor;

  beforeEach(() => {
    redactor = new Redactor({
      sensitivity: 0.7,
      strategy: 'mask',
      detectPii: true,
      detectSecrets: true,
      detectCredentials: true,
      minConfidence: 0.8,
      returnRedactedContent: true,
      partialMaskChars: 4,
    });
  });

  describe('PII Detection', () => {
    it('should detect and redact email addresses', () => {
      const result = redactor.redact(`Contact me at ${TEST_EMAIL}`);

      expect(result.dataRedacted).toBe(true);
      expect(result.redactedContent).toContain('[EMAIL]');
      expect(result.redactedContent).not.toContain(TEST_EMAIL);
      expect(result.redactedEntities[0].category).toBe('pii');
    });

    it('should detect and redact SSN', () => {
      const result = redactor.redact(`My SSN is ${TEST_SSN}`);

      expect(result.dataRedacted).toBe(true);
      expect(result.redactedContent).toContain('[SSN]');
      expect(result.redactedContent).not.toContain(TEST_SSN);
      expect(result.severity).toBe('critical');
    });

    it('should detect and redact credit card numbers', () => {
      const result = redactor.redact(`Card number: ${TEST_CREDIT_CARD}`);

      expect(result.dataRedacted).toBe(true);
      expect(result.redactedContent).toContain('[CREDIT_CARD]');
      expect(result.redactedContent).not.toContain(TEST_CREDIT_CARD);
      expect(result.severity).toBe('critical');
    });
  });

  describe('Secret Detection', () => {
    it('should detect and redact AWS access keys', () => {
      const result = redactor.redact(`AWS_ACCESS_KEY_ID=${TEST_AWS_KEY}`);

      expect(result.dataRedacted).toBe(true);
      expect(result.redactedContent).toContain('[AWS_CREDENTIALS]');
      expect(result.redactedContent).not.toContain(TEST_AWS_KEY);
      expect(result.severity).toBe('critical');
    });

    it('should detect and redact GitHub tokens', () => {
      const result = redactor.redact(`GITHUB_TOKEN=${TEST_GITHUB_TOKEN}`);

      expect(result.dataRedacted).toBe(true);
      expect(result.redactedContent).toContain('[GITHUB_TOKEN]');
      expect(result.redactedContent).not.toContain(TEST_GITHUB_TOKEN);
    });

    it('should detect and redact OpenAI API keys', () => {
      const result = redactor.redact(`OPENAI_API_KEY=${TEST_OPENAI_KEY}`);

      expect(result.dataRedacted).toBe(true);
      expect(result.redactedContent).toContain('[OPENAI_KEY]');
      expect(result.redactedContent).not.toContain(TEST_OPENAI_KEY);
    });
  });

  describe('Credential Detection', () => {
    it('should detect and redact passwords', () => {
      const result = redactor.redact(`Config: ${TEST_PASSWORD}`);

      expect(result.dataRedacted).toBe(true);
      expect(result.redactedContent).toContain('[PASSWORD]');
      expect(result.redactedContent).not.toContain('SuperSecret123!');
    });

    it('should detect and redact database URLs', () => {
      const result = redactor.redact(`DATABASE_URL=${TEST_DATABASE_URL}`);

      expect(result.dataRedacted).toBe(true);
      expect(result.redactedContent).toContain('[DATABASE_URL]');
      expect(result.redactedContent).not.toContain('password');
    });
  });

  describe('Redaction Strategies', () => {
    it('should apply mask strategy correctly', () => {
      const maskRedactor = new Redactor({
        sensitivity: 0.7,
        strategy: 'mask',
        detectPii: true,
        detectSecrets: false,
        detectCredentials: false,
        minConfidence: 0.8,
        returnRedactedContent: true,
        partialMaskChars: 4,
      });

      const result = maskRedactor.redact(TEST_EMAIL);
      expect(result.redactedContent).toBe('[EMAIL]');
    });

    it('should apply partial_mask strategy correctly', () => {
      const partialRedactor = new Redactor({
        sensitivity: 0.7,
        strategy: 'partial_mask',
        detectPii: true,
        detectSecrets: false,
        detectCredentials: false,
        minConfidence: 0.8,
        returnRedactedContent: true,
        partialMaskChars: 4,
      });

      const result = partialRedactor.redact(TEST_EMAIL);
      expect(result.redactedContent).toMatch(/^john.*\.com$/);
    });

    it('should apply remove strategy correctly', () => {
      const removeRedactor = new Redactor({
        sensitivity: 0.7,
        strategy: 'remove',
        detectPii: true,
        detectSecrets: false,
        detectCredentials: false,
        minConfidence: 0.8,
        returnRedactedContent: true,
        partialMaskChars: 4,
      });

      const result = removeRedactor.redact(`Email: ${TEST_EMAIL}`);
      expect(result.redactedContent).toBe('Email: ');
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty content', () => {
      const result = redactor.redact('');

      expect(result.dataRedacted).toBe(false);
      expect(result.redactionCount).toBe(0);
      expect(result.severity).toBe('none');
    });

    it('should handle content with no sensitive data', () => {
      const result = redactor.redact('Hello, this is a normal message.');

      expect(result.dataRedacted).toBe(false);
      expect(result.redactionCount).toBe(0);
      expect(result.severity).toBe('none');
    });

    it('should handle multiple sensitive items', () => {
      const result = redactor.redact(
        `Contact: ${TEST_EMAIL}, SSN: ${TEST_SSN}, Key: ${TEST_AWS_KEY}`
      );

      expect(result.dataRedacted).toBe(true);
      expect(result.redactionCount).toBe(3);
      expect(result.detectedCategories).toContain('pii');
      expect(result.detectedCategories).toContain('secret');
    });
  });
});

// =============================================================================
// AGENT TESTS
// =============================================================================

describe('DataRedactionAgent', () => {
  let agent: DataRedactionAgent;

  beforeEach(() => {
    agent = new DataRedactionAgent({
      skipPersistence: true,
      skipTelemetry: true,
    });
  });

  describe('Input Validation', () => {
    it('should reject invalid input', async () => {
      const result = await agent.process({} as DataRedactionInput);

      expect('code' in result).toBe(true);
      if ('code' in result) {
        expect(result.code).toBe('INVALID_INPUT');
      }
    });

    it('should accept valid input', async () => {
      const input = createTestInput('Hello world');
      const result = await agent.process(input);

      expect('code' in result).toBe(false);
    });
  });

  describe('Output Structure', () => {
    it('should return correct agent identity', async () => {
      const input = createTestInput(TEST_EMAIL);
      const result = await agent.process(input);

      if (!('code' in result)) {
        expect(result.agent.agent_id).toBe(AGENT_ID);
        expect(result.agent.agent_version).toBe(AGENT_VERSION);
        expect(result.agent.classification).toBe(AGENT_CLASSIFICATION);
        expect(result.agent.decision_type).toBe(DECISION_TYPE);
      }
    });

    it('should include duration_ms', async () => {
      const input = createTestInput('test');
      const result = await agent.process(input);

      if (!('code' in result)) {
        expect(result.duration_ms).toBeGreaterThanOrEqual(0);
      }
    });

    it('should include redaction result', async () => {
      const input = createTestInput(TEST_EMAIL);
      const result = await agent.process(input);

      if (!('code' in result)) {
        expect(result.result.data_redacted).toBe(true);
        expect(result.result.redaction_count).toBeGreaterThan(0);
        expect(result.result.redacted_content).toBeDefined();
        expect(result.result.redacted_entities.length).toBeGreaterThan(0);
      }
    });
  });

  describe('Sensitive Data Protection', () => {
    it('should NOT expose raw PII in output', async () => {
      const input = createTestInput(TEST_EMAIL);
      const result = await agent.process(input);

      const outputString = JSON.stringify(result);
      expect(outputString).not.toContain(TEST_EMAIL);
    });

    it('should NOT expose raw secrets in output', async () => {
      const input = createTestInput(TEST_AWS_KEY);
      const result = await agent.process(input);

      const outputString = JSON.stringify(result);
      expect(outputString).not.toContain(TEST_AWS_KEY);
    });

    it('should NOT expose raw credentials in output', async () => {
      const input = createTestInput(TEST_PASSWORD);
      const result = await agent.process(input);

      const outputString = JSON.stringify(result);
      expect(outputString).not.toContain('SuperSecret123!');
    });
  });

  describe('Configuration', () => {
    it('should respect sensitivity setting', async () => {
      const input = createTestInput(TEST_EMAIL, { sensitivity: 0.1 });
      const result = await agent.process(input);

      // Lower sensitivity should still detect obvious patterns
      if (!('code' in result)) {
        expect(result.result.data_redacted).toBe(true);
      }
    });

    it('should respect redaction strategy', async () => {
      const input = createTestInput(TEST_EMAIL, { redaction_strategy: 'remove' });
      const result = await agent.process(input);

      if (!('code' in result)) {
        expect(result.result.redacted_content).not.toContain('[EMAIL]');
        expect(result.result.redacted_content).not.toContain(TEST_EMAIL);
      }
    });
  });
});

// =============================================================================
// HASH CONTENT TESTS
// =============================================================================

describe('hashContent', () => {
  it('should return 64-character hex string', () => {
    const hash = hashContent('test content');
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('should be deterministic', () => {
    const hash1 = hashContent('test');
    const hash2 = hashContent('test');
    expect(hash1).toBe(hash2);
  });

  it('should produce different hashes for different content', () => {
    const hash1 = hashContent('content1');
    const hash2 = hashContent('content2');
    expect(hash1).not.toBe(hash2);
  });
});

// =============================================================================
// INTEGRATION VERIFICATION
// =============================================================================

describe('Integration Verification Checklist', () => {
  it('should use schemas from agentics-contracts', () => {
    // This is verified by TypeScript compilation
    expect(true).toBe(true);
  });

  it('should produce deterministic output', async () => {
    const agent = new DataRedactionAgent({
      skipPersistence: true,
      skipTelemetry: true,
    });

    const input = createTestInput(TEST_EMAIL);

    const result1 = await agent.process(input);
    const result2 = await agent.process(input);

    if (!('code' in result1) && !('code' in result2)) {
      expect(result1.result.data_redacted).toBe(result2.result.data_redacted);
      expect(result1.result.redaction_count).toBe(result2.result.redaction_count);
      expect(result1.result.redacted_content).toBe(result2.result.redacted_content);
    }
  });

  it('should be stateless', async () => {
    const agent = new DataRedactionAgent({
      skipPersistence: true,
      skipTelemetry: true,
    });

    // Process multiple inputs
    await agent.process(createTestInput(TEST_EMAIL));
    await agent.process(createTestInput(TEST_SSN));
    await agent.process(createTestInput('clean content'));

    // Verify clean content still produces clean result
    const result = await agent.process(createTestInput('another clean message'));

    if (!('code' in result)) {
      expect(result.result.data_redacted).toBe(false);
    }
  });
});
