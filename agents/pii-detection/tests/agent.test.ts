/**
 * PII Detection Agent Tests
 *
 * Tests for the main agent implementation.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { PIIDetectionAgent } from '../src/agent.js';
import { AGENT_IDENTITY } from '../src/types.js';
import type { PIIDetectionInput, RuvectorClient } from '../src/types.js';

// Mock ruvector client
const mockRuvectorClient: RuvectorClient = {
  persistDecisionEvent: vi.fn().mockResolvedValue(undefined),
  isHealthy: vi.fn().mockResolvedValue(true),
};

// Mock telemetry emitter
const mockTelemetryEmitter = {
  emit: vi.fn(),
  flush: vi.fn().mockResolvedValue(undefined),
  shutdown: vi.fn().mockResolvedValue(undefined),
  getBufferSize: vi.fn().mockReturnValue(0),
  isEnabled: vi.fn().mockReturnValue(true),
};

describe('PIIDetectionAgent', () => {
  let agent: PIIDetectionAgent;

  beforeEach(() => {
    vi.clearAllMocks();

    agent = new PIIDetectionAgent({
      ruvectorClient: mockRuvectorClient,
      telemetryEmitter: mockTelemetryEmitter as any,
      persistEvents: true,
      emitTelemetry: true,
    });
  });

  describe('Agent Identity', () => {
    it('should have correct agent identity', () => {
      expect(AGENT_IDENTITY.agent_id).toBe('pii-detection-agent');
      expect(AGENT_IDENTITY.agent_version).toBe('1.0.0');
      expect(AGENT_IDENTITY.classification).toBe('DETECTION_ONLY');
      expect(AGENT_IDENTITY.decision_type).toBe('pii_detection');
    });
  });

  describe('detect()', () => {
    const createValidInput = (content: string): PIIDetectionInput => ({
      content,
      context: {
        execution_ref: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        timestamp: new Date().toISOString(),
        content_source: 'user_input',
      },
    });

    it('should return valid output for clean content', async () => {
      const input = createValidInput('Hello, this is clean content.');

      const output = await agent.detect(input);

      expect(output.agent).toEqual(AGENT_IDENTITY);
      expect(output.result.pii_detected).toBe(false);
      expect(output.result.risk_score).toBe(0);
      expect(output.result.severity).toBe('none');
      expect(output.result.entities).toHaveLength(0);
      expect(output.duration_ms).toBeGreaterThanOrEqual(0);
      expect(output.cached).toBe(false);
    });

    it('should detect email addresses', async () => {
      const input = createValidInput('Contact me at john@example.com');

      const output = await agent.detect(input);

      expect(output.result.pii_detected).toBe(true);
      expect(output.result.entities.length).toBeGreaterThan(0);
      expect(output.result.detected_types).toContain('email');
    });

    it('should detect SSN', async () => {
      const input = createValidInput('SSN: 123-45-6789');

      const output = await agent.detect(input);

      expect(output.result.pii_detected).toBe(true);
      expect(output.result.severity).toBe('critical');
      expect(output.result.detected_types).toContain('ssn');
    });

    it('should detect credit card numbers', async () => {
      const input = createValidInput('Card: 4111111111111111');

      const output = await agent.detect(input);

      expect(output.result.pii_detected).toBe(true);
      expect(output.result.severity).toBe('critical');
      expect(output.result.detected_types).toContain('credit_card');
    });

    it('should detect multiple PII types', async () => {
      const input = createValidInput(
        'Email: test@example.com, SSN: 123-45-6789, Card: 4111111111111111'
      );

      const output = await agent.detect(input);

      expect(output.result.pii_detected).toBe(true);
      expect(output.result.detected_types).toContain('email');
      expect(output.result.detected_types).toContain('ssn');
      expect(output.result.detected_types).toContain('credit_card');
    });

    it('should respect detect_types filter', async () => {
      const input: PIIDetectionInput = {
        content: 'Email: test@example.com, SSN: 123-45-6789',
        context: {
          execution_ref: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
        detect_types: ['email'], // Only detect email
      };

      const output = await agent.detect(input);

      expect(output.result.pii_detected).toBe(true);
      expect(output.result.detected_types).toContain('email');
      expect(output.result.detected_types).not.toContain('ssn');
    });

    it('should persist DecisionEvent', async () => {
      const input = createValidInput('Email: test@example.com');

      await agent.detect(input);

      // Wait for async persistence
      await new Promise(resolve => setTimeout(resolve, 100));

      expect(mockRuvectorClient.persistDecisionEvent).toHaveBeenCalled();
    });

    it('should emit telemetry', async () => {
      const input = createValidInput('Email: test@example.com');

      await agent.detect(input);

      expect(mockTelemetryEmitter.emit).toHaveBeenCalled();
    });

    it('should not persist when persistEvents is false', async () => {
      const agentNoPersist = new PIIDetectionAgent({
        ruvectorClient: mockRuvectorClient,
        persistEvents: false,
        emitTelemetry: false,
      });

      const input = createValidInput('Email: test@example.com');
      await agentNoPersist.detect(input);

      // Wait a bit
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(mockRuvectorClient.persistDecisionEvent).not.toHaveBeenCalled();
    });
  });

  describe('Input Validation', () => {
    it('should reject invalid input', async () => {
      const invalidInput = {
        content: 123, // Should be string
        context: {},
      };

      await expect(agent.detect(invalidInput as any)).rejects.toThrow();
    });

    it('should reject missing content', async () => {
      const invalidInput = {
        context: {
          execution_ref: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
      };

      await expect(agent.detect(invalidInput as any)).rejects.toThrow();
    });

    it('should reject invalid execution_ref format', async () => {
      const invalidInput = {
        content: 'test content',
        context: {
          execution_ref: 'not-a-uuid',
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
      };

      await expect(agent.detect(invalidInput as any)).rejects.toThrow();
    });
  });

  describe('Risk Score and Severity', () => {
    it('should calculate higher risk for critical PII', async () => {
      const agent = new PIIDetectionAgent({
        persistEvents: false,
        emitTelemetry: false,
      });

      // Email is medium severity
      const emailInput = {
        content: 'Email: test@example.com',
        context: {
          execution_ref: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
          timestamp: new Date().toISOString(),
          content_source: 'user_input' as const,
        },
        detect_types: ['email' as const],
      };

      // SSN is critical severity
      const ssnInput = {
        content: 'SSN: 123-45-6789',
        context: {
          execution_ref: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
          timestamp: new Date().toISOString(),
          content_source: 'user_input' as const,
        },
        detect_types: ['ssn' as const],
      };

      const emailOutput = await agent.detect(emailInput);
      const ssnOutput = await agent.detect(ssnInput);

      expect(ssnOutput.result.risk_score).toBeGreaterThan(emailOutput.result.risk_score);
      expect(ssnOutput.result.severity).toBe('critical');
      expect(emailOutput.result.severity).toBe('medium');
    });
  });

  describe('Type Counts', () => {
    it('should correctly count PII by type', async () => {
      const agent = new PIIDetectionAgent({
        persistEvents: false,
        emitTelemetry: false,
      });

      const input: PIIDetectionInput = {
        content: 'Emails: a@test.com, b@test.com, c@test.com',
        context: {
          execution_ref: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
      };

      const output = await agent.detect(input);

      expect(output.result.type_counts['email']).toBe(3);
    });
  });

  describe('Entities Output', () => {
    it('should not include raw PII values in entities', async () => {
      const agent = new PIIDetectionAgent({
        persistEvents: false,
        emitTelemetry: false,
      });

      const input: PIIDetectionInput = {
        content: 'Email: secret@private.com',
        context: {
          execution_ref: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
      };

      const output = await agent.detect(input);

      // Verify entities don't contain the actual email
      const outputStr = JSON.stringify(output);
      expect(outputStr).not.toContain('secret@private.com');

      // But should have position information
      expect(output.result.entities[0].start).toBeDefined();
      expect(output.result.entities[0].end).toBeDefined();
    });
  });
});
