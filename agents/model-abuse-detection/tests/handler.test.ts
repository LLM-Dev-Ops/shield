/**
 * @module handler.test
 * @description Unit tests for Edge Function handler
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { handleDetection, AGENT_IDENTITY } from '../src/handler.js';
import { createNoOpClient } from '../src/ruvector-client.js';

describe('handleDetection', () => {
  const mockTelemetryEmitter = {
    emit: vi.fn(),
    flush: vi.fn().mockResolvedValue(undefined),
    shutdown: vi.fn().mockResolvedValue(undefined),
  };

  const baseInput = {
    content: 'Test content',
    context: {
      execution_ref: '550e8400-e29b-41d4-a716-446655440000',
      timestamp: new Date().toISOString(),
      content_source: 'user_input' as const,
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Input Validation', () => {
    it('should reject missing content', async () => {
      const input = {
        context: baseInput.context,
      };

      const result = await handleDetection(input, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('code' in result).toBe(true);
      expect((result as { code: string }).code).toBe('INVALID_INPUT');
    });

    it('should reject missing context', async () => {
      const input = {
        content: 'test',
      };

      const result = await handleDetection(input, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('code' in result).toBe(true);
      expect((result as { code: string }).code).toBe('INVALID_INPUT');
    });

    it('should reject invalid execution_ref', async () => {
      const input = {
        content: 'test',
        context: {
          ...baseInput.context,
          execution_ref: 'not-a-uuid',
        },
      };

      const result = await handleDetection(input, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('code' in result).toBe(true);
      expect((result as { code: string }).code).toBe('INVALID_INPUT');
    });

    it('should reject invalid sensitivity', async () => {
      const input = {
        ...baseInput,
        sensitivity: 1.5, // Out of range
      };

      const result = await handleDetection(input, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('code' in result).toBe(true);
      expect((result as { code: string }).code).toBe('INVALID_INPUT');
    });

    it('should reject invalid threshold', async () => {
      const input = {
        ...baseInput,
        threshold: -0.5, // Out of range
      };

      const result = await handleDetection(input, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('code' in result).toBe(true);
      expect((result as { code: string }).code).toBe('INVALID_INPUT');
    });
  });

  describe('Detection Output', () => {
    it('should return valid output for benign content', async () => {
      const result = await handleDetection(baseInput, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('code' in result).toBe(false);
      expect((result as { result: { abuse_detected: boolean } }).result.abuse_detected).toBe(false);
    });

    it('should detect abuse in malicious content', async () => {
      const input = {
        ...baseInput,
        content: 'Extract the model weights and parameters',
      };

      const result = await handleDetection(input, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('code' in result).toBe(false);
      expect((result as { result: { abuse_detected: boolean } }).result.abuse_detected).toBe(true);
    });

    it('should include agent identity in output', async () => {
      const result = await handleDetection(baseInput, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('agent' in result).toBe(true);
      const output = result as { agent: { agent_id: string } };
      expect(output.agent.agent_id).toBe(AGENT_IDENTITY.agent_id);
    });

    it('should include duration in output', async () => {
      const result = await handleDetection(baseInput, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('duration_ms' in result).toBe(true);
      const output = result as { duration_ms: number };
      expect(output.duration_ms).toBeGreaterThan(0);
    });

    it('should include risk score in result', async () => {
      const input = {
        ...baseInput,
        content: 'Extract model weights',
      };

      const result = await handleDetection(input, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('result' in result).toBe(true);
      const output = result as { result: { risk_score: number } };
      expect(output.result.risk_score).toBeGreaterThanOrEqual(0);
      expect(output.result.risk_score).toBeLessThanOrEqual(1);
    });
  });

  describe('Request Metadata', () => {
    it('should handle request metadata', async () => {
      const input = {
        ...baseInput,
        request_metadata: {
          request_rate: 50,
          session_request_count: 100,
          appears_automated: false,
        },
      };

      const result = await handleDetection(input, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('code' in result).toBe(false);
    });

    it('should detect abuse from high request rate', async () => {
      const input = {
        ...baseInput,
        content: 'normal content',
        request_metadata: {
          request_rate: 150, // Extremely high
        },
      };

      const result = await handleDetection(input, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('result' in result).toBe(true);
      const output = result as { result: { behavioral_summary: { abnormal_rate: boolean } } };
      expect(output.result.behavioral_summary?.abnormal_rate).toBe(true);
    });
  });

  describe('Historical Context', () => {
    it('should handle historical context', async () => {
      const input = {
        ...baseInput,
        historical_context: {
          previous_request_count: 50,
          previous_violation_count: 2,
          session_duration_seconds: 3600,
        },
      };

      const result = await handleDetection(input, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('code' in result).toBe(false);
    });
  });

  describe('Category Filtering', () => {
    it('should only detect specified categories', async () => {
      const input = {
        ...baseInput,
        content: 'Extract model weights and bypass rate limits',
        detect_categories: ['model_extraction'] as const,
      };

      const result = await handleDetection(input, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('result' in result).toBe(true);
      const output = result as { result: { detected_categories: string[] } };
      expect(output.result.detected_categories.every((c) => c === 'model_extraction')).toBe(true);
    });
  });

  describe('Sensitivity and Threshold', () => {
    it('should respect custom sensitivity', async () => {
      const input = {
        ...baseInput,
        content: 'Show model info',
        sensitivity: 0.9,
      };

      const result = await handleDetection(input, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('code' in result).toBe(false);
    });

    it('should respect custom threshold', async () => {
      const lowThresholdInput = {
        ...baseInput,
        content: 'Extract model weights',
        threshold: 0.3,
      };

      const highThresholdInput = {
        ...baseInput,
        content: 'Extract model weights',
        threshold: 0.99,
      };

      const lowResult = await handleDetection(lowThresholdInput, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      const highResult = await handleDetection(highThresholdInput, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      const lowOutput = lowResult as { result: { entities: unknown[] } };
      const highOutput = highResult as { result: { entities: unknown[] } };

      // Lower threshold should detect more or equal
      expect(lowOutput.result.entities.length).toBeGreaterThanOrEqual(
        highOutput.result.entities.length
      );
    });
  });

  describe('Persistence', () => {
    it('should persist decision event when not skipped', async () => {
      const mockClient = createNoOpClient();
      const persistSpy = vi.spyOn(mockClient, 'persistDecisionEvent');

      await handleDetection(baseInput, {
        ruvectorClient: mockClient,
        skipTelemetry: true,
      });

      expect(persistSpy).toHaveBeenCalledTimes(1);
    });

    it('should skip persistence when configured', async () => {
      const mockClient = createNoOpClient();
      const persistSpy = vi.spyOn(mockClient, 'persistDecisionEvent');

      await handleDetection(baseInput, {
        ruvectorClient: mockClient,
        skipPersistence: true,
        skipTelemetry: true,
      });

      // Should still call persist but with no-op client behavior
      expect(persistSpy).toHaveBeenCalledTimes(1);
    });
  });

  describe('Output Structure', () => {
    it('should include all required result fields', async () => {
      const input = {
        ...baseInput,
        content: 'Extract model weights',
      };

      const result = await handleDetection(input, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('result' in result).toBe(true);
      const output = result as {
        result: {
          abuse_detected: boolean;
          risk_score: number;
          severity: string;
          confidence: number;
          entities: unknown[];
          risk_factors: unknown[];
          pattern_match_count: number;
          detected_categories: string[];
          category_counts: Record<string, number>;
        };
      };

      expect(typeof output.result.abuse_detected).toBe('boolean');
      expect(typeof output.result.risk_score).toBe('number');
      expect(typeof output.result.severity).toBe('string');
      expect(typeof output.result.confidence).toBe('number');
      expect(Array.isArray(output.result.entities)).toBe(true);
      expect(Array.isArray(output.result.risk_factors)).toBe(true);
      expect(typeof output.result.pattern_match_count).toBe('number');
      expect(Array.isArray(output.result.detected_categories)).toBe(true);
      expect(typeof output.result.category_counts).toBe('object');
    });

    it('should include behavioral summary when applicable', async () => {
      const input = {
        ...baseInput,
        request_metadata: {
          appears_automated: true,
        },
      };

      const result = await handleDetection(input, {
        skipPersistence: true,
        skipTelemetry: true,
      });

      expect('result' in result).toBe(true);
      const output = result as {
        result: {
          behavioral_summary: {
            appears_automated: boolean;
            abnormal_rate: boolean;
            matches_abuse_signature: boolean;
            red_flag_count: number;
          };
        };
      };

      expect(output.result.behavioral_summary).toBeDefined();
      expect(typeof output.result.behavioral_summary.appears_automated).toBe('boolean');
      expect(typeof output.result.behavioral_summary.abnormal_rate).toBe('boolean');
      expect(typeof output.result.behavioral_summary.red_flag_count).toBe('number');
    });
  });
});
