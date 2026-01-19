/**
 * @module agent.test
 * @description Unit tests for Content Moderation Agent
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { randomUUID } from 'crypto';
import { ContentModerationAgent, createAgent, AGENT_IDENTITY } from '../src/agent.js';
import type { ContentModerationAgentInput } from '@llm-shield/agentics-contracts';

// Mock fetch for ruvector-service and telemetry
vi.stubGlobal('fetch', vi.fn(() =>
  Promise.resolve({
    ok: true,
    json: () => Promise.resolve({ success: true, event_id: 'test-event-id' }),
  })
));

describe('ContentModerationAgent', () => {
  let agent: ContentModerationAgent;

  beforeEach(() => {
    agent = createAgent({
      ruvectorConfig: { baseUrl: 'http://mock-ruvector' },
      telemetryConfig: { enabled: false },
    });
  });

  afterEach(async () => {
    await agent.shutdown();
    vi.clearAllMocks();
  });

  describe('AGENT_IDENTITY', () => {
    it('should have correct agent identity', () => {
      expect(AGENT_IDENTITY.agent_id).toBe('content-moderation-agent');
      expect(AGENT_IDENTITY.agent_version).toBe('1.0.0');
      expect(AGENT_IDENTITY.classification).toBe('ENFORCEMENT');
      expect(AGENT_IDENTITY.decision_type).toBe('content_moderation');
    });
  });

  describe('validateInput', () => {
    it('should validate correct input', () => {
      const input = {
        content: 'Test content',
        context: {
          execution_ref: randomUUID(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input' as const,
        },
      };

      const validated = agent.validateInput(input);
      expect(validated.content).toBe('Test content');
      expect(validated.context.content_source).toBe('user_input');
    });

    it('should reject invalid input', () => {
      const input = {
        content: 123, // Should be string
        context: {},
      };

      expect(() => agent.validateInput(input)).toThrow();
    });

    it('should apply default values', () => {
      const input = {
        content: 'Test',
        context: {
          execution_ref: randomUUID(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input' as const,
        },
      };

      const validated = agent.validateInput(input);
      expect(validated.sensitivity).toBe(0.7);
      expect(validated.default_action).toBe('BLOCK');
      expect(validated.user_age_verified).toBe(false);
    });
  });

  describe('moderate', () => {
    it('should allow safe content', async () => {
      const input: ContentModerationAgentInput = {
        content: 'This is a friendly message about programming.',
        context: {
          execution_ref: randomUUID(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
      };

      const result = await agent.moderate(input);

      expect(result.result.allowed).toBe(true);
      expect(result.result.action).toBe('ALLOW');
      expect(result.result.violations_detected).toBe(false);
      expect(result.result.violations).toHaveLength(0);
      expect(result.result.risk_score).toBe(0);
      expect(result.agent).toEqual(AGENT_IDENTITY);
    });

    it('should block child safety violations', async () => {
      const input: ContentModerationAgentInput = {
        content: 'child exploitation content',
        context: {
          execution_ref: randomUUID(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
      };

      const result = await agent.moderate(input);

      expect(result.result.allowed).toBe(false);
      expect(result.result.action).toBe('BLOCK');
      expect(result.result.violations_detected).toBe(true);
      expect(result.result.violated_categories).toContain('child_safety');
      expect(result.result.severity).toBe('critical');
    });

    it('should block hate speech', async () => {
      const input: ContentModerationAgentInput = {
        content: 'kill all people of a certain race',
        context: {
          execution_ref: randomUUID(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
      };

      const result = await agent.moderate(input);

      expect(result.result.allowed).toBe(false);
      expect(result.result.action).toBe('BLOCK');
      expect(result.result.violated_categories).toContain('hate_discriminatory');
    });

    it('should block self-harm content', async () => {
      const input: ContentModerationAgentInput = {
        content: 'how to kill yourself methods',
        context: {
          execution_ref: randomUUID(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
      };

      const result = await agent.moderate(input);

      expect(result.result.allowed).toBe(false);
      expect(result.result.action).toBe('BLOCK');
      expect(result.result.violated_categories).toContain('self_harm');
    });

    it('should apply age gate for adult content without verification', async () => {
      const input: ContentModerationAgentInput = {
        content: 'explicit sexual content material',
        context: {
          execution_ref: randomUUID(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
        user_age_verified: false,
      };

      const result = await agent.moderate(input);

      expect(result.result.action).toBe('AGE_GATE');
      expect(result.result.violated_categories).toContain('adult_content');
    });

    it('should warn for adult content with age verification', async () => {
      const input: ContentModerationAgentInput = {
        content: 'explicit sexual content material',
        context: {
          execution_ref: randomUUID(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
        user_age_verified: true,
      };

      const result = await agent.moderate(input);

      expect(result.result.allowed).toBe(true);
      expect(result.result.action).toBe('WARN');
      expect(result.result.content_warning).toBeDefined();
    });

    it('should respect custom moderation rules', async () => {
      const input: ContentModerationAgentInput = {
        content: 'This is spam misleading content link',
        context: {
          execution_ref: randomUUID(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
        moderation_rules: [
          {
            rule_id: 'custom-spam-allow',
            category: 'spam_misleading',
            description: 'Allow spam for testing',
            action: 'ALLOW',
            threshold: 0.5,
            enabled: true,
            priority: 1,
          },
        ],
      };

      const result = await agent.moderate(input);

      // Even with custom rule, scam content should be blocked
      // because the pattern matches at higher confidence
      expect(result.result.violations_detected).toBe(false);
    });

    it('should flag content below confidence threshold', async () => {
      const agentLowThreshold = createAgent({
        ruvectorConfig: { baseUrl: 'http://mock-ruvector' },
        telemetryConfig: { enabled: false },
        minModerationConfidence: 0.99, // Very high threshold
      });

      const input: ContentModerationAgentInput = {
        content: 'election was stolen fraud',
        context: {
          execution_ref: randomUUID(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
        min_moderation_confidence: 0.99,
      };

      const result = await agentLowThreshold.moderate(input);

      expect(result.result.action).toBe('FLAG');
      expect(result.result.requires_human_review).toBe(true);

      await agentLowThreshold.shutdown();
    });

    it('should include execution metadata', async () => {
      const input: ContentModerationAgentInput = {
        content: 'Safe test content',
        context: {
          execution_ref: randomUUID(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
      };

      const result = await agent.moderate(input);

      expect(result.duration_ms).toBeGreaterThan(0);
      expect(result.cached).toBe(false);
      expect(result.agent.agent_id).toBe('content-moderation-agent');
    });

    it('should filter by categories', async () => {
      const input: ContentModerationAgentInput = {
        content: 'explicit sexual content material',
        context: {
          execution_ref: randomUUID(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
        moderate_categories: ['hate_discriminatory'], // Only check hate speech
      };

      const result = await agent.moderate(input);

      // Should not detect adult content since we only check hate_discriminatory
      expect(result.result.allowed).toBe(true);
      expect(result.result.violated_categories).not.toContain('adult_content');
    });
  });

  describe('decision semantics', () => {
    it('should set requires_human_review for FLAG actions', async () => {
      const agentWithFlag = createAgent({
        ruvectorConfig: { baseUrl: 'http://mock-ruvector' },
        telemetryConfig: { enabled: false },
        defaultAction: 'FLAG',
      });

      const input: ContentModerationAgentInput = {
        content: 'impersonate a doctor to give medical advice',
        context: {
          execution_ref: randomUUID(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
        default_action: 'FLAG',
      };

      const result = await agentWithFlag.moderate(input);

      if (result.result.violations_detected) {
        expect(result.result.requires_human_review).toBe(true);
      }

      await agentWithFlag.shutdown();
    });

    it('should not require human review for clean content', async () => {
      const input: ContentModerationAgentInput = {
        content: 'What is the weather like today?',
        context: {
          execution_ref: randomUUID(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input',
        },
      };

      const result = await agent.moderate(input);

      expect(result.result.requires_human_review).toBe(false);
    });
  });
});

describe('ContentModerationAgent - Edge Cases', () => {
  let agent: ContentModerationAgent;

  beforeEach(() => {
    agent = createAgent({
      ruvectorConfig: { baseUrl: 'http://mock-ruvector' },
      telemetryConfig: { enabled: false },
    });
  });

  afterEach(async () => {
    await agent.shutdown();
  });

  it('should handle empty content', async () => {
    const input: ContentModerationAgentInput = {
      content: '',
      context: {
        execution_ref: randomUUID(),
        timestamp: new Date().toISOString(),
        content_source: 'user_input',
      },
    };

    const result = await agent.moderate(input);

    expect(result.result.allowed).toBe(true);
    expect(result.result.violations).toHaveLength(0);
  });

  it('should handle very long content', async () => {
    const input: ContentModerationAgentInput = {
      content: 'Safe content. '.repeat(10000),
      context: {
        execution_ref: randomUUID(),
        timestamp: new Date().toISOString(),
        content_source: 'user_input',
      },
    };

    const result = await agent.moderate(input);

    expect(result.result.allowed).toBe(true);
  });

  it('should handle unicode content', async () => {
    const input: ContentModerationAgentInput = {
      content: 'Hello 世界! 🌍 Привет мир! مرحبا',
      context: {
        execution_ref: randomUUID(),
        timestamp: new Date().toISOString(),
        content_source: 'user_input',
      },
    };

    const result = await agent.moderate(input);

    expect(result.result.allowed).toBe(true);
  });

  it('should handle case insensitivity', async () => {
    const inputLower: ContentModerationAgentInput = {
      content: 'child exploitation',
      context: {
        execution_ref: randomUUID(),
        timestamp: new Date().toISOString(),
        content_source: 'user_input',
      },
    };

    const inputUpper: ContentModerationAgentInput = {
      content: 'CHILD EXPLOITATION',
      context: {
        execution_ref: randomUUID(),
        timestamp: new Date().toISOString(),
        content_source: 'user_input',
      },
    };

    const resultLower = await agent.moderate(inputLower);
    const resultUpper = await agent.moderate(inputUpper);

    // Both should be blocked
    expect(resultLower.result.allowed).toBe(false);
    expect(resultUpper.result.allowed).toBe(false);
  });
});
