/**
 * Toxicity Detection Agent Tests
 *
 * @module toxicity-detection-agent/tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { ToxicityDetectionAgent } from '../src/agent.js';
import { ToxicityDetector } from '../src/detector.js';
import { AGENT_IDENTITY } from '../src/types.js';
import { v4 as uuidv4 } from 'uuid';

describe('ToxicityDetectionAgent', () => {
  let agent: ToxicityDetectionAgent;

  beforeEach(() => {
    agent = new ToxicityDetectionAgent({
      persistEvents: false,
      emitTelemetry: false,
    });
  });

  describe('Agent Identity', () => {
    it('should have correct agent identity', () => {
      expect(AGENT_IDENTITY.agent_id).toBe('toxicity-detection-agent');
      expect(AGENT_IDENTITY.agent_version).toBe('1.0.0');
      expect(AGENT_IDENTITY.classification).toBe('DETECTION_ONLY');
      expect(AGENT_IDENTITY.decision_type).toBe('toxicity_detection');
    });
  });

  describe('detect()', () => {
    it('should detect insults in content', async () => {
      const input = {
        content: 'You are an idiot and completely stupid',
        context: {
          execution_ref: uuidv4(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input' as const,
        },
      };

      const output = await agent.detect(input);

      expect(output.result.toxicity_detected).toBe(true);
      expect(output.result.detected_categories).toContain('insult');
      expect(output.result.risk_score).toBeGreaterThan(0);
      expect(output.result.severity).not.toBe('none');
    });

    it('should detect threats in content', async () => {
      const input = {
        content: 'I will kill you if you do not listen',
        context: {
          execution_ref: uuidv4(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input' as const,
        },
      };

      const output = await agent.detect(input);

      expect(output.result.toxicity_detected).toBe(true);
      expect(output.result.detected_categories).toContain('threat');
      expect(output.result.severity).toBe('critical');
    });

    it('should not detect toxicity in clean content', async () => {
      const input = {
        content: 'Thank you for your help, I really appreciate it!',
        context: {
          execution_ref: uuidv4(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input' as const,
        },
      };

      const output = await agent.detect(input);

      expect(output.result.toxicity_detected).toBe(false);
      expect(output.result.risk_score).toBe(0);
      expect(output.result.severity).toBe('none');
      expect(output.result.entities).toHaveLength(0);
    });

    it('should respect threshold settings', async () => {
      const input = {
        content: 'You are a fool',
        context: {
          execution_ref: uuidv4(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input' as const,
        },
        threshold: 0.95, // Very high threshold
      };

      const output = await agent.detect(input);

      // With high threshold, might not flag lower-confidence matches
      expect(output.result.entities.every(e => e.confidence >= 0.95 || !output.result.toxicity_detected)).toBe(true);
    });

    it('should include agent identity in output', async () => {
      const input = {
        content: 'You are an idiot',
        context: {
          execution_ref: uuidv4(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input' as const,
        },
      };

      const output = await agent.detect(input);

      expect(output.agent.agent_id).toBe('toxicity-detection-agent');
      expect(output.agent.agent_version).toBe('1.0.0');
      expect(output.agent.classification).toBe('DETECTION_ONLY');
      expect(output.agent.decision_type).toBe('toxicity_detection');
    });

    it('should include duration in output', async () => {
      const input = {
        content: 'This is a test message',
        context: {
          execution_ref: uuidv4(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input' as const,
        },
      };

      const output = await agent.detect(input);

      expect(output.duration_ms).toBeGreaterThanOrEqual(0);
      expect(output.cached).toBe(false);
    });

    it('should detect multiple categories in content', async () => {
      const input = {
        content: 'You are an idiot and I will hurt you',
        context: {
          execution_ref: uuidv4(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input' as const,
        },
      };

      const output = await agent.detect(input);

      expect(output.result.toxicity_detected).toBe(true);
      expect(output.result.detected_categories.length).toBeGreaterThanOrEqual(2);
    });

    it('should filter by specific categories', async () => {
      const input = {
        content: 'You are an idiot and I hate you',
        context: {
          execution_ref: uuidv4(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input' as const,
        },
        detect_categories: ['threat'] as const, // Only look for threats
      };

      const output = await agent.detect(input);

      // Should not detect insults when only looking for threats
      expect(output.result.detected_categories.every(c => c === 'threat')).toBe(true);
    });

    it('should not include raw toxic content in entities', async () => {
      const input = {
        content: 'You are an idiot and stupid',
        context: {
          execution_ref: uuidv4(),
          timestamp: new Date().toISOString(),
          content_source: 'user_input' as const,
        },
      };

      const output = await agent.detect(input);
      const outputStr = JSON.stringify(output);

      // Should not contain the actual toxic words in output (only positions)
      // The entities should have positions but no matchedText field
      for (const entity of output.result.entities) {
        expect(entity).not.toHaveProperty('matchedText');
        expect(entity).toHaveProperty('start');
        expect(entity).toHaveProperty('end');
        expect(entity).toHaveProperty('toxicity_category');
      }
    });
  });
});

describe('ToxicityDetector', () => {
  let detector: ToxicityDetector;

  beforeEach(() => {
    detector = new ToxicityDetector();
  });

  describe('detect()', () => {
    it('should detect insult patterns', () => {
      const config = ToxicityDetector.createDefaultConfig({});
      const matches = detector.detect('You are an idiot', config);

      expect(matches.length).toBeGreaterThan(0);
      expect(matches.some(m => m.pattern.category === 'insult')).toBe(true);
    });

    it('should detect threat patterns', () => {
      const config = ToxicityDetector.createDefaultConfig({});
      const matches = detector.detect('I will kill you', config);

      expect(matches.length).toBeGreaterThan(0);
      expect(matches.some(m => m.pattern.category === 'threat')).toBe(true);
    });

    it('should not match clean text', () => {
      const config = ToxicityDetector.createDefaultConfig({});
      const matches = detector.detect('Hello, how are you today?', config);

      expect(matches.length).toBe(0);
    });

    it('should calculate risk score correctly', () => {
      const config = ToxicityDetector.createDefaultConfig({});
      const matches = detector.detect('You are an idiot', config);
      const riskScore = detector.calculateRiskScore(matches);

      expect(riskScore).toBeGreaterThan(0);
      expect(riskScore).toBeLessThanOrEqual(1);
    });

    it('should determine max severity correctly', () => {
      const config = ToxicityDetector.createDefaultConfig({});
      const threatMatches = detector.detect('I will kill you', config);
      const severity = detector.getMaxSeverity(threatMatches);

      expect(severity).toBe('critical');
    });

    it('should return none severity for no matches', () => {
      const severity = detector.getMaxSeverity([]);
      expect(severity).toBe('none');
    });
  });

  describe('createDefaultConfig()', () => {
    it('should create config with defaults', () => {
      const config = ToxicityDetector.createDefaultConfig({});

      expect(config.sensitivity).toBe(0.5);
      expect(config.threshold).toBe(0.7);
      expect(config.detectCategories).toContain('toxic');
      expect(config.detectCategories).toContain('threat');
      expect(config.detectCategories).toContain('insult');
    });

    it('should override defaults with provided values', () => {
      const config = ToxicityDetector.createDefaultConfig({
        sensitivity: 0.8,
        threshold: 0.5,
        detect_categories: ['threat', 'insult'],
      });

      expect(config.sensitivity).toBe(0.8);
      expect(config.threshold).toBe(0.5);
      expect(config.detectCategories).toHaveLength(2);
    });
  });
});
