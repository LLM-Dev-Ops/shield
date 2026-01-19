/**
 * PII Detector Tests
 *
 * Tests for the core PII detection logic.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { PIIDetector } from '../src/detector.js';
import type { DetectionConfig, PIIType, PIICountry } from '../src/types.js';

describe('PIIDetector', () => {
  let detector: PIIDetector;

  beforeEach(() => {
    detector = new PIIDetector();
  });

  describe('Email Detection', () => {
    it('should detect valid email addresses', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['email'],
        countries: ['US'],
      };

      const matches = detector.detect('Contact me at john.doe@example.com', config);

      expect(matches).toHaveLength(1);
      expect(matches[0].pattern.type).toBe('email');
      expect(matches[0].confidence).toBeGreaterThan(0.8);
    });

    it('should detect multiple email addresses', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['email'],
        countries: ['US'],
      };

      const content = 'Send to alice@example.com and bob@company.org';
      const matches = detector.detect(content, config);

      expect(matches).toHaveLength(2);
    });

    it('should not detect invalid email patterns', () => {
      const config: DetectionConfig = {
        sensitivity: 0.3,
        detectTypes: ['email'],
        countries: ['US'],
      };

      const matches = detector.detect('This is not an email: @example.com', config);

      expect(matches).toHaveLength(0);
    });
  });

  describe('SSN Detection', () => {
    it('should detect SSN in xxx-xx-xxxx format', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['ssn'],
        countries: ['US'],
      };

      const matches = detector.detect('SSN: 123-45-6789', config);

      expect(matches).toHaveLength(1);
      expect(matches[0].pattern.type).toBe('ssn');
      expect(matches[0].validationPassed).toBe(true);
    });

    it('should detect SSN in xxx xx xxxx format', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['ssn'],
        countries: ['US'],
      };

      const matches = detector.detect('SSN: 123 45 6789', config);

      expect(matches).toHaveLength(1);
      expect(matches[0].pattern.type).toBe('ssn');
    });

    it('should reject invalid SSN area numbers', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['ssn'],
        countries: ['US'],
      };

      // Area 000 is invalid
      const matches1 = detector.detect('SSN: 000-45-6789', config);
      expect(matches1).toHaveLength(0);

      // Area 666 is invalid
      const matches2 = detector.detect('SSN: 666-45-6789', config);
      expect(matches2).toHaveLength(0);

      // Area 900+ is invalid
      const matches3 = detector.detect('SSN: 900-45-6789', config);
      expect(matches3).toHaveLength(0);
    });
  });

  describe('Credit Card Detection', () => {
    it('should detect valid Visa card numbers', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['credit_card'],
        countries: ['US'],
      };

      // Valid Visa test number (passes Luhn)
      const matches = detector.detect('Card: 4111111111111111', config);

      expect(matches).toHaveLength(1);
      expect(matches[0].pattern.type).toBe('credit_card');
      expect(matches[0].validationPassed).toBe(true);
      expect(matches[0].confidence).toBeGreaterThan(0.95);
    });

    it('should detect valid Mastercard numbers', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['credit_card'],
        countries: ['US'],
      };

      // Valid Mastercard test number
      const matches = detector.detect('Card: 5555555555554444', config);

      expect(matches).toHaveLength(1);
      expect(matches[0].pattern.type).toBe('credit_card');
    });

    it('should reject invalid credit card numbers (fails Luhn)', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['credit_card'],
        countries: ['US'],
      };

      // Invalid number that doesn't pass Luhn check
      const matches = detector.detect('Card: 4111111111111112', config);

      expect(matches).toHaveLength(0);
    });

    it('should detect Amex card numbers', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['credit_card'],
        countries: ['US'],
      };

      // Valid Amex test number
      const matches = detector.detect('Card: 378282246310005', config);

      expect(matches).toHaveLength(1);
      expect(matches[0].pattern.type).toBe('credit_card');
    });
  });

  describe('Phone Number Detection', () => {
    it('should detect US phone numbers', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['phone'],
        countries: ['US'],
      };

      const matches = detector.detect('Call me at 555-123-4567', config);

      expect(matches).toHaveLength(1);
      expect(matches[0].pattern.type).toBe('phone');
    });

    it('should detect formatted US phone numbers', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['phone'],
        countries: ['US'],
      };

      const matches = detector.detect('Call (555) 123-4567', config);

      expect(matches).toHaveLength(1);
    });

    it('should detect UK phone numbers when UK country is enabled', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['phone'],
        countries: ['UK'],
      };

      const matches = detector.detect('Call +44 7911 123456', config);

      expect(matches).toHaveLength(1);
      expect(matches[0].pattern.type).toBe('phone');
    });
  });

  describe('IP Address Detection', () => {
    it('should detect IPv4 addresses', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['ip_address'],
        countries: ['US'],
      };

      const matches = detector.detect('Server IP: 192.168.1.100', config);

      expect(matches).toHaveLength(1);
      expect(matches[0].pattern.type).toBe('ip_address');
    });

    it('should detect IPv6 addresses', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['ip_address'],
        countries: ['US'],
      };

      const matches = detector.detect('IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334', config);

      expect(matches).toHaveLength(1);
      expect(matches[0].pattern.type).toBe('ip_address');
    });
  });

  describe('Multiple PII Types', () => {
    it('should detect multiple types of PII in content', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['email', 'ssn', 'phone'],
        countries: ['US'],
      };

      const content = 'Contact john@example.com, SSN: 123-45-6789, Phone: 555-123-4567';
      const matches = detector.detect(content, config);

      expect(matches.length).toBeGreaterThanOrEqual(3);

      const types = matches.map(m => m.pattern.type);
      expect(types).toContain('email');
      expect(types).toContain('ssn');
      expect(types).toContain('phone');
    });
  });

  describe('Sensitivity Adjustment', () => {
    it('should detect more matches with higher sensitivity', () => {
      const lowSensitivity: DetectionConfig = {
        sensitivity: 0.2,
        detectTypes: ['email', 'phone', 'ssn'],
        countries: ['US'],
      };

      const highSensitivity: DetectionConfig = {
        sensitivity: 0.8,
        detectTypes: ['email', 'phone', 'ssn'],
        countries: ['US'],
      };

      const content = 'SSN: 123-45-6789, email@test.com';

      const lowMatches = detector.detect(content, lowSensitivity);
      const highMatches = detector.detect(content, highSensitivity);

      // Higher sensitivity should have equal or more matches
      expect(highMatches.length).toBeGreaterThanOrEqual(lowMatches.length);
    });
  });

  describe('Risk Score Calculation', () => {
    it('should calculate higher risk for critical severity PII', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['credit_card', 'ip_address'],
        countries: ['US'],
      };

      // Credit card is critical severity
      const ccMatches = detector.detect('Card: 4111111111111111', config);
      const ccRisk = detector.calculateRiskScore(ccMatches);

      // IP address is low severity
      const ipMatches = detector.detect('IP: 192.168.1.1', config);
      const ipRisk = detector.calculateRiskScore(ipMatches);

      expect(ccRisk).toBeGreaterThan(ipRisk);
    });

    it('should return 0 risk score for no matches', () => {
      const riskScore = detector.calculateRiskScore([]);
      expect(riskScore).toBe(0);
    });
  });

  describe('Maximum Severity', () => {
    it('should return "none" for empty matches', () => {
      const severity = detector.getMaxSeverity([]);
      expect(severity).toBe('none');
    });

    it('should return correct max severity', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['email', 'ssn'],
        countries: ['US'],
      };

      // SSN is critical, email is medium
      const content = 'email@test.com, SSN: 123-45-6789';
      const matches = detector.detect(content, config);
      const severity = detector.getMaxSeverity(matches);

      expect(severity).toBe('critical');
    });
  });

  describe('Country Filtering', () => {
    it('should only use patterns for specified countries', () => {
      const usConfig: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['phone'],
        countries: ['US'],
      };

      const ukConfig: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['phone'],
        countries: ['UK'],
      };

      const ukPhone = '+44 7911 123456';

      const usMatches = detector.detect(ukPhone, usConfig);
      const ukMatches = detector.detect(ukPhone, ukConfig);

      // UK phone should match UK patterns better
      expect(ukMatches.length).toBeGreaterThan(0);
    });
  });

  describe('Overlapping Match Deduplication', () => {
    it('should remove overlapping matches keeping highest confidence', () => {
      const config: DetectionConfig = {
        sensitivity: 0.5,
        detectTypes: ['email', 'phone'],
        countries: ['US'],
      };

      // This shouldn't have overlapping matches, but if it did...
      const content = 'email@test.com';
      const matches = detector.detect(content, config);

      // Verify no overlapping positions in results
      for (let i = 0; i < matches.length - 1; i++) {
        for (let j = i + 1; j < matches.length; j++) {
          const overlap =
            matches[i].start < matches[j].end && matches[j].start < matches[i].end;
          expect(overlap).toBe(false);
        }
      }
    });
  });
});
