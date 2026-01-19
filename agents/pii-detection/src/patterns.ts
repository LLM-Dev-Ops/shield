/**
 * PII Detection Patterns
 *
 * Contains all pattern definitions for detecting various types of PII.
 * Patterns are organized by PII type and include validation methods
 * where applicable.
 *
 * @module pii-detection-agent/patterns
 */

import type { PIIPattern } from './types.js';

/**
 * Email address patterns
 */
const EMAIL_PATTERNS: PIIPattern[] = [
  {
    id: 'email-rfc5322',
    type: 'email',
    name: 'Email Address (RFC 5322)',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    severity: 'medium',
    baseConfidence: 0.95,
    validationMethod: 'format',
  },
];

/**
 * Phone number patterns
 */
const PHONE_PATTERNS: PIIPattern[] = [
  {
    id: 'phone-us',
    type: 'phone',
    name: 'US Phone Number',
    pattern: /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    severity: 'medium',
    baseConfidence: 0.75,
    validationMethod: 'format',
    countries: ['US'],
  },
  {
    id: 'phone-uk',
    type: 'phone',
    name: 'UK Phone Number',
    pattern: /\b\+44\s?[0-9]{4}\s?[0-9]{6}\b/g,
    severity: 'medium',
    baseConfidence: 0.75,
    validationMethod: 'format',
    countries: ['UK'],
  },
  {
    id: 'phone-international',
    type: 'phone',
    name: 'International Phone Number',
    pattern: /\b\+[1-9]\d{1,14}\b/g,
    severity: 'medium',
    baseConfidence: 0.70,
    validationMethod: 'format',
  },
];

/**
 * Social Security Number patterns
 */
const SSN_PATTERNS: PIIPattern[] = [
  {
    id: 'ssn-dashed',
    type: 'ssn',
    name: 'SSN (xxx-xx-xxxx)',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    severity: 'critical',
    baseConfidence: 0.90,
    validationMethod: 'area_check',
    countries: ['US'],
  },
  {
    id: 'ssn-spaced',
    type: 'ssn',
    name: 'SSN (xxx xx xxxx)',
    pattern: /\b\d{3}\s\d{2}\s\d{4}\b/g,
    severity: 'critical',
    baseConfidence: 0.90,
    validationMethod: 'area_check',
    countries: ['US'],
  },
  {
    id: 'ssn-raw',
    type: 'ssn',
    name: 'SSN (raw 9 digits)',
    // More restrictive to reduce false positives
    pattern: /\b(?<![\d.-])([0-6]\d{2}|7[0-6]\d|77[0-2])(\d{2})(\d{4})(?![\d.-])\b/g,
    severity: 'high',
    baseConfidence: 0.70,
    validationMethod: 'area_check',
    countries: ['US'],
  },
];

/**
 * Credit card patterns
 */
const CREDIT_CARD_PATTERNS: PIIPattern[] = [
  {
    id: 'cc-visa',
    type: 'credit_card',
    name: 'Credit Card (Visa)',
    pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/g,
    severity: 'critical',
    baseConfidence: 0.99,
    validationMethod: 'luhn',
  },
  {
    id: 'cc-mastercard',
    type: 'credit_card',
    name: 'Credit Card (Mastercard)',
    pattern: /\b5[1-5][0-9]{14}\b/g,
    severity: 'critical',
    baseConfidence: 0.99,
    validationMethod: 'luhn',
  },
  {
    id: 'cc-amex',
    type: 'credit_card',
    name: 'Credit Card (Amex)',
    pattern: /\b3[47][0-9]{13}\b/g,
    severity: 'critical',
    baseConfidence: 0.99,
    validationMethod: 'luhn',
  },
  {
    id: 'cc-discover',
    type: 'credit_card',
    name: 'Credit Card (Discover)',
    pattern: /\b6(?:011|5[0-9]{2})[0-9]{12}\b/g,
    severity: 'critical',
    baseConfidence: 0.99,
    validationMethod: 'luhn',
  },
  {
    id: 'cc-spaced',
    type: 'credit_card',
    name: 'Credit Card (spaced/dashed)',
    pattern: /\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b/g,
    severity: 'critical',
    baseConfidence: 0.99,
    validationMethod: 'luhn',
  },
];

/**
 * IP address patterns
 */
const IP_ADDRESS_PATTERNS: PIIPattern[] = [
  {
    id: 'ipv4',
    type: 'ip_address',
    name: 'IPv4 Address',
    pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    severity: 'low',
    baseConfidence: 0.85,
    validationMethod: 'format',
  },
  {
    id: 'ipv6',
    type: 'ip_address',
    name: 'IPv6 Address',
    pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
    severity: 'low',
    baseConfidence: 0.85,
    validationMethod: 'format',
  },
  {
    id: 'ipv6-compressed',
    type: 'ip_address',
    name: 'IPv6 Address (compressed)',
    pattern: /\b(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b/g,
    severity: 'low',
    baseConfidence: 0.80,
    validationMethod: 'format',
  },
];

/**
 * Passport number patterns
 */
const PASSPORT_PATTERNS: PIIPattern[] = [
  {
    id: 'passport-us',
    type: 'passport',
    name: 'US Passport Number',
    pattern: /\b[A-Z][0-9]{8}\b/g,
    severity: 'high',
    baseConfidence: 0.80,
    validationMethod: 'format',
    countries: ['US'],
  },
  {
    id: 'passport-uk',
    type: 'passport',
    name: 'UK Passport Number',
    pattern: /\b[0-9]{9}\b/g,
    severity: 'high',
    baseConfidence: 0.60, // Lower confidence due to generic pattern
    validationMethod: 'format',
    countries: ['UK'],
  },
];

/**
 * Driver's license patterns
 */
const DRIVERS_LICENSE_PATTERNS: PIIPattern[] = [
  {
    id: 'dl-generic',
    type: 'drivers_license',
    name: 'Driver\'s License (generic)',
    pattern: /\b[A-Z][0-9]{7,8}\b/g,
    severity: 'high',
    baseConfidence: 0.75,
    validationMethod: 'format',
    countries: ['US'],
  },
  {
    id: 'dl-california',
    type: 'drivers_license',
    name: 'California Driver\'s License',
    pattern: /\b[A-Z][0-9]{7}\b/g,
    severity: 'high',
    baseConfidence: 0.80,
    validationMethod: 'format',
    countries: ['US'],
  },
];

/**
 * Date of birth patterns
 */
const DOB_PATTERNS: PIIPattern[] = [
  {
    id: 'dob-us',
    type: 'date_of_birth',
    name: 'Date of Birth (MM/DD/YYYY)',
    pattern: /\b(?:0[1-9]|1[0-2])\/(?:0[1-9]|[12]\d|3[01])\/(?:19|20)\d{2}\b/g,
    severity: 'medium',
    baseConfidence: 0.70,
    validationMethod: 'format',
    countries: ['US'],
  },
  {
    id: 'dob-iso',
    type: 'date_of_birth',
    name: 'Date of Birth (YYYY-MM-DD)',
    pattern: /\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b/g,
    severity: 'medium',
    baseConfidence: 0.70,
    validationMethod: 'format',
  },
  {
    id: 'dob-eu',
    type: 'date_of_birth',
    name: 'Date of Birth (DD/MM/YYYY)',
    pattern: /\b(?:0[1-9]|[12]\d|3[01])\/(?:0[1-9]|1[0-2])\/(?:19|20)\d{2}\b/g,
    severity: 'medium',
    baseConfidence: 0.70,
    validationMethod: 'format',
    countries: ['UK', 'EU', 'AU'],
  },
];

/**
 * Physical address patterns
 */
const ADDRESS_PATTERNS: PIIPattern[] = [
  {
    id: 'address-us-street',
    type: 'address',
    name: 'US Street Address',
    pattern: /\b\d{1,5}\s+(?:[A-Za-z]+\s+){1,4}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl)\b/gi,
    severity: 'medium',
    baseConfidence: 0.75,
    validationMethod: 'format',
    countries: ['US'],
  },
  {
    id: 'address-us-zip',
    type: 'address',
    name: 'US ZIP Code',
    pattern: /\b\d{5}(?:-\d{4})?\b/g,
    severity: 'low',
    baseConfidence: 0.60,
    validationMethod: 'format',
    countries: ['US'],
  },
  {
    id: 'address-uk-postcode',
    type: 'address',
    name: 'UK Postcode',
    pattern: /\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b/gi,
    severity: 'low',
    baseConfidence: 0.70,
    validationMethod: 'format',
    countries: ['UK'],
  },
];

/**
 * Name patterns (using common name indicators)
 */
const NAME_PATTERNS: PIIPattern[] = [
  {
    id: 'name-titled',
    type: 'name',
    name: 'Name with Title',
    pattern: /\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss|Dr\.?|Prof\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b/g,
    severity: 'low',
    baseConfidence: 0.65,
    validationMethod: 'format',
  },
];

/**
 * All PII patterns organized for export
 */
export const PII_PATTERNS: PIIPattern[] = [
  ...EMAIL_PATTERNS,
  ...PHONE_PATTERNS,
  ...SSN_PATTERNS,
  ...CREDIT_CARD_PATTERNS,
  ...IP_ADDRESS_PATTERNS,
  ...PASSPORT_PATTERNS,
  ...DRIVERS_LICENSE_PATTERNS,
  ...DOB_PATTERNS,
  ...ADDRESS_PATTERNS,
  ...NAME_PATTERNS,
];

/**
 * Get patterns by PII type
 */
export function getPatternsByType(type: string): PIIPattern[] {
  return PII_PATTERNS.filter(p => p.type === type);
}

/**
 * Get patterns by country
 */
export function getPatternsByCountry(country: string): PIIPattern[] {
  return PII_PATTERNS.filter(p => !p.countries || p.countries.includes(country as any));
}

/**
 * Get pattern by ID
 */
export function getPatternById(id: string): PIIPattern | undefined {
  return PII_PATTERNS.find(p => p.id === id);
}
