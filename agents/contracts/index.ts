/**
 * @module agentics-contracts
 * @description Schema definitions for LLM-Shield agents
 *
 * All agents MUST import schemas exclusively from this module.
 * This ensures contract compliance and type safety across the platform.
 */

import { z } from 'zod';

// =============================================================================
// CORE ENUMS
// =============================================================================

/**
 * Agent classification determines behavior and capabilities
 */
export const AgentClassification = z.enum([
  'DETECTION_ONLY',    // Detects threats, does not modify content
  'REDACTION',         // Detects and sanitizes/redacts content
  'ENFORCEMENT',       // Full enforcement: BLOCK / ALLOW / SANITIZE
]);
export type AgentClassification = z.infer<typeof AgentClassification>;

/**
 * Decision types emitted by agents
 */
export const DecisionType = z.enum([
  'prompt_injection_detection',
  'secret_detection',
  'pii_detection',
  'toxicity_detection',
  'jailbreak_detection',
  'code_injection_detection',
  'input_validation',
  'output_validation',
  'data_redaction',
  'safety_boundary_enforcement',
  'content_moderation',
  'model_abuse_detection',
  'credential_exposure_detection',
]);
export type DecisionType = z.infer<typeof DecisionType>;

/**
 * Severity levels for detected threats
 */
export const Severity = z.enum(['none', 'low', 'medium', 'high', 'critical']);
export type Severity = z.infer<typeof Severity>;

/**
 * Enforcement actions for ENFORCEMENT class agents
 */
export const EnforcementAction = z.enum([
  'ALLOW',      // Allow content to pass
  'BLOCK',      // Block content entirely
  'SANITIZE',   // Sanitize/redact content and allow
  'AUDIT',      // Allow but flag for audit
  'CHALLENGE',  // Require additional verification
]);
export type EnforcementAction = z.infer<typeof EnforcementAction>;

// =============================================================================
// AGENT IDENTITY
// =============================================================================

/**
 * Unique agent identifier with semantic versioning
 */
export const AgentIdentity = z.object({
  /** Unique agent ID (e.g., "prompt-injection-detection-agent") */
  agent_id: z.string().regex(/^[a-z][a-z0-9-]*[a-z0-9]$/),
  /** Semantic version (e.g., "1.0.0") */
  agent_version: z.string().regex(/^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$/),
  /** Agent classification */
  classification: AgentClassification,
  /** Decision type this agent emits */
  decision_type: DecisionType,
});
export type AgentIdentity = z.infer<typeof AgentIdentity>;

// =============================================================================
// COMMON OUTPUT SCHEMAS (defined early for reuse)
// =============================================================================

/**
 * Detected entity with location and confidence
 */
export const DetectedEntity = z.object({
  /** Entity type (e.g., "prompt_injection", "jailbreak_attempt") */
  entity_type: z.string(),
  /** Detection category */
  category: z.string(),
  /** Start position in content */
  start: z.number().int().min(0),
  /** End position in content */
  end: z.number().int().min(0),
  /** Detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** Pattern that matched (for audit purposes) */
  pattern_id: z.string().optional(),
  /** Severity of this specific entity */
  severity: Severity,
});
export type DetectedEntity = z.infer<typeof DetectedEntity>;

/**
 * Risk factor contributing to overall risk score
 */
export const RiskFactor = z.object({
  /** Factor identifier */
  factor_id: z.string(),
  /** Category of risk */
  category: z.string(),
  /** Human-readable description */
  description: z.string(),
  /** Severity level */
  severity: Severity,
  /** Contribution to overall risk score (0.0 - 1.0) */
  score_contribution: z.number().min(0).max(1),
  /** Confidence in this factor (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
});
export type RiskFactor = z.infer<typeof RiskFactor>;

// =============================================================================
// INPUT SCHEMAS
// =============================================================================

/**
 * Policy reference for constraint application
 */
export const PolicyReference = z.object({
  /** Policy ID */
  policy_id: z.string(),
  /** Policy version */
  policy_version: z.string().optional(),
  /** Policy rule IDs that were matched */
  rule_ids: z.array(z.string()).optional(),
});
export type PolicyReference = z.infer<typeof PolicyReference>;

/**
 * Invocation context provided at runtime
 */
export const InvocationContext = z.object({
  /** Unique execution reference for tracing */
  execution_ref: z.string().uuid(),
  /** Timestamp of invocation (UTC ISO 8601) */
  timestamp: z.string().datetime(),
  /** Source of the content (e.g., "user_input", "model_output", "tool_call") */
  content_source: z.enum(['user_input', 'model_output', 'tool_call', 'system']),
  /** Caller identifier */
  caller_id: z.string().optional(),
  /** Session identifier for correlation */
  session_id: z.string().optional(),
  /** Active policy references */
  policies: z.array(PolicyReference).optional(),
  /** Additional context metadata */
  metadata: z.record(z.string(), z.unknown()).optional(),
  /** Execution ID for the Agentics execution tree */
  execution_id: z.string().uuid().optional(),
  /** Parent span ID from the calling Core - required for external invocations */
  parent_span_id: z.string().min(1).optional(),
});
export type InvocationContext = z.infer<typeof InvocationContext>;

/**
 * Base input schema for all detection agents
 */
export const DetectionAgentInput = z.object({
  /** Content to analyze */
  content: z.string(),
  /** Invocation context */
  context: InvocationContext,
  /** Optional configuration overrides */
  config_overrides: z.record(z.string(), z.unknown()).optional(),
});
export type DetectionAgentInput = z.infer<typeof DetectionAgentInput>;

/**
 * Prompt Injection Detection Agent specific input
 */
export const PromptInjectionDetectionInput = DetectionAgentInput.extend({
  /** Optional system prompt for context (will NOT be persisted) */
  system_prompt_hash: z.string().optional(),
  /** Detection sensitivity: higher = more sensitive, more false positives */
  sensitivity: z.number().min(0).max(1).default(0.5),
  /** Categories to detect */
  detect_categories: z.array(z.enum([
    'instruction_override',
    'role_manipulation',
    'system_prompt_attack',
    'jailbreak',
    'delimiter_injection',
    'encoding_attack',
    'context_manipulation',
  ])).optional(),
});
export type PromptInjectionDetectionInput = z.infer<typeof PromptInjectionDetectionInput>;

// =============================================================================
// TOXICITY DETECTION AGENT SCHEMAS (DETECTION_ONLY)
// =============================================================================

/**
 * Toxicity categories that can be detected
 */
export const ToxicityCategory = z.enum([
  'toxic',
  'severe_toxic',
  'obscene',
  'threat',
  'insult',
  'identity_hate',
]);
export type ToxicityCategory = z.infer<typeof ToxicityCategory>;

/**
 * Toxicity Detection Agent specific input
 *
 * Classification: DETECTION_ONLY
 * This agent ONLY detects toxicity, it does NOT redact or modify content.
 */
export const ToxicityDetectionInput = DetectionAgentInput.extend({
  /** Detection sensitivity: higher = more sensitive, more false positives */
  sensitivity: z.number().min(0).max(1).default(0.5),
  /** Detection threshold: minimum score to flag as toxic */
  threshold: z.number().min(0).max(1).default(0.7),
  /** Toxicity categories to detect (optional, defaults to all) */
  detect_categories: z.array(ToxicityCategory).optional(),
});
export type ToxicityDetectionInput = z.infer<typeof ToxicityDetectionInput>;

/**
 * Toxicity-specific detected entity
 * Note: Raw toxic text is NEVER included in output
 */
export const ToxicityDetectedEntity = z.object({
  /** Toxicity category detected */
  toxicity_category: ToxicityCategory,
  /** Detection category (same as toxicity_category for Toxicity agent) */
  category: z.string(),
  /** Start position in content (for caller reference only) */
  start: z.number().int().min(0),
  /** End position in content (for caller reference only) */
  end: z.number().int().min(0),
  /** Detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** Pattern that matched (pattern ID, not the actual pattern) */
  pattern_id: z.string().optional(),
  /** Severity of this toxicity type */
  severity: Severity,
  /** Additional indicators contributing to this detection */
  indicator_count: z.number().int().min(1).optional(),
});
export type ToxicityDetectedEntity = z.infer<typeof ToxicityDetectedEntity>;

/**
 * Toxicity Detection result output (DETECTION_ONLY - no redacted content)
 */
export const ToxicityDetectionResult = z.object({
  /** Whether toxicity was detected */
  toxicity_detected: z.boolean(),
  /** Overall risk score (0.0 - 1.0) */
  risk_score: z.number().min(0).max(1),
  /** Overall severity */
  severity: Severity,
  /** Overall detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** List of detected toxicity entities (positions only, NO raw values) */
  entities: z.array(ToxicityDetectedEntity),
  /** Risk factors contributing to the score */
  risk_factors: z.array(RiskFactor),
  /** Number of patterns matched */
  pattern_match_count: z.number().int().min(0),
  /** Categories detected (e.g., ["insult", "threat"]) */
  detected_categories: z.array(ToxicityCategory),
  /** Count by toxicity category: { insult: 2, threat: 1 } */
  category_counts: z.record(z.string(), z.number()),
});
export type ToxicityDetectionResult = z.infer<typeof ToxicityDetectionResult>;

/**
 * Toxicity Detection Agent output with execution metadata
 */
export const ToxicityDetectionAgentOutput = z.object({
  /** Agent identity */
  agent: AgentIdentity,
  /** Detection result */
  result: ToxicityDetectionResult,
  /** Execution duration in milliseconds */
  duration_ms: z.number().min(0),
  /** Whether this is a cached result */
  cached: z.boolean().default(false),
});
export type ToxicityDetectionAgentOutput = z.infer<typeof ToxicityDetectionAgentOutput>;

/**
 * Toxicity Detection DecisionEvent for persistence to ruvector-service
 *
 * CRITICAL: This is the ONLY data structure that gets persisted.
 * Raw toxic content MUST NEVER appear in this schema.
 */
export const ToxicityDetectionDecisionEvent = z.object({
  /** Agent ID */
  agent_id: z.literal('toxicity-detection-agent'),
  /** Agent version */
  agent_version: z.string(),
  /** Type of decision made */
  decision_type: z.literal('toxicity_detection'),
  /** SHA-256 hash of the input content (NOT the content itself) */
  inputs_hash: z.string().regex(/^[a-f0-9]{64}$/),
  /** Detection outputs (sanitized - no raw content, no toxic text) */
  outputs: z.object({
    toxicity_detected: z.boolean(),
    risk_score: z.number(),
    severity: Severity,
    confidence: z.number(),
    pattern_match_count: z.number(),
    detected_categories: z.array(z.string()),
    entity_count: z.number(),
    /** Count by toxicity category (e.g., { insult: 2, threat: 1 }) */
    category_counts: z.record(z.string(), z.number()),
  }),
  /** Overall detection confidence */
  confidence: z.number().min(0).max(1),
  /** Policy references that were applied */
  constraints_applied: z.array(PolicyReference),
  /** Unique execution reference for tracing */
  execution_ref: z.string().uuid(),
  /** UTC timestamp */
  timestamp: z.string().datetime(),
  /** Execution duration in milliseconds */
  duration_ms: z.number(),
  /** Telemetry metadata (no toxic content) */
  telemetry: z.object({
    content_length: z.number().int(),
    content_source: z.string(),
    session_id: z.string().optional(),
    caller_id: z.string().optional(),
    threshold_used: z.number().optional(),
    categories_checked: z.array(z.string()).optional(),
  }).optional(),
});
export type ToxicityDetectionDecisionEvent = z.infer<typeof ToxicityDetectionDecisionEvent>;

// =============================================================================
// SECRET TYPE CATEGORIES (defined before use)
// =============================================================================

/**
 * Secret type categories for detection
 */
export const SecretTypeCategory = z.enum([
  'aws_credentials',
  'github_token',
  'stripe_key',
  'openai_key',
  'anthropic_key',
  'slack_token',
  'google_api_key',
  'private_key',
  'jwt_token',
  'database_url',
  'generic_api_key',
  'generic_secret',
  'password',
  'connection_string',
]);
export type SecretTypeCategory = z.infer<typeof SecretTypeCategory>;

/**
 * Secrets Leakage Detection Agent specific input
 */
export const SecretsLeakageDetectionInput = DetectionAgentInput.extend({
  /** Detection sensitivity: higher = more sensitive, more false positives */
  sensitivity: z.number().min(0).max(1).default(0.5),
  /** Categories of secrets to detect (optional, defaults to all) */
  detect_categories: z.array(SecretTypeCategory).optional(),
  /** Whether to include entropy-based detection (slower but catches generic secrets) */
  entropy_detection: z.boolean().default(true),
  /** Minimum entropy threshold for generic secret detection (0.0 - 8.0) */
  entropy_threshold: z.number().min(0).max(8).default(4.5),
  /** Custom patterns to detect (pattern_id -> regex as string) */
  custom_patterns: z.record(z.string(), z.string()).optional(),
});
export type SecretsLeakageDetectionInput = z.infer<typeof SecretsLeakageDetectionInput>;

/**
 * Detected secret entity with type classification
 */
export const DetectedSecretEntity = DetectedEntity.extend({
  /** Specific type of secret detected */
  secret_type: SecretTypeCategory,
  /** Whether detected via entropy analysis */
  entropy_based: z.boolean().default(false),
  /** Entropy value if entropy-based detection */
  entropy_value: z.number().optional(),
  /** Redacted preview (first 4, last 4 chars with **** in middle) */
  redacted_preview: z.string().optional(),
});
export type DetectedSecretEntity = z.infer<typeof DetectedSecretEntity>;

// =============================================================================
// PII DETECTION AGENT SCHEMAS
// =============================================================================

/**
 * PII types that can be detected
 */
export const PIIType = z.enum([
  'email',
  'phone',
  'ssn',
  'credit_card',
  'ip_address',
  'passport',
  'drivers_license',
  'date_of_birth',
  'address',
  'name',
]);
export type PIIType = z.infer<typeof PIIType>;

/**
 * Supported countries for PII format detection
 */
export const PIICountry = z.enum(['US', 'UK', 'CA', 'AU', 'EU']);
export type PIICountry = z.infer<typeof PIICountry>;

/**
 * PII Detection Agent specific input
 */
export const PIIDetectionInput = DetectionAgentInput.extend({
  /** Detection sensitivity: higher = more sensitive, more false positives */
  sensitivity: z.number().min(0).max(1).default(0.5),
  /** PII types to detect (optional, defaults to all) */
  detect_types: z.array(PIIType).optional(),
  /** Country-specific formats to detect (optional) */
  countries: z.array(PIICountry).optional(),
});
export type PIIDetectionInput = z.infer<typeof PIIDetectionInput>;

/**
 * PII-specific detected entity
 */
export const PIIDetectedEntity = z.object({
  /** PII type detected */
  pii_type: PIIType,
  /** Detection category (same as pii_type for PII agent) */
  category: z.string(),
  /** Start position in content (for caller reference only) */
  start: z.number().int().min(0),
  /** End position in content (for caller reference only) */
  end: z.number().int().min(0),
  /** Detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** Pattern that matched (pattern ID, not the actual pattern) */
  pattern_id: z.string().optional(),
  /** Severity of this PII type */
  severity: Severity,
  /** Validation method used (e.g., "luhn", "area_check", "format") */
  validation_method: z.string().optional(),
  /** Whether validation passed */
  validation_passed: z.boolean().optional(),
});
export type PIIDetectedEntity = z.infer<typeof PIIDetectedEntity>;

/**
 * PII Detection result output
 */
export const PIIDetectionResult = z.object({
  /** Whether PII was detected */
  pii_detected: z.boolean(),
  /** Overall risk score (0.0 - 1.0) */
  risk_score: z.number().min(0).max(1),
  /** Overall severity */
  severity: Severity,
  /** Overall detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** List of detected PII entities (positions only, NO raw values) */
  entities: z.array(PIIDetectedEntity),
  /** Risk factors contributing to the score */
  risk_factors: z.array(RiskFactor),
  /** Number of patterns matched */
  pattern_match_count: z.number().int().min(0),
  /** PII types detected (e.g., ["email", "ssn", "credit_card"]) */
  detected_types: z.array(PIIType),
  /** Count by PII type: { email: 2, ssn: 1 } */
  type_counts: z.record(z.string(), z.number()),
});
export type PIIDetectionResult = z.infer<typeof PIIDetectionResult>;

/**
 * PII Detection Agent output with execution metadata
 */
export const PIIDetectionAgentOutput = z.object({
  /** Agent identity */
  agent: AgentIdentity,
  /** Detection result */
  result: PIIDetectionResult,
  /** Execution duration in milliseconds */
  duration_ms: z.number().min(0),
  /** Whether this is a cached result */
  cached: z.boolean().default(false),
});
export type PIIDetectionAgentOutput = z.infer<typeof PIIDetectionAgentOutput>;

/**
 * PII Detection DecisionEvent for persistence to ruvector-service
 */
export const PIIDetectionDecisionEvent = z.object({
  /** Agent ID */
  agent_id: z.literal('pii-detection-agent'),
  /** Agent version */
  agent_version: z.string(),
  /** Type of decision made */
  decision_type: z.literal('pii_detection'),
  /** SHA-256 hash of the input content (NOT the content itself) */
  inputs_hash: z.string().regex(/^[a-f0-9]{64}$/),
  /** Detection outputs (sanitized - no raw content, no PII values) */
  outputs: z.object({
    pii_detected: z.boolean(),
    risk_score: z.number(),
    severity: Severity,
    confidence: z.number(),
    pattern_match_count: z.number(),
    detected_types: z.array(z.string()),
    entity_count: z.number(),
    /** Count by PII type (e.g., { email: 2, ssn: 1 }) */
    type_counts: z.record(z.string(), z.number()),
  }),
  /** Overall detection confidence */
  confidence: z.number().min(0).max(1),
  /** Policy references that were applied */
  constraints_applied: z.array(PolicyReference),
  /** Unique execution reference for tracing */
  execution_ref: z.string().uuid(),
  /** UTC timestamp */
  timestamp: z.string().datetime(),
  /** Execution duration in milliseconds */
  duration_ms: z.number(),
  /** Telemetry metadata (no PII) */
  telemetry: z.object({
    content_length: z.number().int(),
    content_source: z.string(),
    session_id: z.string().optional(),
    caller_id: z.string().optional(),
    countries_checked: z.array(z.string()).optional(),
    types_checked: z.array(z.string()).optional(),
  }).optional(),
});
export type PIIDetectionDecisionEvent = z.infer<typeof PIIDetectionDecisionEvent>;

// =============================================================================
// DATA REDACTION AGENT SCHEMAS
// =============================================================================

/**
 * PII type categories for detection and redaction
 */
export const PIITypeCategory = z.enum([
  'email',
  'phone_number',
  'ssn',
  'credit_card',
  'ip_address',
  'passport',
  'drivers_license',
  'date_of_birth',
  'address',
  'name',
  'bank_account',
  'national_id',
]);
export type PIITypeCategory = z.infer<typeof PIITypeCategory>;

/**
 * Redaction strategy determines how sensitive data is replaced
 */
export const RedactionStrategy = z.enum([
  'mask',           // Replace with [TYPE] placeholder
  'hash',           // Replace with SHA-256 hash (deterministic)
  'pseudonymize',   // Replace with consistent fake data
  'remove',         // Remove entirely
  'partial_mask',   // Keep first/last N chars, mask middle
]);
export type RedactionStrategy = z.infer<typeof RedactionStrategy>;

/**
 * Data Redaction Agent specific input
 */
export const DataRedactionAgentInput = DetectionAgentInput.extend({
  /** Detection sensitivity: higher = more sensitive, more false positives */
  sensitivity: z.number().min(0).max(1).default(0.7),
  /** Redaction strategy to apply */
  redaction_strategy: RedactionStrategy.default('mask'),
  /** PII types to detect and redact (defaults to all) */
  pii_types: z.array(PIITypeCategory).optional(),
  /** Secret types to detect and redact (defaults to all) */
  secret_types: z.array(SecretTypeCategory).optional(),
  /** Whether to detect PII */
  detect_pii: z.boolean().default(true),
  /** Whether to detect secrets */
  detect_secrets: z.boolean().default(true),
  /** Whether to detect credentials in plaintext */
  detect_credentials: z.boolean().default(true),
  /** Minimum confidence threshold for redaction (0.0 - 1.0) */
  min_confidence_threshold: z.number().min(0).max(1).default(0.8),
  /** Whether to return redacted content in output */
  return_redacted_content: z.boolean().default(true),
  /** Custom redaction placeholder (e.g., "[REDACTED]" or "***") */
  custom_placeholder: z.string().max(50).optional(),
  /** Number of characters to preserve at start/end for partial_mask strategy */
  partial_mask_chars: z.number().int().min(0).max(10).default(4),
});
export type DataRedactionAgentInput = z.infer<typeof DataRedactionAgentInput>;

/**
 * Redacted entity with redaction metadata
 */
export const RedactedEntity = z.object({
  /** Entity type (e.g., "email", "ssn", "api_key") */
  entity_type: z.string(),
  /** Detection category ("pii", "secret", "credential") */
  category: z.enum(['pii', 'secret', 'credential']),
  /** Start position in ORIGINAL content */
  original_start: z.number().int().min(0),
  /** End position in ORIGINAL content */
  original_end: z.number().int().min(0),
  /** Start position in REDACTED content */
  redacted_start: z.number().int().min(0),
  /** End position in REDACTED content */
  redacted_end: z.number().int().min(0),
  /** Detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** Severity of this entity */
  severity: Severity,
  /** Pattern that matched (for audit purposes) */
  pattern_id: z.string().optional(),
  /** Redaction strategy applied */
  strategy_applied: RedactionStrategy,
  /** Length of original content (NOT the content itself) */
  original_length: z.number().int().min(0),
  /** The redacted placeholder text used */
  redacted_placeholder: z.string(),
});
export type RedactedEntity = z.infer<typeof RedactedEntity>;

/**
 * Data Redaction result output
 */
export const DataRedactionResult = z.object({
  /** Whether sensitive data was detected and redacted */
  data_redacted: z.boolean(),
  /** Number of redactions performed */
  redaction_count: z.number().int().min(0),
  /** Overall risk score of original content (0.0 - 1.0) */
  original_risk_score: z.number().min(0).max(1),
  /** Overall severity */
  severity: Severity,
  /** Overall detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** List of redacted entities (NO raw content, only metadata) */
  redacted_entities: z.array(RedactedEntity),
  /** Redacted (sanitized) content - safe to expose */
  redacted_content: z.string().optional(),
  /** Categories of sensitive data detected */
  detected_categories: z.array(z.string()),
  /** Count by category: { pii: 5, secret: 2, credential: 1 } */
  category_counts: z.record(z.string(), z.number()),
  /** Count by severity: { critical: 2, high: 3, medium: 1 } */
  severity_counts: z.record(z.string(), z.number()),
});
export type DataRedactionResult = z.infer<typeof DataRedactionResult>;

/**
 * Data Redaction Agent output with execution metadata
 */
export const DataRedactionAgentOutput = z.object({
  /** Agent identity */
  agent: AgentIdentity,
  /** Redaction result */
  result: DataRedactionResult,
  /** Execution duration in milliseconds */
  duration_ms: z.number().min(0),
  /** Whether this is a cached result */
  cached: z.boolean().default(false),
});
export type DataRedactionAgentOutput = z.infer<typeof DataRedactionAgentOutput>;

/**
 * Data Redaction DecisionEvent for persistence to ruvector-service
 */
export const DataRedactionDecisionEvent = z.object({
  /** Agent ID */
  agent_id: z.literal('data-redaction-agent'),
  /** Agent version */
  agent_version: z.string(),
  /** Type of decision made */
  decision_type: z.literal('data_redaction'),
  /** SHA-256 hash of the ORIGINAL input content (NOT the content itself) */
  inputs_hash: z.string().regex(/^[a-f0-9]{64}$/),
  /** SHA-256 hash of the REDACTED output content */
  outputs_hash: z.string().regex(/^[a-f0-9]{64}$/),
  /** Redaction outputs (sanitized - no raw content) */
  outputs: z.object({
    data_redacted: z.boolean(),
    redaction_count: z.number(),
    original_risk_score: z.number(),
    severity: Severity,
    confidence: z.number(),
    detected_categories: z.array(z.string()),
    category_counts: z.record(z.string(), z.number()),
    severity_counts: z.record(z.string(), z.number()),
    /** Count of entities by type (e.g., { email: 2, ssn: 1 }) - NO actual values */
    entity_type_counts: z.record(z.string(), z.number()),
  }),
  /** Overall detection confidence */
  confidence: z.number().min(0).max(1),
  /** Policy references that were applied */
  constraints_applied: z.array(PolicyReference),
  /** Unique execution reference for tracing */
  execution_ref: z.string().uuid(),
  /** UTC timestamp */
  timestamp: z.string().datetime(),
  /** Execution duration in milliseconds */
  duration_ms: z.number(),
  /** Telemetry metadata (no PII) */
  telemetry: z.object({
    original_content_length: z.number().int(),
    redacted_content_length: z.number().int(),
    content_source: z.string(),
    session_id: z.string().optional(),
    caller_id: z.string().optional(),
    redaction_strategy: RedactionStrategy,
  }).optional(),
});
export type DataRedactionDecisionEvent = z.infer<typeof DataRedactionDecisionEvent>;

// =============================================================================
// DETECTION RESULT SCHEMAS
// =============================================================================

/**
 * Detection result output
 */
export const DetectionResult = z.object({
  /** Whether threats were detected */
  threats_detected: z.boolean(),
  /** Overall risk score (0.0 - 1.0) */
  risk_score: z.number().min(0).max(1),
  /** Overall severity */
  severity: Severity,
  /** Overall detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** List of detected entities (positions redacted for persistence) */
  entities: z.array(DetectedEntity),
  /** Risk factors contributing to the score */
  risk_factors: z.array(RiskFactor),
  /** Number of patterns matched */
  pattern_match_count: z.number().int().min(0),
  /** Categories of threats detected */
  detected_categories: z.array(z.string()),
});
export type DetectionResult = z.infer<typeof DetectionResult>;

/**
 * Agent output with execution metadata
 */
export const AgentOutput = z.object({
  /** Agent identity */
  agent: AgentIdentity,
  /** Detection result */
  result: DetectionResult,
  /** Execution duration in milliseconds */
  duration_ms: z.number().min(0),
  /** Whether this is a cached result */
  cached: z.boolean().default(false),
});
export type AgentOutput = z.infer<typeof AgentOutput>;

// =============================================================================
// DECISION EVENT (for ruvector-service persistence)
// =============================================================================

/**
 * DecisionEvent schema for persistence to ruvector-service
 *
 * CRITICAL: This is the ONLY data structure that gets persisted.
 * Raw content, PII, secrets MUST NOT appear in this schema.
 */
export const DecisionEvent = z.object({
  /** Agent ID */
  agent_id: z.string(),
  /** Agent version */
  agent_version: z.string(),
  /** Type of decision made */
  decision_type: DecisionType,
  /** SHA-256 hash of the input content (NOT the content itself) */
  inputs_hash: z.string().regex(/^[a-f0-9]{64}$/),
  /** Detection outputs (sanitized - no raw content) */
  outputs: z.object({
    threats_detected: z.boolean(),
    risk_score: z.number(),
    severity: Severity,
    confidence: z.number(),
    pattern_match_count: z.number(),
    detected_categories: z.array(z.string()),
    entity_count: z.number(),
  }),
  /** Overall detection confidence */
  confidence: z.number().min(0).max(1),
  /** Policy references that were applied */
  constraints_applied: z.array(PolicyReference),
  /** Unique execution reference for tracing */
  execution_ref: z.string().uuid(),
  /** UTC timestamp */
  timestamp: z.string().datetime(),
  /** Execution duration in milliseconds */
  duration_ms: z.number(),
  /** Telemetry metadata (no PII) */
  telemetry: z.object({
    content_length: z.number().int(),
    content_source: z.string(),
    session_id: z.string().optional(),
    caller_id: z.string().optional(),
  }).optional(),
});
export type DecisionEvent = z.infer<typeof DecisionEvent>;

// =============================================================================
// SAFETY BOUNDARY AGENT SCHEMAS
// =============================================================================

/**
 * Safety boundary categories for enforcement
 */
export const SafetyBoundaryCategory = z.enum([
  'harmful_content',
  'explicit_content',
  'hate_speech',
  'violence',
  'self_harm',
  'illegal_activity',
  'dangerous_instructions',
  'deceptive_content',
  'privacy_violation',
  'intellectual_property',
]);
export type SafetyBoundaryCategory = z.infer<typeof SafetyBoundaryCategory>;

/**
 * Safety policy rule for enforcement
 */
export const SafetyPolicyRule = z.object({
  /** Rule ID */
  rule_id: z.string(),
  /** Category this rule enforces */
  category: SafetyBoundaryCategory,
  /** Rule description */
  description: z.string(),
  /** Action to take when rule matches */
  action: EnforcementAction,
  /** Confidence threshold for enforcement (0.0 - 1.0) */
  threshold: z.number().min(0).max(1).default(0.8),
  /** Whether this rule is enabled */
  enabled: z.boolean().default(true),
  /** Priority (lower = higher priority) */
  priority: z.number().int().min(0).default(100),
});
export type SafetyPolicyRule = z.infer<typeof SafetyPolicyRule>;

/**
 * Safety Boundary Agent specific input
 */
export const SafetyBoundaryAgentInput = DetectionAgentInput.extend({
  /** Enforcement sensitivity: higher = more strict, more blocks */
  sensitivity: z.number().min(0).max(1).default(0.7),
  /** Categories to enforce (defaults to all) */
  enforce_categories: z.array(SafetyBoundaryCategory).optional(),
  /** Default action when boundary is violated */
  default_action: EnforcementAction.default('BLOCK'),
  /** Custom policy rules (overrides default enforcement) */
  policy_rules: z.array(SafetyPolicyRule).optional(),
  /** Allow explicit content if user has verified age */
  allow_explicit_with_age_verification: z.boolean().default(false),
  /** Minimum confidence required for enforcement action */
  min_enforcement_confidence: z.number().min(0).max(1).default(0.8),
});
export type SafetyBoundaryAgentInput = z.infer<typeof SafetyBoundaryAgentInput>;

/**
 * Safety boundary violation entity
 */
export const SafetyBoundaryViolation = z.object({
  /** Violation ID */
  violation_id: z.string(),
  /** Category violated */
  category: SafetyBoundaryCategory,
  /** Start position in content */
  start: z.number().int().min(0),
  /** End position in content */
  end: z.number().int().min(0),
  /** Detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** Severity of the violation */
  severity: Severity,
  /** Pattern that matched (for audit purposes) */
  pattern_id: z.string().optional(),
  /** Rule that was triggered (if policy-based) */
  triggered_rule_id: z.string().optional(),
  /** Human-readable description of the violation */
  description: z.string(),
});
export type SafetyBoundaryViolation = z.infer<typeof SafetyBoundaryViolation>;

/**
 * Safety Boundary enforcement result output
 */
export const SafetyBoundaryResult = z.object({
  /** Whether content was allowed to pass */
  allowed: z.boolean(),
  /** Enforcement action taken */
  action: EnforcementAction,
  /** Whether any safety boundaries were violated */
  violations_detected: z.boolean(),
  /** Overall risk score (0.0 - 1.0) */
  risk_score: z.number().min(0).max(1),
  /** Overall severity */
  severity: Severity,
  /** Overall detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** List of violations detected (NO raw content) */
  violations: z.array(SafetyBoundaryViolation),
  /** Categories that were violated */
  violated_categories: z.array(SafetyBoundaryCategory),
  /** Number of patterns matched */
  pattern_match_count: z.number().int().min(0),
  /** Count by category: { harmful_content: 2, violence: 1 } */
  category_counts: z.record(z.string(), z.number()),
  /** Reason for the enforcement decision */
  decision_reason: z.string(),
  /** Risk factors contributing to the score */
  risk_factors: z.array(RiskFactor),
});
export type SafetyBoundaryResult = z.infer<typeof SafetyBoundaryResult>;

/**
 * Safety Boundary Agent output with execution metadata
 */
export const SafetyBoundaryAgentOutput = z.object({
  /** Agent identity */
  agent: AgentIdentity,
  /** Enforcement result */
  result: SafetyBoundaryResult,
  /** Execution duration in milliseconds */
  duration_ms: z.number().min(0),
  /** Whether this is a cached result */
  cached: z.boolean().default(false),
});
export type SafetyBoundaryAgentOutput = z.infer<typeof SafetyBoundaryAgentOutput>;

/**
 * Safety Boundary DecisionEvent for persistence to ruvector-service
 */
export const SafetyBoundaryDecisionEvent = z.object({
  /** Agent ID */
  agent_id: z.literal('safety-boundary-agent'),
  /** Agent version */
  agent_version: z.string(),
  /** Type of decision made */
  decision_type: z.literal('safety_boundary_enforcement'),
  /** SHA-256 hash of the input content (NOT the content itself) */
  inputs_hash: z.string().regex(/^[a-f0-9]{64}$/),
  /** Enforcement outputs (sanitized - no raw content) */
  outputs: z.object({
    allowed: z.boolean(),
    action: EnforcementAction,
    violations_detected: z.boolean(),
    risk_score: z.number(),
    severity: Severity,
    confidence: z.number(),
    pattern_match_count: z.number(),
    violation_count: z.number(),
    violated_categories: z.array(z.string()),
    category_counts: z.record(z.string(), z.number()),
    decision_reason: z.string(),
  }),
  /** Overall detection confidence */
  confidence: z.number().min(0).max(1),
  /** Policy references that were applied */
  constraints_applied: z.array(PolicyReference),
  /** Unique execution reference for tracing */
  execution_ref: z.string().uuid(),
  /** UTC timestamp */
  timestamp: z.string().datetime(),
  /** Execution duration in milliseconds */
  duration_ms: z.number(),
  /** Telemetry metadata (no PII) */
  telemetry: z.object({
    content_length: z.number().int(),
    content_source: z.string(),
    session_id: z.string().optional(),
    caller_id: z.string().optional(),
    categories_checked: z.array(z.string()).optional(),
    rules_evaluated: z.number().int().optional(),
  }).optional(),
});
export type SafetyBoundaryDecisionEvent = z.infer<typeof SafetyBoundaryDecisionEvent>;

// =============================================================================
// CONTENT MODERATION AGENT SCHEMAS
// =============================================================================

/**
 * Content moderation categories for enforcement
 */
export const ContentModerationCategory = z.enum([
  'adult_content',
  'violence_graphic',
  'hate_discriminatory',
  'harassment_bullying',
  'spam_misleading',
  'illegal_regulated',
  'self_harm',
  'child_safety',
  'terrorism_extremism',
  'misinformation',
]);
export type ContentModerationCategory = z.infer<typeof ContentModerationCategory>;

/**
 * Content moderation action types
 */
export const ModerationAction = z.enum([
  'ALLOW',        // Content is safe to pass
  'BLOCK',        // Content must be blocked
  'FLAG',         // Content should be flagged for human review
  'WARN',         // Allow but warn user
  'AGE_GATE',     // Require age verification
]);
export type ModerationAction = z.infer<typeof ModerationAction>;

/**
 * Content moderation policy rule
 */
export const ContentModerationRule = z.object({
  /** Rule ID */
  rule_id: z.string(),
  /** Category this rule moderates */
  category: ContentModerationCategory,
  /** Rule description */
  description: z.string(),
  /** Action to take when rule matches */
  action: ModerationAction,
  /** Confidence threshold for enforcement (0.0 - 1.0) */
  threshold: z.number().min(0).max(1).default(0.8),
  /** Whether this rule is enabled */
  enabled: z.boolean().default(true),
  /** Priority (lower = higher priority) */
  priority: z.number().int().min(0).default(100),
});
export type ContentModerationRule = z.infer<typeof ContentModerationRule>;

/**
 * Content Moderation Agent specific input
 */
export const ContentModerationAgentInput = DetectionAgentInput.extend({
  /** Moderation sensitivity: higher = more strict, more blocks */
  sensitivity: z.number().min(0).max(1).default(0.7),
  /** Categories to moderate (defaults to all) */
  moderate_categories: z.array(ContentModerationCategory).optional(),
  /** Default action when content violates policy */
  default_action: ModerationAction.default('BLOCK'),
  /** Custom moderation rules (overrides default enforcement) */
  moderation_rules: z.array(ContentModerationRule).optional(),
  /** Whether content is from a verified adult user */
  user_age_verified: z.boolean().default(false),
  /** Minimum confidence required for moderation action */
  min_moderation_confidence: z.number().min(0).max(1).default(0.8),
  /** Content type for context-aware moderation */
  content_type: z.enum(['text', 'image_description', 'video_description', 'audio_transcript', 'mixed']).default('text'),
  /** Whether to return detailed violation information */
  include_violation_details: z.boolean().default(true),
});
export type ContentModerationAgentInput = z.infer<typeof ContentModerationAgentInput>;

/**
 * Content moderation violation entity
 */
export const ContentModerationViolation = z.object({
  /** Violation ID */
  violation_id: z.string(),
  /** Category violated */
  category: ContentModerationCategory,
  /** Start position in content */
  start: z.number().int().min(0),
  /** End position in content */
  end: z.number().int().min(0),
  /** Detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** Severity of the violation */
  severity: Severity,
  /** Pattern that matched (for audit purposes) */
  pattern_id: z.string().optional(),
  /** Rule that was triggered (if policy-based) */
  triggered_rule_id: z.string().optional(),
  /** Human-readable description of the violation */
  description: z.string(),
  /** Recommended action for this specific violation */
  recommended_action: ModerationAction,
});
export type ContentModerationViolation = z.infer<typeof ContentModerationViolation>;

/**
 * Content Moderation enforcement result output
 */
export const ContentModerationResult = z.object({
  /** Whether content was allowed to pass */
  allowed: z.boolean(),
  /** Moderation action taken */
  action: ModerationAction,
  /** Whether any moderation violations were detected */
  violations_detected: z.boolean(),
  /** Overall risk score (0.0 - 1.0) */
  risk_score: z.number().min(0).max(1),
  /** Overall severity */
  severity: Severity,
  /** Overall detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** List of violations detected (NO raw content) */
  violations: z.array(ContentModerationViolation),
  /** Categories that were violated */
  violated_categories: z.array(ContentModerationCategory),
  /** Number of patterns matched */
  pattern_match_count: z.number().int().min(0),
  /** Count by category: { adult_content: 2, violence_graphic: 1 } */
  category_counts: z.record(z.string(), z.number()),
  /** Reason for the moderation decision */
  decision_reason: z.string(),
  /** Risk factors contributing to the score */
  risk_factors: z.array(RiskFactor),
  /** Whether human review is recommended */
  requires_human_review: z.boolean(),
  /** Suggested content warning if applicable */
  content_warning: z.string().optional(),
});
export type ContentModerationResult = z.infer<typeof ContentModerationResult>;

/**
 * Content Moderation Agent output with execution metadata
 */
export const ContentModerationAgentOutput = z.object({
  /** Agent identity */
  agent: AgentIdentity,
  /** Moderation result */
  result: ContentModerationResult,
  /** Execution duration in milliseconds */
  duration_ms: z.number().min(0),
  /** Whether this is a cached result */
  cached: z.boolean().default(false),
});
export type ContentModerationAgentOutput = z.infer<typeof ContentModerationAgentOutput>;

/**
 * Content Moderation DecisionEvent for persistence to ruvector-service
 *
 * CRITICAL: Raw content MUST NEVER appear in this schema.
 * Only hashes and aggregated metadata are persisted.
 */
export const ContentModerationDecisionEvent = z.object({
  /** Agent ID */
  agent_id: z.literal('content-moderation-agent'),
  /** Agent version */
  agent_version: z.string(),
  /** Type of decision made */
  decision_type: z.literal('content_moderation'),
  /** SHA-256 hash of the input content (NOT the content itself) */
  inputs_hash: z.string().regex(/^[a-f0-9]{64}$/),
  /** Moderation outputs (sanitized - no raw content) */
  outputs: z.object({
    allowed: z.boolean(),
    action: ModerationAction,
    violations_detected: z.boolean(),
    risk_score: z.number(),
    severity: Severity,
    confidence: z.number(),
    pattern_match_count: z.number(),
    violation_count: z.number(),
    violated_categories: z.array(z.string()),
    category_counts: z.record(z.string(), z.number()),
    decision_reason: z.string(),
    requires_human_review: z.boolean(),
  }),
  /** Overall detection confidence */
  confidence: z.number().min(0).max(1),
  /** Policy references that were applied */
  constraints_applied: z.array(PolicyReference),
  /** Unique execution reference for tracing */
  execution_ref: z.string().uuid(),
  /** UTC timestamp */
  timestamp: z.string().datetime(),
  /** Execution duration in milliseconds */
  duration_ms: z.number(),
  /** Telemetry metadata (no PII or content) */
  telemetry: z.object({
    content_length: z.number().int(),
    content_source: z.string(),
    content_type: z.string().optional(),
    session_id: z.string().optional(),
    caller_id: z.string().optional(),
    categories_checked: z.array(z.string()).optional(),
    rules_evaluated: z.number().int().optional(),
    user_age_verified: z.boolean().optional(),
  }).optional(),
});
export type ContentModerationDecisionEvent = z.infer<typeof ContentModerationDecisionEvent>;

// =============================================================================
// MODEL ABUSE DETECTION AGENT SCHEMAS
// =============================================================================

/**
 * Model abuse pattern categories for detection
 */
export const ModelAbuseCategory = z.enum([
  'unauthorized_access',       // Unauthorized API/model access attempts
  'rate_limit_evasion',        // Attempts to evade rate limits
  'credential_stuffing',       // Automated credential testing
  'model_extraction',          // Attempts to extract model weights/behavior
  'prompt_harvesting',         // Systematic prompt collection
  'training_data_extraction',  // Attempts to extract training data
  'resource_exhaustion',       // Intentional resource overconsumption
  'api_abuse',                 // General API misuse patterns
  'inference_attack',          // Model inference/membership attacks
  'adversarial_input',         // Adversarial examples targeting model behavior
  'fingerprinting',            // Model fingerprinting attempts
  'context_manipulation',      // Manipulating context windows maliciously
]);
export type ModelAbuseCategory = z.infer<typeof ModelAbuseCategory>;

/**
 * Model Abuse Detection Agent specific input
 *
 * Classification: DETECTION_ONLY
 * This agent ONLY detects abuse patterns, it does NOT block or modify requests.
 */
export const ModelAbuseDetectionInput = DetectionAgentInput.extend({
  /** Detection sensitivity: higher = more sensitive, more false positives */
  sensitivity: z.number().min(0).max(1).default(0.5),
  /** Detection threshold: minimum score to flag as abuse */
  threshold: z.number().min(0).max(1).default(0.7),
  /** Abuse categories to detect (optional, defaults to all) */
  detect_categories: z.array(ModelAbuseCategory).optional(),
  /** Request metadata for pattern detection */
  request_metadata: z.object({
    /** Request rate in requests per minute (if available) */
    request_rate: z.number().min(0).optional(),
    /** Client IP hash (for privacy) */
    client_ip_hash: z.string().optional(),
    /** User agent fingerprint hash */
    user_agent_hash: z.string().optional(),
    /** Session request count */
    session_request_count: z.number().int().min(0).optional(),
    /** Token usage in this session */
    session_token_usage: z.number().int().min(0).optional(),
    /** Whether request appears automated */
    appears_automated: z.boolean().optional(),
    /** API endpoint being accessed */
    api_endpoint: z.string().optional(),
    /** Request timestamp for temporal analysis */
    request_timestamp: z.string().datetime().optional(),
  }).optional(),
  /** Historical context for pattern detection */
  historical_context: z.object({
    /** Number of previous requests from same source */
    previous_request_count: z.number().int().min(0).optional(),
    /** Number of previous violations */
    previous_violation_count: z.number().int().min(0).optional(),
    /** Time since first request (seconds) */
    session_duration_seconds: z.number().min(0).optional(),
  }).optional(),
});
export type ModelAbuseDetectionInput = z.infer<typeof ModelAbuseDetectionInput>;

/**
 * Model abuse detected entity
 * Note: Raw content is NEVER included in output
 */
export const ModelAbuseDetectedEntity = z.object({
  /** Abuse category detected */
  abuse_category: ModelAbuseCategory,
  /** Detection category (same as abuse_category for Model Abuse agent) */
  category: z.string(),
  /** Start position in content (for caller reference only) */
  start: z.number().int().min(0),
  /** End position in content (for caller reference only) */
  end: z.number().int().min(0),
  /** Detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** Pattern that matched (pattern ID, not the actual pattern) */
  pattern_id: z.string().optional(),
  /** Severity of this abuse type */
  severity: Severity,
  /** Additional indicators contributing to this detection */
  indicator_count: z.number().int().min(1).optional(),
  /** Behavioral indicators detected */
  behavioral_indicators: z.array(z.string()).optional(),
});
export type ModelAbuseDetectedEntity = z.infer<typeof ModelAbuseDetectedEntity>;

/**
 * Model Abuse Detection result output (DETECTION_ONLY - no enforcement)
 */
export const ModelAbuseDetectionResult = z.object({
  /** Whether abuse was detected */
  abuse_detected: z.boolean(),
  /** Overall risk score (0.0 - 1.0) */
  risk_score: z.number().min(0).max(1),
  /** Overall severity */
  severity: Severity,
  /** Overall detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** List of detected abuse entities (positions only, NO raw values) */
  entities: z.array(ModelAbuseDetectedEntity),
  /** Risk factors contributing to the score */
  risk_factors: z.array(RiskFactor),
  /** Number of patterns matched */
  pattern_match_count: z.number().int().min(0),
  /** Categories detected (e.g., ["rate_limit_evasion", "api_abuse"]) */
  detected_categories: z.array(ModelAbuseCategory),
  /** Count by abuse category: { rate_limit_evasion: 2, api_abuse: 1 } */
  category_counts: z.record(z.string(), z.number()),
  /** Behavioral analysis summary */
  behavioral_summary: z.object({
    /** Whether request patterns appear automated */
    appears_automated: z.boolean(),
    /** Whether rate appears abnormal */
    abnormal_rate: z.boolean(),
    /** Whether pattern matches known abuse signatures */
    matches_abuse_signature: z.boolean(),
    /** Number of behavioral red flags */
    red_flag_count: z.number().int().min(0),
  }).optional(),
});
export type ModelAbuseDetectionResult = z.infer<typeof ModelAbuseDetectionResult>;

/**
 * Model Abuse Detection Agent output with execution metadata
 */
export const ModelAbuseDetectionAgentOutput = z.object({
  /** Agent identity */
  agent: AgentIdentity,
  /** Detection result */
  result: ModelAbuseDetectionResult,
  /** Execution duration in milliseconds */
  duration_ms: z.number().min(0),
  /** Whether this is a cached result */
  cached: z.boolean().default(false),
});
export type ModelAbuseDetectionAgentOutput = z.infer<typeof ModelAbuseDetectionAgentOutput>;

/**
 * Model Abuse Detection DecisionEvent for persistence to ruvector-service
 *
 * CRITICAL: This is the ONLY data structure that gets persisted.
 * Raw content and request data MUST NEVER appear in this schema.
 */
export const ModelAbuseDetectionDecisionEvent = z.object({
  /** Agent ID */
  agent_id: z.literal('model-abuse-detection-agent'),
  /** Agent version */
  agent_version: z.string(),
  /** Type of decision made */
  decision_type: z.literal('model_abuse_detection'),
  /** SHA-256 hash of the input content (NOT the content itself) */
  inputs_hash: z.string().regex(/^[a-f0-9]{64}$/),
  /** Detection outputs (sanitized - no raw content, no request data) */
  outputs: z.object({
    abuse_detected: z.boolean(),
    risk_score: z.number(),
    severity: Severity,
    confidence: z.number(),
    pattern_match_count: z.number(),
    detected_categories: z.array(z.string()),
    entity_count: z.number(),
    /** Count by abuse category (e.g., { rate_limit_evasion: 2, api_abuse: 1 }) */
    category_counts: z.record(z.string(), z.number()),
    /** Behavioral summary (no sensitive data) */
    behavioral_summary: z.object({
      appears_automated: z.boolean(),
      abnormal_rate: z.boolean(),
      matches_abuse_signature: z.boolean(),
      red_flag_count: z.number(),
    }).optional(),
  }),
  /** Overall detection confidence */
  confidence: z.number().min(0).max(1),
  /** Policy references that were applied */
  constraints_applied: z.array(PolicyReference),
  /** Unique execution reference for tracing */
  execution_ref: z.string().uuid(),
  /** UTC timestamp */
  timestamp: z.string().datetime(),
  /** Execution duration in milliseconds */
  duration_ms: z.number(),
  /** Telemetry metadata (no raw content or PII) */
  telemetry: z.object({
    content_length: z.number().int(),
    content_source: z.string(),
    session_id: z.string().optional(),
    caller_id: z.string().optional(),
    threshold_used: z.number().optional(),
    categories_checked: z.array(z.string()).optional(),
    /** Anonymized request metadata */
    request_rate_bucket: z.string().optional(),  // "low", "medium", "high", "extreme"
    session_request_bucket: z.string().optional(),  // "few", "some", "many", "excessive"
  }).optional(),
});
export type ModelAbuseDetectionDecisionEvent = z.infer<typeof ModelAbuseDetectionDecisionEvent>;

// =============================================================================
// CREDENTIAL EXPOSURE DETECTION AGENT SCHEMAS
// =============================================================================

/**
 * Credential type categories for detection
 *
 * This categorizes different types of authentication credentials that
 * may be accidentally exposed in prompts, outputs, or tool calls.
 */
export const CredentialType = z.enum([
  'username_password',        // Username/password combinations
  'basic_auth',               // Basic authentication headers/strings
  'bearer_token',             // Bearer tokens in headers or content
  'api_credential',           // API username/password or key pairs
  'database_credential',      // Database username/password combinations
  'ssh_credential',           // SSH usernames with keys or passwords
  'ftp_credential',           // FTP/SFTP credentials
  'smtp_credential',          // SMTP/email server credentials
  'ldap_credential',          // LDAP/AD credentials
  'oauth_credential',         // OAuth client ID/secret pairs
  'service_account',          // Service account credentials
  'admin_credential',         // Admin/root credentials
  'hardcoded_credential',     // Hardcoded credentials in code/config
  'environment_credential',   // Credentials from environment variable patterns
  'generic_credential',       // Generic username/password patterns
]);
export type CredentialType = z.infer<typeof CredentialType>;

/**
 * Credential Exposure Detection Agent specific input
 *
 * Classification: DETECTION_ONLY
 * This agent ONLY detects credential exposure, it does NOT redact or modify content.
 *
 * Purpose: Detect accidental exposure of usernames, passwords, access keys,
 * or authentication artifacts in LLM inputs/outputs.
 */
export const CredentialExposureDetectionInput = DetectionAgentInput.extend({
  /** Detection sensitivity: higher = more sensitive, more false positives */
  sensitivity: z.number().min(0).max(1).default(0.5),
  /** Detection threshold: minimum score to flag as credential exposure */
  threshold: z.number().min(0).max(1).default(0.7),
  /** Credential types to detect (optional, defaults to all) */
  detect_types: z.array(CredentialType).optional(),
  /** Whether to detect password patterns (e.g., password= assignments) */
  detect_password_patterns: z.boolean().default(true),
  /** Whether to detect username patterns (e.g., username= assignments) */
  detect_username_patterns: z.boolean().default(true),
  /** Whether to detect authentication headers (Basic, Bearer, etc.) */
  detect_auth_headers: z.boolean().default(true),
  /** Whether to detect credential pairs (username + password together) */
  detect_credential_pairs: z.boolean().default(true),
  /** Minimum password length to consider (to reduce false positives) */
  min_password_length: z.number().int().min(1).max(100).default(6),
  /** Custom credential patterns to detect (pattern_id -> regex as string) */
  custom_patterns: z.record(z.string(), z.string()).optional(),
});
export type CredentialExposureDetectionInput = z.infer<typeof CredentialExposureDetectionInput>;

/**
 * Credential exposure detected entity
 * Note: Raw credentials (usernames, passwords) are NEVER included in output
 */
export const CredentialExposureDetectedEntity = z.object({
  /** Credential type detected */
  credential_type: CredentialType,
  /** Detection category (same as credential_type for Credential Exposure agent) */
  category: z.string(),
  /** Start position in content (for caller reference only) */
  start: z.number().int().min(0),
  /** End position in content (for caller reference only) */
  end: z.number().int().min(0),
  /** Detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** Pattern that matched (pattern ID, not the actual pattern) */
  pattern_id: z.string().optional(),
  /** Severity of this credential type */
  severity: Severity,
  /** Whether this is a credential pair (username + password together) */
  is_credential_pair: z.boolean().default(false),
  /** Whether username was detected (never the actual username) */
  has_username: z.boolean().default(false),
  /** Whether password/secret was detected (never the actual value) */
  has_password: z.boolean().default(false),
  /** Redacted preview (e.g., "user****" or "pass****") */
  redacted_preview: z.string().optional(),
  /** Additional context about the detection */
  context_hint: z.string().optional(),
});
export type CredentialExposureDetectedEntity = z.infer<typeof CredentialExposureDetectedEntity>;

/**
 * Credential Exposure Detection result output (DETECTION_ONLY - no redacted content)
 */
export const CredentialExposureDetectionResult = z.object({
  /** Whether credential exposure was detected */
  credentials_detected: z.boolean(),
  /** Overall risk score (0.0 - 1.0) */
  risk_score: z.number().min(0).max(1),
  /** Overall severity */
  severity: Severity,
  /** Overall detection confidence (0.0 - 1.0) */
  confidence: z.number().min(0).max(1),
  /** List of detected credential entities (positions only, NO raw values) */
  entities: z.array(CredentialExposureDetectedEntity),
  /** Risk factors contributing to the score */
  risk_factors: z.array(RiskFactor),
  /** Number of patterns matched */
  pattern_match_count: z.number().int().min(0),
  /** Credential types detected (e.g., ["username_password", "api_credential"]) */
  detected_types: z.array(CredentialType),
  /** Count by credential type: { username_password: 2, api_credential: 1 } */
  type_counts: z.record(z.string(), z.number()),
  /** Number of credential pairs detected (username + password together) */
  credential_pair_count: z.number().int().min(0),
  /** Summary of exposure context */
  exposure_summary: z.object({
    /** Number of username exposures */
    username_exposures: z.number().int().min(0),
    /** Number of password exposures */
    password_exposures: z.number().int().min(0),
    /** Number of auth header exposures */
    auth_header_exposures: z.number().int().min(0),
    /** Number of hardcoded credential exposures */
    hardcoded_exposures: z.number().int().min(0),
  }).optional(),
});
export type CredentialExposureDetectionResult = z.infer<typeof CredentialExposureDetectionResult>;

/**
 * Credential Exposure Detection Agent output with execution metadata
 */
export const CredentialExposureDetectionAgentOutput = z.object({
  /** Agent identity */
  agent: AgentIdentity,
  /** Detection result */
  result: CredentialExposureDetectionResult,
  /** Execution duration in milliseconds */
  duration_ms: z.number().min(0),
  /** Whether this is a cached result */
  cached: z.boolean().default(false),
});
export type CredentialExposureDetectionAgentOutput = z.infer<typeof CredentialExposureDetectionAgentOutput>;

/**
 * Credential Exposure Detection DecisionEvent for persistence to ruvector-service
 *
 * CRITICAL: This is the ONLY data structure that gets persisted.
 * Raw credentials (usernames, passwords, tokens) MUST NEVER appear in this schema.
 */
export const CredentialExposureDecisionEvent = z.object({
  /** Agent ID */
  agent_id: z.literal('credential-exposure-detection-agent'),
  /** Agent version */
  agent_version: z.string(),
  /** Type of decision made */
  decision_type: z.literal('credential_exposure_detection'),
  /** SHA-256 hash of the input content (NOT the content itself) */
  inputs_hash: z.string().regex(/^[a-f0-9]{64}$/),
  /** Detection outputs (sanitized - no raw content, no credentials) */
  outputs: z.object({
    credentials_detected: z.boolean(),
    risk_score: z.number(),
    severity: Severity,
    confidence: z.number(),
    pattern_match_count: z.number(),
    detected_types: z.array(z.string()),
    entity_count: z.number(),
    /** Count by credential type (e.g., { username_password: 2, api_credential: 1 }) */
    type_counts: z.record(z.string(), z.number()),
    credential_pair_count: z.number(),
    /** Exposure summary (counts only, no sensitive data) */
    exposure_summary: z.object({
      username_exposures: z.number(),
      password_exposures: z.number(),
      auth_header_exposures: z.number(),
      hardcoded_exposures: z.number(),
    }).optional(),
  }),
  /** Overall detection confidence */
  confidence: z.number().min(0).max(1),
  /** Policy references that were applied */
  constraints_applied: z.array(PolicyReference),
  /** Unique execution reference for tracing */
  execution_ref: z.string().uuid(),
  /** UTC timestamp */
  timestamp: z.string().datetime(),
  /** Execution duration in milliseconds */
  duration_ms: z.number(),
  /** Telemetry metadata (no credentials or PII) */
  telemetry: z.object({
    content_length: z.number().int(),
    content_source: z.string(),
    session_id: z.string().optional(),
    caller_id: z.string().optional(),
    threshold_used: z.number().optional(),
    types_checked: z.array(z.string()).optional(),
    detection_flags: z.object({
      password_patterns: z.boolean(),
      username_patterns: z.boolean(),
      auth_headers: z.boolean(),
      credential_pairs: z.boolean(),
    }).optional(),
  }).optional(),
});
export type CredentialExposureDecisionEvent = z.infer<typeof CredentialExposureDecisionEvent>;

// =============================================================================
// ERROR SCHEMAS
// =============================================================================

/**
 * Error codes for agent failures
 */
export const AgentErrorCode = z.enum([
  'INVALID_INPUT',
  'VALIDATION_FAILED',
  'TIMEOUT',
  'INTERNAL_ERROR',
  'CONFIGURATION_ERROR',
  'PERSISTENCE_ERROR',
]);
export type AgentErrorCode = z.infer<typeof AgentErrorCode>;

/**
 * Agent error response
 */
export const AgentError = z.object({
  /** Error code */
  code: AgentErrorCode,
  /** Human-readable message */
  message: z.string(),
  /** Agent identity */
  agent: AgentIdentity.optional(),
  /** Execution reference for tracing */
  execution_ref: z.string().uuid().optional(),
  /** Timestamp */
  timestamp: z.string().datetime(),
  /** Additional error details (no sensitive data) */
  details: z.record(z.string(), z.unknown()).optional(),
});
export type AgentError = z.infer<typeof AgentError>;

// =============================================================================
// CLI INVOCATION SCHEMAS
// =============================================================================

/**
 * CLI invocation modes
 */
export const CliMode = z.enum(['test', 'simulate', 'inspect']);
export type CliMode = z.infer<typeof CliMode>;

/**
 * CLI invocation request
 */
export const CliInvocation = z.object({
  /** Invocation mode */
  mode: CliMode,
  /** Content to analyze */
  content: z.string(),
  /** Optional configuration */
  config: z.record(z.string(), z.unknown()).optional(),
  /** Output format */
  format: z.enum(['json', 'text', 'table']).default('json'),
  /** Verbose output */
  verbose: z.boolean().default(false),
});
export type CliInvocation = z.infer<typeof CliInvocation>;

// =============================================================================
// EXPORTS
// =============================================================================

export const contracts = {
  // Core enums
  AgentClassification,
  DecisionType,
  Severity,
  EnforcementAction,
  // Agent identity
  AgentIdentity,
  PolicyReference,
  InvocationContext,
  // Detection inputs
  DetectionAgentInput,
  PromptInjectionDetectionInput,
  // Toxicity Detection Agent
  ToxicityCategory,
  ToxicityDetectionInput,
  ToxicityDetectedEntity,
  ToxicityDetectionResult,
  ToxicityDetectionAgentOutput,
  ToxicityDetectionDecisionEvent,
  // Secret Detection
  SecretTypeCategory,
  SecretsLeakageDetectionInput,
  DetectedSecretEntity,
  // PII Detection Agent
  PIIType,
  PIICountry,
  PIIDetectionInput,
  PIIDetectedEntity,
  PIIDetectionResult,
  PIIDetectionAgentOutput,
  PIIDetectionDecisionEvent,
  // Data Redaction Agent
  PIITypeCategory,
  RedactionStrategy,
  DataRedactionAgentInput,
  RedactedEntity,
  DataRedactionResult,
  DataRedactionAgentOutput,
  DataRedactionDecisionEvent,
  // Safety Boundary Agent
  SafetyBoundaryCategory,
  SafetyPolicyRule,
  SafetyBoundaryAgentInput,
  SafetyBoundaryViolation,
  SafetyBoundaryResult,
  SafetyBoundaryAgentOutput,
  SafetyBoundaryDecisionEvent,
  // Content Moderation Agent
  ContentModerationCategory,
  ModerationAction,
  ContentModerationRule,
  ContentModerationAgentInput,
  ContentModerationViolation,
  ContentModerationResult,
  ContentModerationAgentOutput,
  ContentModerationDecisionEvent,
  // Model Abuse Detection Agent
  ModelAbuseCategory,
  ModelAbuseDetectionInput,
  ModelAbuseDetectedEntity,
  ModelAbuseDetectionResult,
  ModelAbuseDetectionAgentOutput,
  ModelAbuseDetectionDecisionEvent,
  // Credential Exposure Detection Agent
  CredentialType,
  CredentialExposureDetectionInput,
  CredentialExposureDetectedEntity,
  CredentialExposureDetectionResult,
  CredentialExposureDetectionAgentOutput,
  CredentialExposureDecisionEvent,
  // Detection outputs
  DetectedEntity,
  RiskFactor,
  DetectionResult,
  AgentOutput,
  DecisionEvent,
  // Errors
  AgentErrorCode,
  AgentError,
  // CLI
  CliMode,
  CliInvocation,
};
