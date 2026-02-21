/**
 * @module patterns
 * @description Model abuse detection patterns for identifying misuse and exploitation
 *
 * These patterns detect various forms of model abuse including:
 * - Rate limit evasion attempts
 * - Model extraction attempts
 * - Training data extraction
 * - Adversarial inputs
 * - API abuse patterns
 */
/**
 * Content-based abuse detection patterns
 */
export const MODEL_ABUSE_PATTERNS = [
    // Model Extraction Attempts
    {
        id: 'model-extraction-weights',
        category: 'model_extraction',
        name: 'Model Weights Extraction',
        pattern: /(?:extract|dump|export|reveal|show|give\s+me)\s+(?:the\s+)?(?:model\s+)?(?:weights|parameters|embeddings|vectors|architecture)/gi,
        severity: 'critical',
        baseConfidence: 0.85,
        description: 'Attempts to extract model weights or parameters',
        behavioralIndicators: ['systematic_prompting', 'technical_terminology'],
    },
    {
        id: 'model-extraction-internals',
        category: 'model_extraction',
        name: 'Model Internals Extraction',
        pattern: /(?:what\s+(?:are|is)\s+your|show\s+me\s+your|reveal\s+your)\s+(?:internal|hidden)\s+(?:layers?|neurons?|activations?|representations?)/gi,
        severity: 'high',
        baseConfidence: 0.75,
        description: 'Attempts to extract internal model representations',
    },
    {
        id: 'model-extraction-config',
        category: 'model_extraction',
        name: 'Model Configuration Extraction',
        pattern: /(?:what|tell\s+me|reveal|show)\s+(?:is\s+)?(?:your|the)\s+(?:model\s+)?(?:configuration|hyperparameters?|training\s+(?:config|setup)|architecture\s+details)/gi,
        severity: 'medium',
        baseConfidence: 0.65,
        description: 'Attempts to extract model configuration details',
    },
    // Training Data Extraction
    {
        id: 'training-data-direct',
        category: 'training_data_extraction',
        name: 'Direct Training Data Request',
        pattern: /(?:show|give|reveal|extract|provide)\s+(?:me\s+)?(?:your|the)\s+(?:training\s+)?(?:data|dataset|examples|corpus)/gi,
        severity: 'critical',
        baseConfidence: 0.90,
        description: 'Direct requests for training data',
        behavioralIndicators: ['repeated_attempts', 'escalating_specificity'],
    },
    {
        id: 'training-data-memorization',
        category: 'training_data_extraction',
        name: 'Memorization Probing',
        pattern: /(?:complete|continue|finish)\s+(?:this|the\s+following)\s*[:"]?\s*(?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+){3,})/g,
        severity: 'high',
        baseConfidence: 0.70,
        description: 'Attempts to probe for memorized training data',
    },
    {
        id: 'training-data-verbatim',
        category: 'training_data_extraction',
        name: 'Verbatim Recall Request',
        pattern: /(?:recite|recall|reproduce|quote)\s+(?:verbatim|exactly|word\s+for\s+word)\s+(?:from|what\s+you\s+(?:learned|were\s+trained\s+on))/gi,
        severity: 'high',
        baseConfidence: 0.80,
        description: 'Attempts to extract verbatim training content',
    },
    // Prompt Harvesting
    {
        id: 'prompt-harvesting-system',
        category: 'prompt_harvesting',
        name: 'System Prompt Extraction',
        pattern: /(?:what|show|reveal|repeat|tell\s+me)\s+(?:is\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|initial\s+(?:prompt|instructions?)|configuration\s+prompt)/gi,
        severity: 'high',
        baseConfidence: 0.85,
        description: 'Attempts to extract system prompts',
        behavioralIndicators: ['session_start', 'multiple_rephrasing'],
    },
    {
        id: 'prompt-harvesting-ignore',
        category: 'prompt_harvesting',
        name: 'Ignore Instructions Pattern',
        pattern: /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions?|prompts?|rules?|guidelines?)/gi,
        severity: 'high',
        baseConfidence: 0.80,
        description: 'Attempts to bypass system instructions',
    },
    // Inference Attacks
    {
        id: 'inference-membership',
        category: 'inference_attack',
        name: 'Membership Inference',
        pattern: /(?:was|is)\s+(?:this|the\s+following)\s+(?:text|data|example|sample)\s+(?:in|part\s+of)\s+(?:your|the)\s+(?:training\s+)?(?:data|dataset)/gi,
        severity: 'high',
        baseConfidence: 0.75,
        description: 'Membership inference attack attempts',
    },
    {
        id: 'inference-attribute',
        category: 'inference_attack',
        name: 'Attribute Inference',
        pattern: /(?:infer|determine|figure\s+out|tell\s+me)\s+(?:the\s+)?(?:private|sensitive|personal)\s+(?:attributes?|information|data)\s+(?:about|of|from)/gi,
        severity: 'high',
        baseConfidence: 0.70,
        description: 'Attribute inference attack attempts',
    },
    // Adversarial Input Patterns
    {
        id: 'adversarial-perturbation',
        category: 'adversarial_input',
        name: 'Adversarial Perturbation',
        pattern: /[\u200B-\u200D\uFEFF\u2060-\u2064\u206A-\u206F]{3,}/g,
        severity: 'medium',
        baseConfidence: 0.80,
        description: 'Zero-width or invisible character injection',
    },
    {
        id: 'adversarial-unicode',
        category: 'adversarial_input',
        name: 'Unicode Confusion Attack',
        pattern: /[\u0400-\u04FF][\u0041-\u005A]|[\u0041-\u005A][\u0400-\u04FF]/g,
        severity: 'medium',
        baseConfidence: 0.70,
        description: 'Mixing Cyrillic and Latin characters for confusion',
    },
    {
        id: 'adversarial-encoding',
        category: 'adversarial_input',
        name: 'Encoding Attack',
        pattern: /(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|&#x?[0-9a-fA-F]+;){5,}/g,
        severity: 'medium',
        baseConfidence: 0.75,
        description: 'Unusual encoding sequences potentially hiding malicious content',
    },
    // API Abuse Patterns
    {
        id: 'api-abuse-batch',
        category: 'api_abuse',
        name: 'Batch Request Abuse',
        pattern: /(?:for\s+(?:each|every)|iterate\s+(?:over|through)|loop\s+(?:through|over))\s+(?:all|every|each)\s+(?:\d+|\w+)\s+(?:items?|entries?|records?)/gi,
        severity: 'medium',
        baseConfidence: 0.60,
        description: 'Patterns suggesting batch API abuse',
    },
    {
        id: 'api-abuse-automation',
        category: 'api_abuse',
        name: 'Automation Detection',
        pattern: /(?:generate|create|produce)\s+(?:\d+|multiple|many|all)\s+(?:variations?|versions?|alternatives?)\s+(?:of|for)\s+(?:each|every|all)/gi,
        severity: 'low',
        baseConfidence: 0.50,
        description: 'Patterns suggesting automated bulk generation',
    },
    // Rate Limit Evasion
    {
        id: 'rate-evasion-bypass',
        category: 'rate_limit_evasion',
        name: 'Rate Limit Bypass Attempt',
        pattern: /(?:bypass|circumvent|evade|avoid|get\s+around)\s+(?:the\s+)?(?:rate\s+)?limit(?:s|ing)?/gi,
        severity: 'high',
        baseConfidence: 0.90,
        description: 'Explicit attempts to evade rate limits',
    },
    // Resource Exhaustion
    {
        id: 'resource-exhaustion-loop',
        category: 'resource_exhaustion',
        name: 'Infinite Loop Induction',
        pattern: /(?:infinite\s+)?(?:loop|recursion|repeat)\s+(?:forever|infinitely|endlessly|until\s+(?:crash|exhaustion))/gi,
        severity: 'critical',
        baseConfidence: 0.85,
        description: 'Attempts to induce infinite loops or recursion',
    },
    {
        id: 'resource-exhaustion-memory',
        category: 'resource_exhaustion',
        name: 'Memory Exhaustion',
        pattern: /(?:allocate|use|consume)\s+(?:all|maximum|unlimited)\s+(?:memory|RAM|resources?)/gi,
        severity: 'high',
        baseConfidence: 0.80,
        description: 'Attempts to exhaust memory resources',
    },
    // Fingerprinting
    {
        id: 'fingerprinting-version',
        category: 'fingerprinting',
        name: 'Version Fingerprinting',
        pattern: /(?:what\s+(?:is\s+)?(?:your|the)|tell\s+me\s+(?:your|the))\s+(?:model\s+)?(?:version|release|build|revision|commit)/gi,
        severity: 'low',
        baseConfidence: 0.60,
        description: 'Attempts to determine model version',
    },
    {
        id: 'fingerprinting-capabilities',
        category: 'fingerprinting',
        name: 'Capability Fingerprinting',
        pattern: /(?:list|enumerate|what\s+are)\s+(?:all\s+)?(?:your|the\s+model(?:'s)?)\s+(?:capabilities|features|functions|abilities)/gi,
        severity: 'low',
        baseConfidence: 0.50,
        description: 'Systematic capability enumeration',
    },
    // Context Manipulation
    {
        id: 'context-overflow',
        category: 'context_manipulation',
        name: 'Context Overflow Attempt',
        pattern: /(?:fill|use\s+up|exhaust|overflow)\s+(?:the\s+)?(?:context|token|input)\s+(?:window|limit|buffer)/gi,
        severity: 'high',
        baseConfidence: 0.80,
        description: 'Attempts to overflow context window',
    },
    {
        id: 'context-injection',
        category: 'context_manipulation',
        name: 'Context Injection',
        pattern: /(?:inject|insert|add)\s+(?:into|to)\s+(?:the\s+)?(?:context|memory|history|conversation)/gi,
        severity: 'high',
        baseConfidence: 0.75,
        description: 'Attempts to inject malicious context',
    },
    // Unauthorized Access
    {
        id: 'unauthorized-admin',
        category: 'unauthorized_access',
        name: 'Admin Access Attempt',
        pattern: /(?:enable|activate|grant\s+(?:me)?|give\s+(?:me)?)\s+(?:admin|administrator|root|superuser|elevated)\s+(?:access|privileges?|permissions?|mode)/gi,
        severity: 'critical',
        baseConfidence: 0.90,
        description: 'Attempts to gain administrative access',
    },
    {
        id: 'unauthorized-developer',
        category: 'unauthorized_access',
        name: 'Developer Mode Access',
        pattern: /(?:enter|enable|activate|switch\s+to)\s+(?:developer|dev|debug|maintenance)\s+mode/gi,
        severity: 'high',
        baseConfidence: 0.85,
        description: 'Attempts to access developer mode',
    },
    // Credential Stuffing
    {
        id: 'credential-test',
        category: 'credential_stuffing',
        name: 'Credential Testing',
        pattern: /(?:try|test|check|validate)\s+(?:these?\s+)?(?:credentials?|passwords?|logins?|accounts?)\s*[:=]?\s*(?:\[|\{|")/gi,
        severity: 'critical',
        baseConfidence: 0.85,
        description: 'Patterns suggesting credential testing',
    },
];
/**
 * Behavioral thresholds for abuse detection
 */
export const BEHAVIORAL_THRESHOLDS = [
    {
        id: 'rate-high',
        category: 'rate_limit_evasion',
        name: 'High Request Rate',
        description: 'Requests per minute exceeds normal threshold',
        severity: 'high',
        threshold: 60,
        unit: 'requests_per_minute',
        baseConfidence: 0.85,
    },
    {
        id: 'rate-extreme',
        category: 'rate_limit_evasion',
        name: 'Extreme Request Rate',
        description: 'Requests per minute at extreme levels',
        severity: 'critical',
        threshold: 120,
        unit: 'requests_per_minute',
        baseConfidence: 0.95,
    },
    {
        id: 'session-tokens-high',
        category: 'resource_exhaustion',
        name: 'High Token Usage',
        description: 'Session token usage exceeds normal threshold',
        severity: 'medium',
        threshold: 100000,
        unit: 'tokens_per_session',
        baseConfidence: 0.70,
    },
    {
        id: 'session-tokens-extreme',
        category: 'resource_exhaustion',
        name: 'Extreme Token Usage',
        description: 'Session token usage at extreme levels',
        severity: 'high',
        threshold: 500000,
        unit: 'tokens_per_session',
        baseConfidence: 0.85,
    },
    {
        id: 'session-requests-many',
        category: 'api_abuse',
        name: 'Many Session Requests',
        description: 'Session request count exceeds normal threshold',
        severity: 'medium',
        threshold: 100,
        unit: 'requests_per_session',
        baseConfidence: 0.65,
    },
    {
        id: 'session-requests-excessive',
        category: 'api_abuse',
        name: 'Excessive Session Requests',
        description: 'Session request count at excessive levels',
        severity: 'high',
        threshold: 500,
        unit: 'requests_per_session',
        baseConfidence: 0.80,
    },
    {
        id: 'violations-repeated',
        category: 'api_abuse',
        name: 'Repeated Violations',
        description: 'Multiple previous violations detected',
        severity: 'high',
        threshold: 3,
        unit: 'previous_violations',
        baseConfidence: 0.80,
    },
    {
        id: 'violations-persistent',
        category: 'api_abuse',
        name: 'Persistent Violations',
        description: 'Persistent violation pattern detected',
        severity: 'critical',
        threshold: 10,
        unit: 'previous_violations',
        baseConfidence: 0.95,
    },
];
/**
 * Get all pattern IDs
 */
export function getAllPatternIds() {
    return MODEL_ABUSE_PATTERNS.map((p) => p.id);
}
/**
 * Get patterns for specific categories
 */
export function getPatternsForCategories(categories) {
    return MODEL_ABUSE_PATTERNS.filter((p) => categories.includes(p.category));
}
/**
 * Get behavioral thresholds for specific categories
 */
export function getThresholdsForCategories(categories) {
    return BEHAVIORAL_THRESHOLDS.filter((t) => categories.includes(t.category));
}
/**
 * Get pattern by ID
 */
export function getPatternById(id) {
    return MODEL_ABUSE_PATTERNS.find((p) => p.id === id);
}
/**
 * Get threshold by ID
 */
export function getThresholdById(id) {
    return BEHAVIORAL_THRESHOLDS.find((t) => t.id === id);
}
//# sourceMappingURL=patterns.js.map