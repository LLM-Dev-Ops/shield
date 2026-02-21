/**
 * @module patterns
 * @description Detection patterns for prompt injection identification
 *
 * Patterns are organized by category with severity weights
 * for confidence scoring.
 */
/**
 * Detection categories
 */
export const CATEGORIES = {
    INSTRUCTION_OVERRIDE: 'instruction_override',
    ROLE_MANIPULATION: 'role_manipulation',
    SYSTEM_PROMPT_ATTACK: 'system_prompt_attack',
    JAILBREAK: 'jailbreak',
    DELIMITER_INJECTION: 'delimiter_injection',
    ENCODING_ATTACK: 'encoding_attack',
    CONTEXT_MANIPULATION: 'context_manipulation',
};
/**
 * All detection patterns organized by category
 */
export const DETECTION_PATTERNS = [
    // ==========================================================================
    // INSTRUCTION OVERRIDE PATTERNS
    // ==========================================================================
    {
        id: 'IO-001',
        category: CATEGORIES.INSTRUCTION_OVERRIDE,
        pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|commands?|guidelines?)/i,
        severity: 0.9,
        confidence: 0.85,
        description: 'Attempts to ignore previous instructions',
    },
    {
        id: 'IO-002',
        category: CATEGORIES.INSTRUCTION_OVERRIDE,
        pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier|the)\s+(instructions?|prompts?|rules?|context)?/i,
        severity: 0.9,
        confidence: 0.85,
        description: 'Attempts to disregard instructions',
    },
    {
        id: 'IO-003',
        category: CATEGORIES.INSTRUCTION_OVERRIDE,
        pattern: /forget\s+(everything|all|what)\s+(you\s+)?(know|learned|were\s+told|have\s+been\s+told)/i,
        severity: 0.85,
        confidence: 0.8,
        description: 'Attempts to make model forget instructions',
    },
    {
        id: 'IO-004',
        category: CATEGORIES.INSTRUCTION_OVERRIDE,
        pattern: /override\s+(previous|system|all|your|the)\s+(instructions?|prompts?|rules?|settings?|configuration)/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'Direct override attempts',
    },
    {
        id: 'IO-005',
        category: CATEGORIES.INSTRUCTION_OVERRIDE,
        pattern: /bypass\s+(the\s+)?(safety|security|content|your)\s+(filters?|measures?|restrictions?|checks?|guidelines?)/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'Attempts to bypass safety measures',
    },
    {
        id: 'IO-006',
        category: CATEGORIES.INSTRUCTION_OVERRIDE,
        pattern: /new\s+rules?\s*[:：]/i,
        severity: 0.8,
        confidence: 0.75,
        description: 'Attempts to establish new rules',
    },
    {
        id: 'IO-007',
        category: CATEGORIES.INSTRUCTION_OVERRIDE,
        pattern: /from\s+now\s+on[\s,]+(?:you\s+)?(will|must|should|shall)/i,
        severity: 0.8,
        confidence: 0.75,
        description: 'Attempts to change future behavior',
    },
    {
        id: 'IO-008',
        category: CATEGORIES.INSTRUCTION_OVERRIDE,
        pattern: /stop\s+following\s+(your|the|all)\s+(instructions?|rules?|guidelines?)/i,
        severity: 0.9,
        confidence: 0.85,
        description: 'Attempts to stop instruction following',
    },
    // ==========================================================================
    // ROLE MANIPULATION PATTERNS
    // ==========================================================================
    {
        id: 'RM-001',
        category: CATEGORIES.ROLE_MANIPULATION,
        pattern: /you\s+are\s+(now|no\s+longer)\s+(a|an|the)/i,
        severity: 0.8,
        confidence: 0.75,
        description: 'Attempts to change model identity',
    },
    {
        id: 'RM-002',
        category: CATEGORIES.ROLE_MANIPULATION,
        pattern: /pretend\s+(to\s+be|you\s+are|you're|that\s+you\s+are)/i,
        severity: 0.75,
        confidence: 0.7,
        description: 'Pretend-based role manipulation',
    },
    {
        id: 'RM-003',
        category: CATEGORIES.ROLE_MANIPULATION,
        pattern: /act\s+as\s+(if\s+you\s+are|a|an|though\s+you)/i,
        severity: 0.75,
        confidence: 0.7,
        description: 'Act-as role manipulation',
    },
    {
        id: 'RM-004',
        category: CATEGORIES.ROLE_MANIPULATION,
        pattern: /roleplay\s+(as|being|that\s+you\s+are)/i,
        severity: 0.7,
        confidence: 0.65,
        description: 'Roleplay-based manipulation',
    },
    {
        id: 'RM-005',
        category: CATEGORIES.ROLE_MANIPULATION,
        pattern: /simulate\s+(being|that\s+you\s+are|a|an)/i,
        severity: 0.7,
        confidence: 0.65,
        description: 'Simulation-based manipulation',
    },
    {
        id: 'RM-006',
        category: CATEGORIES.ROLE_MANIPULATION,
        pattern: /imagine\s+(you\s+are|yourself\s+as|being)/i,
        severity: 0.7,
        confidence: 0.65,
        description: 'Imagination-based manipulation',
    },
    {
        id: 'RM-007',
        category: CATEGORIES.ROLE_MANIPULATION,
        pattern: /your\s+new\s+(name|identity|persona|role)\s+(is|will\s+be)/i,
        severity: 0.85,
        confidence: 0.8,
        description: 'Direct identity assignment',
    },
    {
        id: 'RM-008',
        category: CATEGORIES.ROLE_MANIPULATION,
        pattern: /you\s+will\s+now\s+(respond|act|behave)\s+as/i,
        severity: 0.85,
        confidence: 0.8,
        description: 'Behavioral override attempts',
    },
    // ==========================================================================
    // SYSTEM PROMPT ATTACK PATTERNS
    // ==========================================================================
    {
        id: 'SP-001',
        category: CATEGORIES.SYSTEM_PROMPT_ATTACK,
        pattern: /system\s*prompt\s*[:：]/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'Direct system prompt injection',
    },
    {
        id: 'SP-002',
        category: CATEGORIES.SYSTEM_PROMPT_ATTACK,
        pattern: /new\s+instructions?\s*[:：]/i,
        severity: 0.9,
        confidence: 0.85,
        description: 'New instruction injection',
    },
    {
        id: 'SP-003',
        category: CATEGORIES.SYSTEM_PROMPT_ATTACK,
        pattern: /admin\s*(mode|access|override)\s*[:：]?/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'Admin mode attempts',
    },
    {
        id: 'SP-004',
        category: CATEGORIES.SYSTEM_PROMPT_ATTACK,
        pattern: /developer\s*(mode|access|override)\s*[:：]?/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'Developer mode attempts',
    },
    {
        id: 'SP-005',
        category: CATEGORIES.SYSTEM_PROMPT_ATTACK,
        pattern: /sudo\s+(mode|enable|activate)/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'Sudo/root access attempts',
    },
    {
        id: 'SP-006',
        category: CATEGORIES.SYSTEM_PROMPT_ATTACK,
        pattern: /reveal\s+(your|the)\s+(system\s+)?prompt/i,
        severity: 0.85,
        confidence: 0.8,
        description: 'System prompt extraction attempts',
    },
    {
        id: 'SP-007',
        category: CATEGORIES.SYSTEM_PROMPT_ATTACK,
        pattern: /show\s+me\s+(your|the)\s+(hidden\s+)?(instructions?|prompt|rules?)/i,
        severity: 0.85,
        confidence: 0.8,
        description: 'Instruction extraction attempts',
    },
    {
        id: 'SP-008',
        category: CATEGORIES.SYSTEM_PROMPT_ATTACK,
        pattern: /what\s+(is|are)\s+your\s+(original|initial|system)\s+(instructions?|prompt|rules?)/i,
        severity: 0.8,
        confidence: 0.75,
        description: 'Prompt probing attempts',
    },
    // ==========================================================================
    // JAILBREAK PATTERNS
    // ==========================================================================
    {
        id: 'JB-001',
        category: CATEGORIES.JAILBREAK,
        pattern: /jailbreak/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'Direct jailbreak reference',
    },
    {
        id: 'JB-002',
        category: CATEGORIES.JAILBREAK,
        pattern: /\bDAN\s*(mode)?/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'DAN (Do Anything Now) jailbreak',
    },
    {
        id: 'JB-003',
        category: CATEGORIES.JAILBREAK,
        pattern: /do\s+anything\s+now/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'DAN jailbreak variant',
    },
    {
        id: 'JB-004',
        category: CATEGORIES.JAILBREAK,
        pattern: /unlock\s+(the\s+)?(full|hidden|true)\s+(potential|capabilities|power)/i,
        severity: 0.9,
        confidence: 0.85,
        description: 'Capability unlock attempts',
    },
    {
        id: 'JB-005',
        category: CATEGORIES.JAILBREAK,
        pattern: /remove\s+(all\s+)?(restrictions?|limitations?|filters?|constraints?)/i,
        severity: 0.9,
        confidence: 0.85,
        description: 'Restriction removal attempts',
    },
    {
        id: 'JB-006',
        category: CATEGORIES.JAILBREAK,
        pattern: /\bAIM\b.*\bMachiavelli/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'AIM (Always Intelligent Machiavelli) jailbreak',
    },
    {
        id: 'JB-007',
        category: CATEGORIES.JAILBREAK,
        pattern: /\bDEVIL\b.*\bmode/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'DEVIL mode jailbreak',
    },
    {
        id: 'JB-008',
        category: CATEGORIES.JAILBREAK,
        pattern: /\bEVIL\b.*\b(mode|confidant)/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'EVIL mode jailbreak',
    },
    {
        id: 'JB-009',
        category: CATEGORIES.JAILBREAK,
        pattern: /you\s+have\s+no\s+(rules?|restrictions?|limitations?|ethical\s+guidelines?)/i,
        severity: 0.9,
        confidence: 0.85,
        description: 'Rule negation attempts',
    },
    {
        id: 'JB-010',
        category: CATEGORIES.JAILBREAK,
        pattern: /hypothetical(ly)?\s+(evil|unethical|malicious)/i,
        severity: 0.85,
        confidence: 0.8,
        description: 'Hypothetical scenario exploitation',
    },
    // ==========================================================================
    // DELIMITER INJECTION PATTERNS
    // ==========================================================================
    {
        id: 'DI-001',
        category: CATEGORIES.DELIMITER_INJECTION,
        pattern: /\[\s*INST\s*\]/i,
        severity: 0.9,
        confidence: 0.85,
        description: 'Llama instruction delimiter injection',
    },
    {
        id: 'DI-002',
        category: CATEGORIES.DELIMITER_INJECTION,
        pattern: /\[\s*SYSTEM\s*\]/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'System role delimiter injection',
    },
    {
        id: 'DI-003',
        category: CATEGORIES.DELIMITER_INJECTION,
        pattern: /<\|im_start\|>/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'ChatML start delimiter injection',
    },
    {
        id: 'DI-004',
        category: CATEGORIES.DELIMITER_INJECTION,
        pattern: /<\|im_end\|>/i,
        severity: 0.9,
        confidence: 0.85,
        description: 'ChatML end delimiter injection',
    },
    {
        id: 'DI-005',
        category: CATEGORIES.DELIMITER_INJECTION,
        pattern: /###\s*(SYSTEM|INSTRUCTION|HUMAN|ASSISTANT)/i,
        severity: 0.9,
        confidence: 0.85,
        description: 'Markdown-style delimiter injection',
    },
    {
        id: 'DI-006',
        category: CATEGORIES.DELIMITER_INJECTION,
        pattern: /<\|endoftext\|>/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'End-of-text delimiter injection',
    },
    {
        id: 'DI-007',
        category: CATEGORIES.DELIMITER_INJECTION,
        pattern: /\[\/INST\]/i,
        severity: 0.9,
        confidence: 0.85,
        description: 'Llama instruction close delimiter',
    },
    {
        id: 'DI-008',
        category: CATEGORIES.DELIMITER_INJECTION,
        pattern: /<\|user\|>|<\|assistant\|>|<\|system\|>/i,
        severity: 0.95,
        confidence: 0.9,
        description: 'Role delimiter injection',
    },
    {
        id: 'DI-009',
        category: CATEGORIES.DELIMITER_INJECTION,
        pattern: /\[\[SYSTEM\]\]|\[\[USER\]\]|\[\[ASSISTANT\]\]/i,
        severity: 0.9,
        confidence: 0.85,
        description: 'Double-bracket delimiter injection',
    },
    // ==========================================================================
    // ENCODING ATTACK PATTERNS
    // ==========================================================================
    {
        id: 'EA-001',
        category: CATEGORIES.ENCODING_ATTACK,
        pattern: /(?:[A-Za-z0-9+/]{4}){10,}={0,2}/,
        severity: 0.6,
        confidence: 0.5,
        description: 'Potential Base64 encoded content',
    },
    {
        id: 'EA-002',
        category: CATEGORIES.ENCODING_ATTACK,
        pattern: /(?:\\x[0-9a-fA-F]{2}){4,}/,
        severity: 0.7,
        confidence: 0.6,
        description: 'Hex-encoded content',
    },
    {
        id: 'EA-003',
        category: CATEGORIES.ENCODING_ATTACK,
        pattern: /(?:\\u[0-9a-fA-F]{4}){4,}/,
        severity: 0.7,
        confidence: 0.6,
        description: 'Unicode-encoded content',
    },
    {
        id: 'EA-004',
        category: CATEGORIES.ENCODING_ATTACK,
        pattern: /[\u200B-\u200F\u2028-\u202F\uFEFF]/,
        severity: 0.75,
        confidence: 0.7,
        description: 'Zero-width character injection',
    },
    {
        id: 'EA-005',
        category: CATEGORIES.ENCODING_ATTACK,
        pattern: /[\u0400-\u04FF]/,
        severity: 0.5,
        confidence: 0.4,
        description: 'Cyrillic homoglyph potential',
    },
    // ==========================================================================
    // CONTEXT MANIPULATION PATTERNS
    // ==========================================================================
    {
        id: 'CM-001',
        category: CATEGORIES.CONTEXT_MANIPULATION,
        pattern: /forget\s+(the|our)\s+conversation/i,
        severity: 0.8,
        confidence: 0.75,
        description: 'Conversation reset attempts',
    },
    {
        id: 'CM-002',
        category: CATEGORIES.CONTEXT_MANIPULATION,
        pattern: /start\s+(a\s+)?new\s+(conversation|session|chat)/i,
        severity: 0.7,
        confidence: 0.65,
        description: 'Session reset attempts',
    },
    {
        id: 'CM-003',
        category: CATEGORIES.CONTEXT_MANIPULATION,
        pattern: /clear\s+(your|the)\s+(memory|context|history)/i,
        severity: 0.8,
        confidence: 0.75,
        description: 'Memory clear attempts',
    },
    {
        id: 'CM-004',
        category: CATEGORIES.CONTEXT_MANIPULATION,
        pattern: /beginning\s+of\s+(a\s+)?new\s+(conversation|context)/i,
        severity: 0.75,
        confidence: 0.7,
        description: 'Context boundary injection',
    },
    {
        id: 'CM-005',
        category: CATEGORIES.CONTEXT_MANIPULATION,
        pattern: /the\s+(above|previous)\s+(was|is)\s+(just\s+)?(a\s+)?(test|example|joke)/i,
        severity: 0.85,
        confidence: 0.8,
        description: 'Context invalidation attempts',
    },
];
/**
 * Get patterns by category
 */
export function getPatternsByCategory(category) {
    return DETECTION_PATTERNS.filter((p) => p.category === category);
}
/**
 * Get patterns for multiple categories
 */
export function getPatternsForCategories(categories) {
    return DETECTION_PATTERNS.filter((p) => categories.includes(p.category));
}
/**
 * Get all pattern IDs
 */
export function getAllPatternIds() {
    return DETECTION_PATTERNS.map((p) => p.id);
}
/**
 * Get pattern by ID
 */
export function getPatternById(id) {
    return DETECTION_PATTERNS.find((p) => p.id === id);
}
//# sourceMappingURL=patterns.js.map