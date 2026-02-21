/**
 * @module patterns
 * @description Safety boundary detection patterns
 *
 * These patterns detect content that violates safety boundaries.
 * Pattern IDs follow format: sb-{category}-{number}
 */
/**
 * All safety categories
 */
export const SAFETY_CATEGORIES = [
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
];
/**
 * Safety boundary detection patterns
 */
export const SAFETY_PATTERNS = [
    // ============================================
    // HATE SPEECH PATTERNS
    // ============================================
    {
        id: 'sb-hate-001',
        pattern: '\\b(kill\\s+all|exterminate|genocide)\\s+(\\w+\\s+)?(people|race|ethnicity|religion)\\b',
        category: 'hate_speech',
        confidence: 0.95,
        severity: 1.0,
        description: 'Genocidal language targeting groups',
        tags: ['violence', 'discrimination'],
    },
    {
        id: 'sb-hate-002',
        pattern: '\\b(all|every)\\s+(\\w+)\\s+(should|must|need\\s+to)\\s+(die|be\\s+killed|be\\s+eliminated)\\b',
        category: 'hate_speech',
        confidence: 0.9,
        severity: 1.0,
        description: 'Group-targeted death wishes',
        tags: ['violence', 'discrimination'],
    },
    {
        id: 'sb-hate-003',
        pattern: '\\b(inferior|subhuman|vermin|animals?)\\s+(race|people|group)\\b',
        category: 'hate_speech',
        confidence: 0.85,
        severity: 0.9,
        description: 'Dehumanizing language',
        tags: ['discrimination'],
    },
    // ============================================
    // SELF-HARM PATTERNS
    // ============================================
    {
        id: 'sb-self-001',
        pattern: '\\b(how\\s+to|ways\\s+to|best\\s+way\\s+to)\\s+(kill\\s+(yourself|myself)|commit\\s+suicide|end\\s+(my|your)\\s+life)\\b',
        category: 'self_harm',
        confidence: 0.95,
        severity: 1.0,
        description: 'Suicide method seeking',
        tags: ['crisis', 'urgent'],
    },
    {
        id: 'sb-self-002',
        pattern: '\\b(i\\s+want\\s+to|going\\s+to|planning\\s+to)\\s+(kill\\s+myself|end\\s+my\\s+life|commit\\s+suicide)\\b',
        category: 'self_harm',
        confidence: 0.95,
        severity: 1.0,
        description: 'Suicidal ideation expression',
        tags: ['crisis', 'urgent'],
    },
    {
        id: 'sb-self-003',
        pattern: '\\b(cut|cutting|harm|hurting)\\s+(myself|yourself)\\s+(to\\s+feel|because)\\b',
        category: 'self_harm',
        confidence: 0.85,
        severity: 0.9,
        description: 'Self-harm discussion',
        tags: ['crisis'],
    },
    // ============================================
    // VIOLENCE PATTERNS
    // ============================================
    {
        id: 'sb-viol-001',
        pattern: '\\b(how\\s+to|instructions?\\s+for)\\s+(make|build|create)\\s+(a\\s+)?(bomb|explosive|weapon)\\b',
        category: 'violence',
        confidence: 0.95,
        severity: 1.0,
        description: 'Weapon/explosive creation instructions',
        tags: ['weapons', 'dangerous'],
    },
    {
        id: 'sb-viol-002',
        pattern: '\\b(i\\s+will|i\'m\\s+going\\s+to|planning\\s+to)\\s+(kill|murder|attack|hurt)\\s+',
        category: 'violence',
        confidence: 0.9,
        severity: 0.95,
        description: 'Violence threat expression',
        tags: ['threat', 'urgent'],
    },
    {
        id: 'sb-viol-003',
        pattern: '\\b(torture|torturing|mutilate|mutilating)\\s+(someone|people|animals?)\\b',
        category: 'violence',
        confidence: 0.9,
        severity: 0.95,
        description: 'Torture/mutilation content',
        tags: ['graphic'],
    },
    // ============================================
    // ILLEGAL ACTIVITY PATTERNS
    // ============================================
    {
        id: 'sb-illegal-001',
        pattern: '\\b(how\\s+to|recipe\\s+for|synthesize|make|cook|produce|manufacture)\\s+(\\w+\\s+)?(meth|methamphetamine|cocaine|heroin|fentanyl)\\b',
        category: 'illegal_activity',
        confidence: 0.95,
        severity: 1.0,
        description: 'Drug synthesis instructions',
        tags: ['drugs', 'manufacturing'],
    },
    {
        id: 'sb-illegal-002',
        pattern: '\\b(how\\s+to|steps\\s+to)\\s+(hack|break\\s+into|steal\\s+from)\\s+(a\\s+)?(bank|account|system)\\b',
        category: 'illegal_activity',
        confidence: 0.85,
        severity: 0.9,
        description: 'Criminal hacking instructions',
        tags: ['cybercrime'],
    },
    {
        id: 'sb-illegal-003',
        pattern: '\\b(launder|laundering)\\s+money\\b|\\bmoney\\s+laundering\\s+(techniques?|methods?)\\b',
        category: 'illegal_activity',
        confidence: 0.85,
        severity: 0.9,
        description: 'Money laundering content',
        tags: ['financial-crime'],
    },
    {
        id: 'sb-illegal-004',
        pattern: '\\b(child|minor)\\s+(porn|pornography|exploitation|abuse)\\b|\\bcsam\\b',
        category: 'illegal_activity',
        confidence: 0.99,
        severity: 1.0,
        description: 'Child exploitation content',
        tags: ['csam', 'urgent'],
    },
    // ============================================
    // DANGEROUS INSTRUCTIONS PATTERNS
    // ============================================
    {
        id: 'sb-danger-001',
        pattern: '\\b(how\\s+to|steps\\s+to)\\s+(poison|poisoning)\\s+(someone|food|water)\\b',
        category: 'dangerous_instructions',
        confidence: 0.9,
        severity: 0.95,
        description: 'Poisoning instructions',
        tags: ['harm'],
    },
    {
        id: 'sb-danger-002',
        pattern: '\\b(mix|combine)\\s+(bleach|ammonia|chemicals?)\\s+(to\\s+make|for)\\s+(gas|poison)\\b',
        category: 'dangerous_instructions',
        confidence: 0.9,
        severity: 0.95,
        description: 'Toxic chemical mixing instructions',
        tags: ['chemical'],
    },
    {
        id: 'sb-danger-003',
        pattern: '\\b(disable|bypass|defeat)\\s+(safety|security)\\s+(features?|systems?|measures?)\\b',
        category: 'dangerous_instructions',
        confidence: 0.7,
        severity: 0.7,
        description: 'Safety bypass instructions',
        tags: ['safety'],
    },
    // ============================================
    // EXPLICIT CONTENT PATTERNS
    // ============================================
    {
        id: 'sb-explicit-001',
        pattern: '\\b(explicit|graphic)\\s+(sexual|sex)\\s+(content|material|description)\\b',
        category: 'explicit_content',
        confidence: 0.8,
        severity: 0.6,
        description: 'Explicit sexual content request',
        tags: ['adult'],
    },
    {
        id: 'sb-explicit-002',
        pattern: '\\b(write|generate|create)\\s+(pornographic|erotic|sexual)\\s+(story|content|scene)\\b',
        category: 'explicit_content',
        confidence: 0.85,
        severity: 0.65,
        description: 'Pornographic content generation',
        tags: ['adult', 'generation'],
    },
    // ============================================
    // DECEPTIVE CONTENT PATTERNS
    // ============================================
    {
        id: 'sb-decept-001',
        pattern: '\\b(write|create|generate)\\s+(fake|false|misleading)\\s+(news|article|report)\\b',
        category: 'deceptive_content',
        confidence: 0.8,
        severity: 0.6,
        description: 'Fake news generation request',
        tags: ['misinformation'],
    },
    {
        id: 'sb-decept-002',
        pattern: '\\b(impersonate|pretend\\s+to\\s+be)\\s+(a\\s+)?(doctor|lawyer|official|authority)\\b',
        category: 'deceptive_content',
        confidence: 0.75,
        severity: 0.65,
        description: 'Professional impersonation',
        tags: ['fraud'],
    },
    {
        id: 'sb-decept-003',
        pattern: '\\b(scam|phishing)\\s+(email|message|script)\\b|\\b(write|create)\\s+(a\\s+)?scam\\b',
        category: 'deceptive_content',
        confidence: 0.85,
        severity: 0.8,
        description: 'Scam/phishing content creation',
        tags: ['fraud', 'cybercrime'],
    },
    // ============================================
    // PRIVACY VIOLATION PATTERNS
    // ============================================
    {
        id: 'sb-privacy-001',
        pattern: '\\b(dox|doxxing|reveal)\\s+(personal|private)\\s+(information|data|address)\\b',
        category: 'privacy_violation',
        confidence: 0.85,
        severity: 0.85,
        description: 'Doxxing/personal info exposure',
        tags: ['pii'],
    },
    {
        id: 'sb-privacy-002',
        pattern: '\\b(find|locate|track)\\s+(someone\'s?|a\\s+person\'s?)\\s+(home|address|location)\\b',
        category: 'privacy_violation',
        confidence: 0.8,
        severity: 0.8,
        description: 'Personal location tracking',
        tags: ['stalking'],
    },
    // ============================================
    // HARMFUL CONTENT PATTERNS
    // ============================================
    {
        id: 'sb-harm-001',
        pattern: '\\b(encourage|promoting|glorify)\\s+(eating\\s+disorder|anorexia|bulimia)\\b',
        category: 'harmful_content',
        confidence: 0.85,
        severity: 0.85,
        description: 'Eating disorder promotion',
        tags: ['health'],
    },
    {
        id: 'sb-harm-002',
        pattern: '\\b(manipulate|gaslight|abuse)\\s+(partner|spouse|someone)\\b',
        category: 'harmful_content',
        confidence: 0.75,
        severity: 0.7,
        description: 'Relationship abuse tactics',
        tags: ['abuse'],
    },
    // ============================================
    // INTELLECTUAL PROPERTY PATTERNS
    // ============================================
    {
        id: 'sb-ip-001',
        pattern: '\\b(crack|pirate|bypass)\\s+(software|license|drm|protection)\\b',
        category: 'intellectual_property',
        confidence: 0.75,
        severity: 0.5,
        description: 'Software piracy assistance',
        tags: ['piracy'],
    },
    {
        id: 'sb-ip-002',
        pattern: '\\b(generate|create)\\s+(copyrighted|trademarked)\\s+(content|material)\\b',
        category: 'intellectual_property',
        confidence: 0.7,
        severity: 0.5,
        description: 'Copyright infringement request',
        tags: ['copyright'],
    },
];
/**
 * Get patterns for specific categories
 */
export function getPatternsForCategories(categories) {
    return SAFETY_PATTERNS.filter((p) => categories.includes(p.category));
}
/**
 * Get all patterns
 */
export function getAllPatterns() {
    return SAFETY_PATTERNS;
}
/**
 * Get pattern by ID
 */
export function getPatternById(id) {
    return SAFETY_PATTERNS.find((p) => p.id === id);
}
/**
 * Pattern count by category
 */
export function getPatternCountByCategory() {
    const counts = {};
    for (const pattern of SAFETY_PATTERNS) {
        counts[pattern.category] = (counts[pattern.category] || 0) + 1;
    }
    return counts;
}
//# sourceMappingURL=patterns.js.map