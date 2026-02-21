/**
 * @module patterns
 * @description Content moderation detection patterns
 *
 * These patterns detect content that violates moderation policies.
 * Pattern IDs follow format: cm-{category}-{number}
 */
/**
 * All moderation categories
 */
export const MODERATION_CATEGORIES = [
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
];
/**
 * Content moderation detection patterns
 */
export const MODERATION_PATTERNS = [
    // ============================================
    // CHILD SAFETY PATTERNS (CRITICAL - Always Block)
    // ============================================
    {
        id: 'cm-child-001',
        pattern: '\\b(child|minor|kid|underage)\\s+(porn|pornography|exploitation|abuse)\\b|\\bcsam\\b|\\bcsa\\s+material\\b',
        category: 'child_safety',
        confidence: 0.99,
        severity: 1.0,
        description: 'Child exploitation content reference',
        recommended_action: 'BLOCK',
        tags: ['csam', 'urgent', 'illegal'],
    },
    {
        id: 'cm-child-002',
        pattern: '\\b(groom|grooming)\\s+(child|children|minor|kid|teen)\\b',
        category: 'child_safety',
        confidence: 0.95,
        severity: 1.0,
        description: 'Child grooming discussion',
        recommended_action: 'BLOCK',
        tags: ['grooming', 'urgent'],
    },
    {
        id: 'cm-child-003',
        pattern: '\\b(attract|attract\\s+to|attracted\\s+to)\\s+(minor|child|children|kid)\\b',
        category: 'child_safety',
        confidence: 0.9,
        severity: 0.95,
        description: 'Inappropriate interest in minors',
        recommended_action: 'BLOCK',
        tags: ['concerning'],
    },
    // ============================================
    // TERRORISM/EXTREMISM PATTERNS (CRITICAL)
    // ============================================
    {
        id: 'cm-terror-001',
        pattern: '\\b(join|recruit|support)\\s+(isis|isil|al[- ]?qaeda|hamas|hezbollah|taliban)\\b',
        category: 'terrorism_extremism',
        confidence: 0.95,
        severity: 1.0,
        description: 'Terrorist organization recruitment/support',
        recommended_action: 'BLOCK',
        tags: ['terrorism', 'recruitment'],
    },
    {
        id: 'cm-terror-002',
        pattern: '\\b(how\\s+to|build|make|create)\\s+(bomb|explosive|ied|improvised\\s+explosive)\\b',
        category: 'terrorism_extremism',
        confidence: 0.95,
        severity: 1.0,
        description: 'Explosive device instructions',
        recommended_action: 'BLOCK',
        tags: ['weapons', 'dangerous'],
    },
    {
        id: 'cm-terror-003',
        pattern: '\\b(manifest|manifesto)\\s+(of|from)\\s+(shooter|bomber|terrorist|attacker)\\b',
        category: 'terrorism_extremism',
        confidence: 0.9,
        severity: 0.95,
        description: 'Terrorist manifesto reference',
        recommended_action: 'BLOCK',
        tags: ['extremism'],
    },
    // ============================================
    // HATE/DISCRIMINATORY PATTERNS (CRITICAL)
    // ============================================
    {
        id: 'cm-hate-001',
        pattern: '\\b(kill\\s+all|exterminate|genocide)\\s+(\\w+\\s+)?(people|race|ethnicity|religion|jews|muslims|blacks|whites)\\b',
        category: 'hate_discriminatory',
        confidence: 0.95,
        severity: 1.0,
        description: 'Genocidal language targeting groups',
        recommended_action: 'BLOCK',
        tags: ['violence', 'discrimination'],
    },
    {
        id: 'cm-hate-002',
        pattern: '\\b(inferior|subhuman|vermin|animals?)\\s+(race|people|group)\\b',
        category: 'hate_discriminatory',
        confidence: 0.85,
        severity: 0.9,
        description: 'Dehumanizing language',
        recommended_action: 'BLOCK',
        tags: ['discrimination'],
    },
    {
        id: 'cm-hate-003',
        pattern: '\\b(n[i1]gg[ae]r|k[i1]ke|sp[i1]c|ch[i1]nk|wetback|f[a@]gg[o0]t)\\b',
        category: 'hate_discriminatory',
        confidence: 0.95,
        severity: 0.95,
        description: 'Racial/ethnic slurs',
        recommended_action: 'BLOCK',
        caseSensitive: false,
        tags: ['slur', 'discrimination'],
    },
    // ============================================
    // SELF-HARM PATTERNS (CRITICAL)
    // ============================================
    {
        id: 'cm-harm-001',
        pattern: '\\b(how\\s+to|ways\\s+to|best\\s+way\\s+to)\\s+(kill\\s+(yourself|myself)|commit\\s+suicide|end\\s+(my|your)\\s+life)\\b',
        category: 'self_harm',
        confidence: 0.95,
        severity: 1.0,
        description: 'Suicide method seeking',
        recommended_action: 'BLOCK',
        tags: ['crisis', 'urgent'],
    },
    {
        id: 'cm-harm-002',
        pattern: '\\b(encourage|promoting|glorify)\\s+(self[- ]?harm|cutting|suicide|anorexia|bulimia)\\b',
        category: 'self_harm',
        confidence: 0.9,
        severity: 0.95,
        description: 'Self-harm promotion',
        recommended_action: 'BLOCK',
        tags: ['crisis'],
    },
    {
        id: 'cm-harm-003',
        pattern: '\\b(pro[- ]?ana|thinspo|pro[- ]?mia|suicide\\s+pact)\\b',
        category: 'self_harm',
        confidence: 0.85,
        severity: 0.9,
        description: 'Pro-eating disorder or suicide pact content',
        recommended_action: 'BLOCK',
        tags: ['crisis', 'eating-disorder'],
    },
    // ============================================
    // ILLEGAL/REGULATED PATTERNS
    // ============================================
    {
        id: 'cm-illegal-001',
        pattern: '\\b(how\\s+to|recipe\\s+for|synthesize|cook|manufacture)\\s+(\\w+\\s+)?(meth|methamphetamine|cocaine|heroin|fentanyl|mdma|lsd)\\b',
        category: 'illegal_regulated',
        confidence: 0.95,
        severity: 1.0,
        description: 'Drug synthesis instructions',
        recommended_action: 'BLOCK',
        tags: ['drugs', 'manufacturing'],
    },
    {
        id: 'cm-illegal-002',
        pattern: '\\b(buy|sell|purchase|order)\\s+(drugs|weapons|guns|ammunition|explosives)\\s+(online|darknet|dark\\s+web)\\b',
        category: 'illegal_regulated',
        confidence: 0.9,
        severity: 0.9,
        description: 'Illegal marketplace solicitation',
        recommended_action: 'BLOCK',
        tags: ['trafficking'],
    },
    {
        id: 'cm-illegal-003',
        pattern: '\\b(hire|contract)\\s+(hitman|assassin|killer)\\b|\\bhit\\s+job\\b',
        category: 'illegal_regulated',
        confidence: 0.95,
        severity: 1.0,
        description: 'Murder for hire solicitation',
        recommended_action: 'BLOCK',
        tags: ['violence', 'murder'],
    },
    // ============================================
    // VIOLENCE/GRAPHIC PATTERNS
    // ============================================
    {
        id: 'cm-violence-001',
        pattern: '\\b(torture|torturing|mutilate|mutilating|dismember)\\s+(someone|people|animals?|victim)\\b',
        category: 'violence_graphic',
        confidence: 0.9,
        severity: 0.95,
        description: 'Graphic violence description',
        recommended_action: 'BLOCK',
        age_restricted: true,
        tags: ['graphic'],
    },
    {
        id: 'cm-violence-002',
        pattern: '\\b(watch|see)\\s+(someone|people)\\s+(die|dying|being\\s+killed|get\\s+killed)\\b',
        category: 'violence_graphic',
        confidence: 0.8,
        severity: 0.85,
        description: 'Death voyeurism',
        recommended_action: 'FLAG',
        age_restricted: true,
        tags: ['graphic'],
    },
    {
        id: 'cm-violence-003',
        pattern: '\\b(gore|snuff\\s+film|execution\\s+video|beheading\\s+video)\\b',
        category: 'violence_graphic',
        confidence: 0.95,
        severity: 0.95,
        description: 'Extreme violent content request',
        recommended_action: 'BLOCK',
        tags: ['extreme', 'graphic'],
    },
    // ============================================
    // HARASSMENT/BULLYING PATTERNS
    // ============================================
    {
        id: 'cm-harass-001',
        pattern: '\\b(kill\\s+yourself|kys|go\\s+die|hope\\s+you\\s+die)\\b',
        category: 'harassment_bullying',
        confidence: 0.9,
        severity: 0.9,
        description: 'Death wish harassment',
        recommended_action: 'BLOCK',
        tags: ['harassment', 'death-wish'],
    },
    {
        id: 'cm-harass-002',
        pattern: '\\b(dox|doxxing|leak\\s+address|expose\\s+identity)\\b',
        category: 'harassment_bullying',
        confidence: 0.85,
        severity: 0.85,
        description: 'Doxxing threat',
        recommended_action: 'BLOCK',
        tags: ['harassment', 'privacy'],
    },
    {
        id: 'cm-harass-003',
        pattern: '\\b(stalk|stalking|track|tracking)\\s+(you|them|her|him|someone)\\b',
        category: 'harassment_bullying',
        confidence: 0.8,
        severity: 0.8,
        description: 'Stalking behavior',
        recommended_action: 'FLAG',
        tags: ['harassment', 'stalking'],
    },
    // ============================================
    // ADULT CONTENT PATTERNS
    // ============================================
    {
        id: 'cm-adult-001',
        pattern: '\\b(explicit|graphic|hardcore)\\s+(sex|sexual|porn|pornographic)\\s+(content|material|scene|video)\\b',
        category: 'adult_content',
        confidence: 0.85,
        severity: 0.6,
        description: 'Explicit sexual content request',
        recommended_action: 'AGE_GATE',
        age_restricted: true,
        tags: ['adult', 'nsfw'],
    },
    {
        id: 'cm-adult-002',
        pattern: '\\b(write|generate|create)\\s+(pornographic|erotic|sexual)\\s+(story|content|scene|fiction)\\b',
        category: 'adult_content',
        confidence: 0.85,
        severity: 0.65,
        description: 'Pornographic content generation',
        recommended_action: 'AGE_GATE',
        age_restricted: true,
        tags: ['adult', 'generation'],
    },
    {
        id: 'cm-adult-003',
        pattern: '\\b(nude|naked)\\s+(photo|picture|image|video)\\s+of\\b',
        category: 'adult_content',
        confidence: 0.8,
        severity: 0.7,
        description: 'Nude content request',
        recommended_action: 'AGE_GATE',
        age_restricted: true,
        tags: ['adult', 'images'],
    },
    // ============================================
    // SPAM/MISLEADING PATTERNS
    // ============================================
    {
        id: 'cm-spam-001',
        pattern: '\\b(scam|phishing)\\s+(email|message|website|link)\\b|\\b(write|create)\\s+(a\\s+)?scam\\b',
        category: 'spam_misleading',
        confidence: 0.85,
        severity: 0.7,
        description: 'Scam/phishing content creation',
        recommended_action: 'BLOCK',
        tags: ['fraud', 'scam'],
    },
    {
        id: 'cm-spam-002',
        pattern: '\\b(impersonate|pretend\\s+to\\s+be)\\s+(a\\s+)?(celebrity|official|authority|doctor|lawyer)\\b',
        category: 'spam_misleading',
        confidence: 0.75,
        severity: 0.65,
        description: 'Identity impersonation',
        recommended_action: 'FLAG',
        tags: ['fraud', 'impersonation'],
    },
    // ============================================
    // MISINFORMATION PATTERNS
    // ============================================
    {
        id: 'cm-misinfo-001',
        pattern: '\\b(vaccines?\\s+(cause|causes)\\s+autism)|(covid|coronavirus)\\s+(is|was)\\s+(a\\s+)?(hoax|fake|planned)\\b',
        category: 'misinformation',
        confidence: 0.85,
        severity: 0.7,
        description: 'Health misinformation',
        recommended_action: 'FLAG',
        tags: ['health', 'conspiracy'],
    },
    {
        id: 'cm-misinfo-002',
        pattern: '\\b(election|vote)\\s+(was\\s+)?(stolen|rigged|fraud)\\b|\\bvoter\\s+fraud\\s+proof\\b',
        category: 'misinformation',
        confidence: 0.7,
        severity: 0.6,
        description: 'Election misinformation',
        recommended_action: 'FLAG',
        tags: ['political', 'conspiracy'],
    },
    {
        id: 'cm-misinfo-003',
        pattern: '\\b(write|create|generate)\\s+(fake|false|misleading)\\s+(news|article|report|story)\\b',
        category: 'misinformation',
        confidence: 0.85,
        severity: 0.7,
        description: 'Fake news generation request',
        recommended_action: 'BLOCK',
        tags: ['fake-news'],
    },
];
/**
 * Get patterns for specific categories
 */
export function getPatternsForCategories(categories) {
    return MODERATION_PATTERNS.filter((p) => categories.includes(p.category));
}
/**
 * Get all patterns
 */
export function getAllPatterns() {
    return MODERATION_PATTERNS;
}
/**
 * Get pattern by ID
 */
export function getPatternById(id) {
    return MODERATION_PATTERNS.find((p) => p.id === id);
}
/**
 * Pattern count by category
 */
export function getPatternCountByCategory() {
    const counts = {};
    for (const pattern of MODERATION_PATTERNS) {
        counts[pattern.category] = (counts[pattern.category] || 0) + 1;
    }
    return counts;
}
//# sourceMappingURL=patterns.js.map