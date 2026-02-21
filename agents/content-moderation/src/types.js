/**
 * @module types
 * @description Internal type definitions for Content Moderation Agent
 */
/**
 * Category metadata map
 */
export const CATEGORY_METADATA = {
    adult_content: {
        category: 'adult_content',
        defaultSeverity: 'medium',
        description: 'Adult or sexually explicit material',
        critical: false,
        ageRestrictedAllowed: true,
        defaultWarning: 'This content may contain adult material',
    },
    violence_graphic: {
        category: 'violence_graphic',
        defaultSeverity: 'high',
        description: 'Graphic violence or gore',
        critical: false,
        ageRestrictedAllowed: true,
        defaultWarning: 'This content contains graphic violence',
    },
    hate_discriminatory: {
        category: 'hate_discriminatory',
        defaultSeverity: 'critical',
        description: 'Hate speech or discriminatory content',
        critical: true,
        ageRestrictedAllowed: false,
        defaultWarning: 'This content contains hate speech',
    },
    harassment_bullying: {
        category: 'harassment_bullying',
        defaultSeverity: 'high',
        description: 'Harassment or bullying content',
        critical: false,
        ageRestrictedAllowed: false,
        defaultWarning: 'This content contains harassment',
    },
    spam_misleading: {
        category: 'spam_misleading',
        defaultSeverity: 'low',
        description: 'Spam or misleading content',
        critical: false,
        ageRestrictedAllowed: false,
        defaultWarning: 'This content may be misleading',
    },
    illegal_regulated: {
        category: 'illegal_regulated',
        defaultSeverity: 'critical',
        description: 'Illegal or heavily regulated content',
        critical: true,
        ageRestrictedAllowed: false,
        defaultWarning: 'This content may be illegal',
    },
    self_harm: {
        category: 'self_harm',
        defaultSeverity: 'critical',
        description: 'Self-harm or suicide-related content',
        critical: true,
        ageRestrictedAllowed: false,
        defaultWarning: 'This content discusses self-harm',
    },
    child_safety: {
        category: 'child_safety',
        defaultSeverity: 'critical',
        description: 'Content that endangers children',
        critical: true,
        ageRestrictedAllowed: false,
        defaultWarning: 'Child safety violation',
    },
    terrorism_extremism: {
        category: 'terrorism_extremism',
        defaultSeverity: 'critical',
        description: 'Terrorism or extremist content',
        critical: true,
        ageRestrictedAllowed: false,
        defaultWarning: 'This content promotes terrorism',
    },
    misinformation: {
        category: 'misinformation',
        defaultSeverity: 'medium',
        description: 'Deliberate misinformation or fake news',
        critical: false,
        ageRestrictedAllowed: false,
        defaultWarning: 'This content may contain misinformation',
    },
};
/**
 * Map severity score to severity level
 */
export function scoreToSeverity(score) {
    if (score >= 0.9)
        return 'critical';
    if (score >= 0.7)
        return 'high';
    if (score >= 0.4)
        return 'medium';
    if (score >= 0.1)
        return 'low';
    return 'none';
}
//# sourceMappingURL=types.js.map