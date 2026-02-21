/**
 * @module types
 * @description Internal type definitions for Safety Boundary Agent
 */
/**
 * Category metadata map
 */
export const CATEGORY_METADATA = {
    harmful_content: {
        category: 'harmful_content',
        defaultSeverity: 'high',
        description: 'General harmful or dangerous content',
        critical: false,
    },
    explicit_content: {
        category: 'explicit_content',
        defaultSeverity: 'medium',
        description: 'Adult or sexually explicit material',
        critical: false,
    },
    hate_speech: {
        category: 'hate_speech',
        defaultSeverity: 'critical',
        description: 'Discriminatory or hateful content',
        critical: true,
    },
    violence: {
        category: 'violence',
        defaultSeverity: 'high',
        description: 'Violent or threatening content',
        critical: false,
    },
    self_harm: {
        category: 'self_harm',
        defaultSeverity: 'critical',
        description: 'Self-harm or suicide-related content',
        critical: true,
    },
    illegal_activity: {
        category: 'illegal_activity',
        defaultSeverity: 'critical',
        description: 'Instructions for illegal activities',
        critical: true,
    },
    dangerous_instructions: {
        category: 'dangerous_instructions',
        defaultSeverity: 'high',
        description: 'Dangerous or harmful instructions',
        critical: false,
    },
    deceptive_content: {
        category: 'deceptive_content',
        defaultSeverity: 'medium',
        description: 'Misinformation or deceptive content',
        critical: false,
    },
    privacy_violation: {
        category: 'privacy_violation',
        defaultSeverity: 'high',
        description: 'Content that violates privacy',
        critical: false,
    },
    intellectual_property: {
        category: 'intellectual_property',
        defaultSeverity: 'medium',
        description: 'Copyright or trademark violations',
        critical: false,
    },
};
/**
 * Map severity score to severity level
 */
export function scoreToseverity(score) {
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