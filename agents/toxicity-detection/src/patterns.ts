/**
 * Toxicity Detection Patterns
 *
 * Defines patterns for detecting various categories of toxic content.
 * These patterns are used for heuristic-based detection.
 *
 * IMPORTANT: This file contains examples of toxic language for detection purposes only.
 * These patterns are necessary for content moderation and safety.
 *
 * @module toxicity-detection-agent/patterns
 */

import type { ToxicityPattern } from './types.js';

/**
 * Severe toxicity patterns - strong profanity and slurs
 * Highest severity, high confidence
 */
const SEVERE_TOXIC_PATTERNS: ToxicityPattern[] = [
  {
    id: 'severe-profanity-1',
    category: 'severe_toxic',
    name: 'Severe Profanity',
    keywords: ['f***', 's***', 'a**hole', 'b***h', 'c***'],
    severity: 'critical',
    baseConfidence: 0.95,
  },
  {
    id: 'severe-slur-1',
    category: 'severe_toxic',
    name: 'Racial/Ethnic Slurs',
    keywords: [], // Intentionally empty - use NLP model for slur detection
    pattern: /\b(n[i1]gg[ae3]r?|k[i1]ke|sp[i1]c|ch[i1]nk|g[o0][o0]k)\b/gi,
    severity: 'critical',
    baseConfidence: 0.98,
    caseSensitive: false,
  },
];

/**
 * Threat patterns - violence and intimidation
 */
const THREAT_PATTERNS: ToxicityPattern[] = [
  {
    id: 'threat-kill-1',
    category: 'threat',
    name: 'Death Threats',
    keywords: [
      'kill you',
      'murder you',
      'end your life',
      'you will die',
      "you're dead",
      'going to kill',
      'gonna kill',
    ],
    severity: 'critical',
    baseConfidence: 0.92,
  },
  {
    id: 'threat-harm-1',
    category: 'threat',
    name: 'Physical Harm Threats',
    keywords: [
      'hurt you',
      'beat you',
      'punch you',
      'attack you',
      'destroy you',
      'break your',
      'smash your',
    ],
    severity: 'critical',
    baseConfidence: 0.88,
  },
  {
    id: 'threat-violence-1',
    category: 'threat',
    name: 'General Violence',
    keywords: [
      'watch your back',
      'coming for you',
      "i'll get you",
      'be afraid',
      'you should be scared',
      'regret this',
    ],
    severity: 'high',
    baseConfidence: 0.75,
    contextRequired: ['you', 'your'],
  },
  {
    id: 'threat-weapon-1',
    category: 'threat',
    name: 'Weapon Threats',
    keywords: [
      'shoot you',
      'stab you',
      'bring a gun',
      'knife you',
    ],
    severity: 'critical',
    baseConfidence: 0.95,
  },
];

/**
 * Insult patterns - personal attacks and degradation
 */
const INSULT_PATTERNS: ToxicityPattern[] = [
  {
    id: 'insult-intelligence-1',
    category: 'insult',
    name: 'Intelligence Insults',
    keywords: [
      'idiot',
      'stupid',
      'dumb',
      'moron',
      'imbecile',
      'retard',
      'braindead',
      'brainless',
    ],
    severity: 'medium',
    baseConfidence: 0.75,
  },
  {
    id: 'insult-general-1',
    category: 'insult',
    name: 'General Insults',
    keywords: [
      'loser',
      'pathetic',
      'worthless',
      'useless',
      'garbage',
      'trash',
      'scum',
      'disgrace',
    ],
    severity: 'medium',
    baseConfidence: 0.70,
  },
  {
    id: 'insult-appearance-1',
    category: 'insult',
    name: 'Appearance-Based Insults',
    keywords: [
      'ugly',
      'fat',
      'disgusting',
      'hideous',
      'repulsive',
    ],
    severity: 'medium',
    baseConfidence: 0.65,
    contextRequired: ['you', 'your', "you're", 'look'],
  },
  {
    id: 'insult-incompetence-1',
    category: 'insult',
    name: 'Competence Insults',
    keywords: [
      'incompetent',
      'failure',
      'hopeless',
      'joke',
      'clown',
      'fool',
    ],
    severity: 'medium',
    baseConfidence: 0.70,
  },
];

/**
 * Identity hate patterns - discrimination and bigotry
 */
const IDENTITY_HATE_PATTERNS: ToxicityPattern[] = [
  {
    id: 'hate-racism-1',
    category: 'identity_hate',
    name: 'Racist Statements',
    keywords: [
      'all [race] are',
      '[race] people are',
      'go back to your country',
      'you people',
    ],
    pattern: /\b(racist|racism|race\s+war|white\s+power|white\s+supremac)/gi,
    severity: 'critical',
    baseConfidence: 0.85,
  },
  {
    id: 'hate-sexism-1',
    category: 'identity_hate',
    name: 'Sexist Statements',
    keywords: [
      'women belong in',
      'women should',
      'females are',
      'typical woman',
      'stupid women',
    ],
    severity: 'high',
    baseConfidence: 0.80,
  },
  {
    id: 'hate-homophobia-1',
    category: 'identity_hate',
    name: 'Homophobic Statements',
    keywords: [
      'f*g',
      'f*ggot',
      'homo',
      'gay people are',
      'gays should',
    ],
    severity: 'critical',
    baseConfidence: 0.88,
  },
  {
    id: 'hate-religious-1',
    category: 'identity_hate',
    name: 'Religious Hate',
    keywords: [
      'all muslims',
      'all jews',
      'all christians',
      '[religion] are terrorists',
      '[religion] are evil',
    ],
    severity: 'high',
    baseConfidence: 0.82,
  },
  {
    id: 'hate-xenophobia-1',
    category: 'identity_hate',
    name: 'Xenophobic Statements',
    keywords: [
      'immigrants are',
      'foreigners are',
      'build the wall',
      'close the borders',
      'send them back',
    ],
    severity: 'high',
    baseConfidence: 0.75,
    contextRequired: ['all', 'should', 'need to', 'must'],
  },
];

/**
 * Obscene patterns - vulgar and explicit content
 */
const OBSCENE_PATTERNS: ToxicityPattern[] = [
  {
    id: 'obscene-sexual-1',
    category: 'obscene',
    name: 'Sexual Content',
    keywords: [
      'suck my',
      'blow me',
      'screw you',
      'f*** yourself',
    ],
    severity: 'high',
    baseConfidence: 0.85,
  },
  {
    id: 'obscene-crude-1',
    category: 'obscene',
    name: 'Crude Language',
    keywords: [
      'piece of s***',
      'eat s***',
      'shove it',
      'go to hell',
      'kiss my a**',
    ],
    severity: 'high',
    baseConfidence: 0.80,
  },
];

/**
 * General toxic patterns - catch-all for toxic behavior
 */
const GENERAL_TOXIC_PATTERNS: ToxicityPattern[] = [
  {
    id: 'toxic-hate-1',
    category: 'toxic',
    name: 'Hate Expression',
    keywords: [
      'i hate you',
      'hate your',
      'despise you',
      'cant stand you',
      "can't stand you",
    ],
    severity: 'medium',
    baseConfidence: 0.70,
  },
  {
    id: 'toxic-wish-harm-1',
    category: 'toxic',
    name: 'Wishing Harm',
    keywords: [
      'hope you die',
      'wish you were dead',
      'drop dead',
      'go die',
      'kys',
      'kill yourself',
    ],
    severity: 'critical',
    baseConfidence: 0.95,
  },
  {
    id: 'toxic-dismissive-1',
    category: 'toxic',
    name: 'Toxic Dismissiveness',
    keywords: [
      'shut up',
      'nobody cares',
      'no one asked',
      'stfu',
      'gtfo',
    ],
    severity: 'low',
    baseConfidence: 0.60,
  },
  {
    id: 'toxic-dehumanizing-1',
    category: 'toxic',
    name: 'Dehumanizing Language',
    keywords: [
      'subhuman',
      'less than human',
      'not even human',
      'animal',
      'vermin',
      'cockroach',
    ],
    severity: 'high',
    baseConfidence: 0.85,
    contextRequired: ['you', 'they', 'them', 'people'],
  },
];

/**
 * All toxicity patterns combined
 */
export const TOXICITY_PATTERNS: ToxicityPattern[] = [
  ...SEVERE_TOXIC_PATTERNS,
  ...THREAT_PATTERNS,
  ...INSULT_PATTERNS,
  ...IDENTITY_HATE_PATTERNS,
  ...OBSCENE_PATTERNS,
  ...GENERAL_TOXIC_PATTERNS,
];

/**
 * Get patterns by category
 */
export function getPatternsByCategory(category: string): ToxicityPattern[] {
  return TOXICITY_PATTERNS.filter(p => p.category === category);
}

/**
 * Get all pattern categories
 */
export function getAllCategories(): string[] {
  return [...new Set(TOXICITY_PATTERNS.map(p => p.category))];
}

/**
 * Normalize text for matching (lowercase, remove extra whitespace)
 */
export function normalizeText(text: string): string {
  return text.toLowerCase().replace(/\s+/g, ' ').trim();
}

/**
 * Expand asterisk censoring for matching
 * e.g., "f***" matches "fuck", "f*ck" matches "fuck"
 */
export function expandCensoredPattern(pattern: string): RegExp {
  // Replace asterisks with regex for any characters
  const escaped = pattern
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&') // Escape regex special chars first
    .replace(/\\\*/g, '.'); // Then replace escaped asterisks with .

  return new RegExp(`\\b${escaped}\\b`, 'gi');
}
