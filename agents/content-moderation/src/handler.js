/**
 * @module handler
 * @description Google Cloud Edge Function handler for Content Moderation Agent
 *
 * This handler is deployed as part of the LLM-Shield unified GCP service.
 * It provides HTTP endpoints for agent invocation.
 */
import { randomUUID } from 'crypto';
import { CliInvocation as CliInvocationSchema, } from '@llm-shield/agentics-contracts';
import { createAgent, AGENT_IDENTITY } from './agent.js';
import { MODERATION_PATTERNS, getPatternCountByCategory, MODERATION_CATEGORIES } from './patterns.js';
/**
 * Create JSON response helper
 */
function jsonResponse(body, status = 200) {
    return {
        status,
        headers: {
            'Content-Type': 'application/json',
            'X-Agent-ID': AGENT_IDENTITY.agent_id,
            'X-Agent-Version': AGENT_IDENTITY.agent_version,
            'X-Agent-Classification': AGENT_IDENTITY.classification,
        },
        body,
    };
}
/**
 * Create error response helper
 */
function errorResponse(code, message, status, details) {
    const error = {
        code,
        message,
        agent: AGENT_IDENTITY,
        timestamp: new Date().toISOString(),
        details,
    };
    return jsonResponse(error, status);
}
/**
 * Edge Function handler
 *
 * Endpoints:
 * - POST /moderate - Execute moderation on content
 * - POST /cli - CLI invocation (test/simulate/inspect)
 * - GET /health - Health check
 * - GET /info - Agent information
 */
export async function handler(request) {
    const url = new URL(request.url, 'http://localhost');
    const path = url.pathname;
    try {
        // Route based on path
        switch (true) {
            case path === '/moderate' && request.method === 'POST':
                return await handleModerate(request);
            case path === '/cli' && request.method === 'POST':
                return await handleCli(request);
            case path === '/health' && request.method === 'GET':
                return handleHealth();
            case path === '/info' && request.method === 'GET':
                return handleInfo();
            default:
                return errorResponse('INVALID_INPUT', `Unknown endpoint: ${request.method} ${path}`, 404);
        }
    }
    catch (error) {
        // Handle validation errors from agent
        if (isAgentError(error)) {
            return jsonResponse(error, 400);
        }
        // Handle unexpected errors
        console.error('[Handler] Unexpected error:', error);
        return errorResponse('INTERNAL_ERROR', error instanceof Error ? error.message : 'Unknown error', 500);
    }
}
/**
 * Handle moderation request
 */
async function handleModerate(request) {
    const agent = createAgent();
    try {
        // Parse and validate input
        const rawInput = await request.json();
        const input = agent.validateInput(rawInput);
        // Execute moderation
        const output = await agent.moderate(input);
        return jsonResponse(output, 200);
    }
    finally {
        await agent.shutdown();
    }
}
/**
 * Handle CLI invocation
 */
async function handleCli(request) {
    const rawInput = await request.json();
    const parseResult = CliInvocationSchema.safeParse(rawInput);
    if (!parseResult.success) {
        return errorResponse('VALIDATION_FAILED', 'Invalid CLI invocation', 400, {
            errors: parseResult.error.errors,
        });
    }
    const cli = parseResult.data;
    const agent = createAgent();
    try {
        switch (cli.mode) {
            case 'test':
                return await handleCliTest(agent, cli);
            case 'simulate':
                return await handleCliSimulate(agent, cli);
            case 'inspect':
                return handleCliInspect(cli);
            default:
                return errorResponse('INVALID_INPUT', `Unknown CLI mode: ${cli.mode}`, 400);
        }
    }
    finally {
        await agent.shutdown();
    }
}
/**
 * Handle CLI test mode
 */
async function handleCliTest(agent, cli) {
    const input = {
        content: cli.content,
        context: {
            execution_ref: randomUUID(),
            timestamp: new Date().toISOString(),
            content_source: 'user_input',
        },
        sensitivity: cli.config?.sensitivity ?? 0.7,
        moderate_categories: cli.config?.categories,
        default_action: cli.config?.default_action ?? 'BLOCK',
        user_age_verified: cli.config?.age_verified ?? false,
    };
    const validatedInput = agent.validateInput(input);
    const output = await agent.moderate(validatedInput);
    return formatCliOutput(output, cli.format, cli.verbose);
}
/**
 * Handle CLI simulate mode
 */
async function handleCliSimulate(agent, cli) {
    // Simulate mode - same as test but marks as simulation
    const input = {
        content: cli.content,
        context: {
            execution_ref: randomUUID(),
            timestamp: new Date().toISOString(),
            content_source: 'user_input',
            metadata: { simulation: true },
        },
        sensitivity: cli.config?.sensitivity ?? 0.7,
        moderate_categories: cli.config?.categories,
        default_action: cli.config?.default_action ?? 'BLOCK',
        user_age_verified: cli.config?.age_verified ?? false,
    };
    const validatedInput = agent.validateInput(input);
    const output = await agent.moderate(validatedInput);
    return formatCliOutput(output, cli.format, cli.verbose);
}
/**
 * Handle CLI inspect mode
 */
function handleCliInspect(cli) {
    // Inspect mode returns agent metadata and configuration
    const inspectData = {
        agent: AGENT_IDENTITY,
        patterns: {
            total: MODERATION_PATTERNS.length,
            by_category: getPatternCountByCategory(),
        },
        categories: MODERATION_CATEGORIES,
        configuration: {
            default_sensitivity: 0.7,
            default_action: 'BLOCK',
            min_moderation_confidence: 0.8,
            telemetry_enabled: process.env.TELEMETRY_ENABLED !== 'false',
            ruvector_url: process.env.RUVECTOR_SERVICE_URL || 'http://localhost:8080',
        },
        invocation: {
            content_preview: cli.content.substring(0, 50) + (cli.content.length > 50 ? '...' : ''),
            config: cli.config,
        },
    };
    return formatCliOutput(inspectData, cli.format, cli.verbose);
}
/**
 * Format CLI output based on format preference
 */
function formatCliOutput(data, format, verbose) {
    switch (format) {
        case 'json':
            return jsonResponse(data);
        case 'text':
            return jsonResponse({
                format: 'text',
                output: formatAsText(data, verbose),
            });
        case 'table':
            return jsonResponse({
                format: 'table',
                output: formatAsTable(data, verbose),
            });
        default:
            return jsonResponse(data);
    }
}
/**
 * Format output as human-readable text
 */
function formatAsText(data, verbose) {
    const output = data;
    if (!output.result) {
        return JSON.stringify(data, null, 2);
    }
    const lines = [
        `=== Content Moderation Results ===`,
        ``,
        `Decision: ${output.result.allowed ? 'ALLOWED' : 'BLOCKED'}`,
        `Action: ${output.result.action}`,
        `Violations Detected: ${output.result.violations_detected ? 'YES' : 'NO'}`,
        `Risk Score: ${(output.result.risk_score * 100).toFixed(1)}%`,
        `Severity: ${output.result.severity.toUpperCase()}`,
        `Confidence: ${(output.result.confidence * 100).toFixed(1)}%`,
        `Pattern Matches: ${output.result.pattern_match_count}`,
        `Requires Human Review: ${output.result.requires_human_review ? 'YES' : 'NO'}`,
        `Duration: ${output.duration_ms.toFixed(2)}ms`,
        ``,
        `Reason: ${output.result.decision_reason}`,
    ];
    if (output.result.content_warning) {
        lines.push(``, `Content Warning: ${output.result.content_warning}`);
    }
    if (output.result.violated_categories.length > 0) {
        lines.push(``, `Violated Categories: ${output.result.violated_categories.join(', ')}`);
    }
    if (verbose && output.result.violations.length > 0) {
        lines.push(``, `--- Violations ---`);
        for (const violation of output.result.violations) {
            lines.push(`  [${violation.pattern_id}] ${violation.category} - ${violation.description}`, `    Confidence: ${(violation.confidence * 100).toFixed(0)}%, Severity: ${violation.severity}, Action: ${violation.recommended_action}`);
        }
    }
    if (verbose && output.result.risk_factors.length > 0) {
        lines.push(``, `--- Risk Factors ---`);
        for (const factor of output.result.risk_factors) {
            lines.push(`  ${factor.category}: ${factor.description} (${factor.severity})`);
        }
    }
    return lines.join('\n');
}
/**
 * Format output as table
 */
function formatAsTable(data, verbose) {
    const output = data;
    if (!output.result) {
        return JSON.stringify(data, null, 2);
    }
    const decisionEmoji = output.result.allowed ? '✓' : '✗';
    const decisionText = output.result.allowed ? 'ALLOWED' : 'BLOCKED';
    const lines = [
        `┌─────────────────────────────────────────────────────────┐`,
        `│ CONTENT MODERATION RESULTS                             │`,
        `├─────────────────────────────────────────────────────────┤`,
        `│ Decision         │ ${(decisionEmoji + ' ' + decisionText).padEnd(37)} │`,
        `│ Action           │ ${output.result.action.padEnd(37)} │`,
        `│ Violations       │ ${String(output.result.violations.length).padEnd(37)} │`,
        `│ Risk Score       │ ${((output.result.risk_score * 100).toFixed(1) + '%').padEnd(37)} │`,
        `│ Severity         │ ${output.result.severity.toUpperCase().padEnd(37)} │`,
        `│ Confidence       │ ${((output.result.confidence * 100).toFixed(1) + '%').padEnd(37)} │`,
        `│ Human Review     │ ${(output.result.requires_human_review ? 'Required' : 'Not Required').padEnd(37)} │`,
        `│ Duration         │ ${(output.duration_ms.toFixed(2) + 'ms').padEnd(37)} │`,
        `└─────────────────────────────────────────────────────────┘`,
    ];
    if (output.result.content_warning) {
        lines.push(``);
        lines.push(`⚠️  Warning: ${output.result.content_warning}`);
    }
    if (verbose && output.result.violations.length > 0) {
        lines.push(``);
        lines.push(`Violations:`);
        for (const v of output.result.violations) {
            lines.push(`  • [${v.category}] ${v.description.substring(0, 50)}...`);
        }
    }
    return lines.join('\n');
}
/**
 * Handle health check
 */
function handleHealth() {
    return jsonResponse({
        status: 'healthy',
        agent: AGENT_IDENTITY.agent_id,
        version: AGENT_IDENTITY.agent_version,
        classification: AGENT_IDENTITY.classification,
        timestamp: new Date().toISOString(),
    });
}
/**
 * Handle info request
 */
function handleInfo() {
    return jsonResponse({
        agent: AGENT_IDENTITY,
        classification: 'ENFORCEMENT',
        description: 'Applies moderation policies to classify or block disallowed content categories.',
        endpoints: [
            { path: '/moderate', method: 'POST', description: 'Execute content moderation' },
            { path: '/cli', method: 'POST', description: 'CLI invocation' },
            { path: '/health', method: 'GET', description: 'Health check' },
            { path: '/info', method: 'GET', description: 'Agent information' },
        ],
        categories: MODERATION_CATEGORIES,
        pattern_count: MODERATION_PATTERNS.length,
        moderation_actions: ['ALLOW', 'BLOCK', 'FLAG', 'WARN', 'AGE_GATE'],
    });
}
/**
 * Type guard for AgentError
 */
function isAgentError(error) {
    return (typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        'message' in error);
}
/**
 * Export for Google Cloud Functions
 */
export const contentModeration = handler;
//# sourceMappingURL=handler.js.map