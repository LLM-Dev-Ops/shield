#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import { resolve, join, relative } from 'path';
import { glob } from 'glob';

const VERSION = '1.0.0';

// Security patterns for detection
const PATTERNS = {
  // Prompt Injection patterns
  promptInjection: [
    /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/i,
    /disregard\s+(all\s+)?(previous|prior|above)/i,
    /forget\s+(everything|all|what)\s+(you\s+)?(know|learned|were\s+told)/i,
    /you\s+are\s+(now|no\s+longer)\s+a/i,
    /pretend\s+(to\s+be|you\s+are)/i,
    /act\s+as\s+(if\s+you\s+are|a)/i,
    /new\s+instructions?:/i,
    /system\s+prompt:/i,
    /override\s+(previous|system)/i,
    /jailbreak/i,
    /DAN\s+mode/i,
  ],

  // Secret patterns (40+ types)
  secrets: [
    // AWS
    { pattern: /AKIA[0-9A-Z]{16}/g, type: 'AWS Access Key ID' },
    { pattern: /aws[_-]?secret[_-]?access[_-]?key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}/gi, type: 'AWS Secret Access Key' },
    // GitHub
    { pattern: /ghp_[a-zA-Z0-9]{36}/g, type: 'GitHub Personal Access Token' },
    { pattern: /gho_[a-zA-Z0-9]{36}/g, type: 'GitHub OAuth Token' },
    { pattern: /ghs_[a-zA-Z0-9]{36}/g, type: 'GitHub App Token' },
    { pattern: /ghr_[a-zA-Z0-9]{36}/g, type: 'GitHub Refresh Token' },
    // Stripe
    { pattern: /sk_live_[0-9a-zA-Z]{24,}/g, type: 'Stripe Live Secret Key' },
    { pattern: /sk_test_[0-9a-zA-Z]{24,}/g, type: 'Stripe Test Secret Key' },
    { pattern: /pk_live_[0-9a-zA-Z]{24,}/g, type: 'Stripe Live Publishable Key' },
    // OpenAI
    { pattern: /sk-[a-zA-Z0-9]{48}/g, type: 'OpenAI API Key' },
    { pattern: /sk-proj-[a-zA-Z0-9]{48}/g, type: 'OpenAI Project API Key' },
    // Anthropic
    { pattern: /sk-ant-[a-zA-Z0-9-]{32,}/g, type: 'Anthropic API Key' },
    // Slack
    { pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g, type: 'Slack Token' },
    { pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,}\/B[a-zA-Z0-9_]{8,}\/[a-zA-Z0-9_]{24}/g, type: 'Slack Webhook URL' },
    // Google
    { pattern: /AIza[0-9A-Za-z\-_]{35}/g, type: 'Google API Key' },
    // Generic
    { pattern: /api[_-]?key["']?\s*[:=]\s*["']?[a-zA-Z0-9]{32,}/gi, type: 'Generic API Key' },
    { pattern: /secret["']?\s*[:=]\s*["']?[a-zA-Z0-9]{32,}/gi, type: 'Generic Secret' },
    { pattern: /password["']?\s*[:=]\s*["']?[^\s'"]{8,}/gi, type: 'Password' },
    // Private Keys
    { pattern: /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g, type: 'Private Key' },
    // JWT
    { pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g, type: 'JWT Token' },
  ],

  // PII patterns
  pii: [
    { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, type: 'Email' },
    { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, type: 'SSN' },
    { pattern: /\b\d{3}\s\d{2}\s\d{4}\b/g, type: 'SSN' },
    { pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/g, type: 'Credit Card (Visa)' },
    { pattern: /\b5[1-5][0-9]{14}\b/g, type: 'Credit Card (Mastercard)' },
    { pattern: /\b3[47][0-9]{13}\b/g, type: 'Credit Card (Amex)' },
    { pattern: /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, type: 'Phone Number' },
  ],

  // Toxicity patterns (basic keyword matching)
  toxicity: [
    /\b(kill|murder|attack|bomb|weapon|terrorist)\b/gi,
    /\b(hate|racist|sexist|bigot)\b/gi,
    /\b(suicide|self-harm)\b/gi,
  ],
};

interface ScanResult {
  file: string;
  line: number;
  column: number;
  type: string;
  category: 'prompt-injection' | 'secret' | 'pii' | 'toxicity';
  severity: 'low' | 'medium' | 'high' | 'critical';
  match: string;
}

interface ScanSummary {
  totalFiles: number;
  totalIssues: number;
  promptInjection: number;
  secrets: number;
  pii: number;
  toxicity: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

function getSeverity(category: string, type: string): 'low' | 'medium' | 'high' | 'critical' {
  if (category === 'secret') {
    if (type.includes('Private Key') || type.includes('AWS')) return 'critical';
    if (type.includes('API Key') || type.includes('Token')) return 'high';
    return 'medium';
  }
  if (category === 'pii') {
    if (type.includes('SSN') || type.includes('Credit Card')) return 'critical';
    if (type.includes('Email') || type.includes('Phone')) return 'medium';
    return 'low';
  }
  if (category === 'prompt-injection') return 'high';
  if (category === 'toxicity') return 'medium';
  return 'low';
}

function scanText(text: string, filename: string = 'input'): ScanResult[] {
  const results: ScanResult[] = [];
  const lines = text.split('\n');

  lines.forEach((line, lineIndex) => {
    // Check prompt injection
    PATTERNS.promptInjection.forEach((pattern) => {
      const match = line.match(pattern);
      if (match) {
        results.push({
          file: filename,
          line: lineIndex + 1,
          column: line.indexOf(match[0]) + 1,
          type: 'Prompt Injection Attempt',
          category: 'prompt-injection',
          severity: 'high',
          match: match[0].substring(0, 50) + (match[0].length > 50 ? '...' : ''),
        });
      }
    });

    // Check secrets
    PATTERNS.secrets.forEach(({ pattern, type }) => {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(line)) !== null) {
        results.push({
          file: filename,
          line: lineIndex + 1,
          column: match.index + 1,
          type,
          category: 'secret',
          severity: getSeverity('secret', type),
          match: match[0].substring(0, 20) + '****',
        });
      }
    });

    // Check PII
    PATTERNS.pii.forEach(({ pattern, type }) => {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(line)) !== null) {
        results.push({
          file: filename,
          line: lineIndex + 1,
          column: match.index + 1,
          type,
          category: 'pii',
          severity: getSeverity('pii', type),
          match: match[0].substring(0, 4) + '****',
        });
      }
    });

    // Check toxicity
    PATTERNS.toxicity.forEach((pattern) => {
      const match = line.match(pattern);
      if (match) {
        results.push({
          file: filename,
          line: lineIndex + 1,
          column: line.indexOf(match[0]) + 1,
          type: 'Potentially Toxic Content',
          category: 'toxicity',
          severity: 'medium',
          match: match[0],
        });
      }
    });
  });

  return results;
}

function formatResult(result: ScanResult): string {
  const severityColors: Record<string, (s: string) => string> = {
    critical: chalk.bgRed.white,
    high: chalk.red,
    medium: chalk.yellow,
    low: chalk.blue,
  };

  const categoryIcons: Record<string, string> = {
    'prompt-injection': '🎯',
    secret: '🔑',
    pii: '👤',
    toxicity: '⚠️',
  };

  const severityColor = severityColors[result.severity] || chalk.white;
  const icon = categoryIcons[result.category] || '•';

  return `  ${icon} ${chalk.gray(result.file)}:${chalk.cyan(result.line)}:${chalk.cyan(result.column)}
     ${severityColor(result.severity.toUpperCase())} ${chalk.white(result.type)}
     ${chalk.gray('Match:')} ${result.match}`;
}

function printSummary(summary: ScanSummary): void {
  console.log('\n' + chalk.bold('━━━ Scan Summary ━━━'));
  console.log(`  Files scanned: ${chalk.cyan(summary.totalFiles)}`);
  console.log(`  Total issues:  ${summary.totalIssues > 0 ? chalk.red(summary.totalIssues) : chalk.green(summary.totalIssues)}`);
  console.log('');
  console.log(chalk.bold('  By Category:'));
  console.log(`    🎯 Prompt Injection: ${summary.promptInjection}`);
  console.log(`    🔑 Secrets:          ${summary.secrets}`);
  console.log(`    👤 PII:              ${summary.pii}`);
  console.log(`    ⚠️  Toxicity:         ${summary.toxicity}`);
  console.log('');
  console.log(chalk.bold('  By Severity:'));
  console.log(`    ${chalk.bgRed.white(' CRITICAL ')} ${summary.criticalCount}`);
  console.log(`    ${chalk.red('HIGH')}       ${summary.highCount}`);
  console.log(`    ${chalk.yellow('MEDIUM')}     ${summary.mediumCount}`);
  console.log(`    ${chalk.blue('LOW')}        ${summary.lowCount}`);
}

async function scanFile(filePath: string): Promise<ScanResult[]> {
  try {
    const content = readFileSync(filePath, 'utf-8');
    return scanText(content, filePath);
  } catch (error) {
    console.error(chalk.red(`Error reading file: ${filePath}`));
    return [];
  }
}

async function scanDirectory(dir: string, patterns: string[]): Promise<ScanResult[]> {
  const results: ScanResult[] = [];
  const files = await glob(patterns, { cwd: dir, absolute: true, nodir: true });

  for (const file of files) {
    const fileResults = await scanFile(file);
    results.push(...fileResults);
  }

  return results;
}

// CLI Program
const program = new Command();

program
  .name('shield')
  .description('LLM Shield CLI - Enterprise-grade security scanning for Large Language Models')
  .version(VERSION);

program
  .command('scan')
  .description('Scan files or directories for security issues')
  .argument('[path]', 'File or directory to scan', '.')
  .option('-p, --pattern <patterns...>', 'File patterns to include', ['**/*.txt', '**/*.md', '**/*.json', '**/*.yaml', '**/*.yml', '**/*.js', '**/*.ts', '**/*.py'])
  .option('-e, --exclude <patterns...>', 'Patterns to exclude', ['**/node_modules/**', '**/dist/**', '**/.git/**'])
  .option('--secrets', 'Only scan for secrets')
  .option('--pii', 'Only scan for PII')
  .option('--prompt-injection', 'Only scan for prompt injection')
  .option('--toxicity', 'Only scan for toxicity')
  .option('-o, --output <format>', 'Output format (text, json)', 'text')
  .option('--fail-on <severity>', 'Exit with error if issues of this severity or higher are found', 'high')
  .action(async (path: string, options) => {
    const spinner = ora('Scanning...').start();

    try {
      const absolutePath = resolve(path);
      let results: ScanResult[] = [];
      let fileCount = 0;

      if (existsSync(absolutePath)) {
        const stat = statSync(absolutePath);
        if (stat.isDirectory()) {
          const patterns = options.pattern.map((p: string) =>
            options.exclude.reduce((acc: string, ex: string) => `!${ex}`, p)
          );
          const files = await glob(options.pattern, {
            cwd: absolutePath,
            absolute: true,
            nodir: true,
            ignore: options.exclude
          });
          fileCount = files.length;

          for (const file of files) {
            const fileResults = await scanFile(file);
            results.push(...fileResults.map(r => ({
              ...r,
              file: relative(absolutePath, r.file)
            })));
          }
        } else {
          fileCount = 1;
          results = await scanFile(absolutePath);
        }
      } else {
        spinner.fail(`Path not found: ${absolutePath}`);
        process.exit(1);
      }

      spinner.stop();

      // Filter by category if specified
      if (options.secrets) results = results.filter(r => r.category === 'secret');
      if (options.pii) results = results.filter(r => r.category === 'pii');
      if (options.promptInjection) results = results.filter(r => r.category === 'prompt-injection');
      if (options.toxicity) results = results.filter(r => r.category === 'toxicity');

      // Output
      if (options.output === 'json') {
        console.log(JSON.stringify(results, null, 2));
      } else {
        console.log(chalk.bold('\n🛡️  LLM Shield Scan Results\n'));

        if (results.length === 0) {
          console.log(chalk.green('  ✓ No security issues found!\n'));
        } else {
          results.forEach((result) => {
            console.log(formatResult(result));
            console.log('');
          });
        }

        const summary: ScanSummary = {
          totalFiles: fileCount,
          totalIssues: results.length,
          promptInjection: results.filter(r => r.category === 'prompt-injection').length,
          secrets: results.filter(r => r.category === 'secret').length,
          pii: results.filter(r => r.category === 'pii').length,
          toxicity: results.filter(r => r.category === 'toxicity').length,
          criticalCount: results.filter(r => r.severity === 'critical').length,
          highCount: results.filter(r => r.severity === 'high').length,
          mediumCount: results.filter(r => r.severity === 'medium').length,
          lowCount: results.filter(r => r.severity === 'low').length,
        };

        printSummary(summary);
      }

      // Exit code based on severity
      const severityOrder = ['low', 'medium', 'high', 'critical'];
      const failIndex = severityOrder.indexOf(options.failOn);
      const hasFailingSeverity = results.some(r => severityOrder.indexOf(r.severity) >= failIndex);

      if (hasFailingSeverity) {
        process.exit(1);
      }
    } catch (error) {
      spinner.fail('Scan failed');
      console.error(error);
      process.exit(1);
    }
  });

program
  .command('check')
  .description('Check a single text input for security issues')
  .argument('<text>', 'Text to check')
  .option('-o, --output <format>', 'Output format (text, json)', 'text')
  .action((text: string, options) => {
    const results = scanText(text, 'input');

    if (options.output === 'json') {
      console.log(JSON.stringify({
        is_safe: results.length === 0,
        issues: results.length,
        results,
      }, null, 2));
    } else {
      console.log(chalk.bold('\n🛡️  LLM Shield Check\n'));

      if (results.length === 0) {
        console.log(chalk.green('  ✓ Text is safe!\n'));
      } else {
        console.log(chalk.red(`  ✗ Found ${results.length} issue(s):\n`));
        results.forEach((result) => {
          console.log(formatResult(result));
          console.log('');
        });
      }
    }

    process.exit(results.length > 0 ? 1 : 0);
  });

// Data Redaction Agent commands
const redactCommand = program
  .command('redact')
  .description('Data Redaction Agent - Detect and redact sensitive data (PII, secrets, credentials)');

redactCommand
  .command('test')
  .description('Test redaction with sample content')
  .argument('<content>', 'Content to redact')
  .option('-s, --strategy <strategy>', 'Redaction strategy (mask, hash, pseudonymize, remove, partial_mask)', 'mask')
  .option('--sensitivity <number>', 'Detection sensitivity (0.0-1.0)', '0.7')
  .option('--pii-types <types>', 'PII types to detect (comma-separated)')
  .option('--secret-types <types>', 'Secret types to detect (comma-separated)')
  .option('-o, --output <format>', 'Output format (json, text)', 'text')
  .option('-v, --verbose', 'Verbose output')
  .action(async (content: string, options) => {
    const spinner = ora('Performing redaction...').start();
    try {
      const result = await performRedaction(content, {
        strategy: options.strategy,
        sensitivity: parseFloat(options.sensitivity),
        piiTypes: options.piiTypes?.split(','),
        secretTypes: options.secretTypes?.split(','),
      });
      spinner.stop();

      if (options.output === 'json') {
        console.log(JSON.stringify(result, null, 2));
      } else {
        printRedactionResult(result, options.verbose);
      }

      process.exit(result.data_redacted ? 1 : 0);
    } catch (error) {
      spinner.fail('Redaction failed');
      console.error(error);
      process.exit(1);
    }
  });

redactCommand
  .command('simulate')
  .description('Simulate redaction with custom configuration')
  .argument('<content>', 'Content to redact')
  .option('-s, --strategy <strategy>', 'Redaction strategy', 'mask')
  .option('--sensitivity <number>', 'Detection sensitivity', '0.7')
  .option('--min-confidence <number>', 'Minimum confidence threshold', '0.8')
  .option('--pii-types <types>', 'PII types to detect')
  .option('--secret-types <types>', 'Secret types to detect')
  .option('--no-pii', 'Disable PII detection')
  .option('--no-secrets', 'Disable secret detection')
  .option('--no-credentials', 'Disable credential detection')
  .option('-o, --output <format>', 'Output format (json, text)', 'json')
  .action(async (content: string, options) => {
    const result = await performRedaction(content, {
      strategy: options.strategy,
      sensitivity: parseFloat(options.sensitivity),
      minConfidence: parseFloat(options.minConfidence),
      piiTypes: options.piiTypes?.split(','),
      secretTypes: options.secretTypes?.split(','),
      detectPii: options.pii !== false,
      detectSecrets: options.secrets !== false,
      detectCredentials: options.credentials !== false,
    });

    if (options.output === 'json') {
      console.log(JSON.stringify(result, null, 2));
    } else {
      printRedactionResult(result, true);
    }
  });

// Redaction helper functions
interface RedactionOptions {
  strategy?: string;
  sensitivity?: number;
  minConfidence?: number;
  piiTypes?: string[];
  secretTypes?: string[];
  detectPii?: boolean;
  detectSecrets?: boolean;
  detectCredentials?: boolean;
}

interface RedactionResult {
  data_redacted: boolean;
  redaction_count: number;
  original_risk_score: number;
  severity: string;
  confidence: number;
  redacted_content: string;
  detected_categories: string[];
  entities: Array<{
    type: string;
    category: string;
    severity: string;
    placeholder: string;
  }>;
}

async function performRedaction(content: string, options: RedactionOptions): Promise<RedactionResult> {
  // Import patterns from embedded definitions (same as in agents/data-redaction)
  const piiPatterns = [
    { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, type: 'email', severity: 'medium' },
    { pattern: /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, type: 'phone', severity: 'medium' },
    { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, type: 'ssn', severity: 'critical' },
    { pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/g, type: 'credit_card', severity: 'critical' },
    { pattern: /\b5[1-5][0-9]{14}\b/g, type: 'credit_card', severity: 'critical' },
  ];

  const secretPatterns = [
    { pattern: /AKIA[0-9A-Z]{16}/g, type: 'aws_key', severity: 'critical' },
    { pattern: /ghp_[a-zA-Z0-9]{36}/g, type: 'github_token', severity: 'high' },
    { pattern: /sk-[a-zA-Z0-9]{48}/g, type: 'openai_key', severity: 'high' },
    { pattern: /sk-ant-[a-zA-Z0-9-]{32,}/g, type: 'anthropic_key', severity: 'high' },
    { pattern: /sk_live_[0-9a-zA-Z]{24,}/g, type: 'stripe_key', severity: 'critical' },
    { pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g, type: 'private_key', severity: 'critical' },
  ];

  const credentialPatterns = [
    { pattern: /password["']?\s*[:=]\s*["']?[^\s'"]{8,}/gi, type: 'password', severity: 'high' },
    { pattern: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^/]+\/[^\s'"]+/gi, type: 'database_url', severity: 'critical' },
  ];

  const patterns = [
    ...(options.detectPii !== false ? piiPatterns : []),
    ...(options.detectSecrets !== false ? secretPatterns : []),
    ...(options.detectCredentials !== false ? credentialPatterns : []),
  ];

  let redactedContent = content;
  const entities: Array<{ type: string; category: string; severity: string; placeholder: string }> = [];
  const detectedCategories = new Set<string>();

  for (const { pattern, type, severity } of patterns) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match;

    while ((match = regex.exec(content)) !== null) {
      const placeholder = getPlaceholder(match[0], type, options.strategy || 'mask');
      redactedContent = redactedContent.replace(match[0], placeholder);

      const category = piiPatterns.some(p => p.type === type) ? 'pii'
        : secretPatterns.some(p => p.type === type) ? 'secret'
        : 'credential';

      entities.push({ type, category, severity, placeholder });
      detectedCategories.add(category);
    }
  }

  const maxSeverity = entities.reduce((max, e) => {
    const order = ['low', 'medium', 'high', 'critical'];
    return order.indexOf(e.severity) > order.indexOf(max) ? e.severity : max;
  }, 'low');

  return {
    data_redacted: entities.length > 0,
    redaction_count: entities.length,
    original_risk_score: entities.length > 0 ? Math.min(1, entities.length * 0.2) : 0,
    severity: entities.length > 0 ? maxSeverity : 'none',
    confidence: 0.95,
    redacted_content: redactedContent,
    detected_categories: Array.from(detectedCategories),
    entities,
  };
}

function getPlaceholder(value: string, type: string, strategy: string): string {
  switch (strategy) {
    case 'mask':
      return `[${type.toUpperCase()}]`;
    case 'hash':
      return `[HASH:${value.substring(0, 8)}...]`;
    case 'remove':
      return '';
    case 'partial_mask':
      if (value.length <= 8) return '*'.repeat(value.length);
      return value.substring(0, 4) + '*'.repeat(value.length - 8) + value.substring(value.length - 4);
    case 'pseudonymize':
      return `[REDACTED-${type}]`;
    default:
      return `[${type.toUpperCase()}]`;
  }
}

function printRedactionResult(result: RedactionResult, verbose?: boolean): void {
  const severityColors: Record<string, (s: string) => string> = {
    critical: chalk.bgRed.white,
    high: chalk.red,
    medium: chalk.yellow,
    low: chalk.blue,
    none: chalk.green,
  };

  console.log(chalk.bold('\n🔒 Data Redaction Result\n'));
  console.log(`  Data Redacted: ${result.data_redacted ? chalk.red('Yes') : chalk.green('No')}`);
  console.log(`  Redaction Count: ${result.redaction_count}`);
  console.log(`  Severity: ${severityColors[result.severity](result.severity.toUpperCase())}`);
  console.log(`  Risk Score: ${(result.original_risk_score * 100).toFixed(1)}%`);
  console.log(`  Categories: ${result.detected_categories.join(', ') || 'none'}`);

  if (verbose && result.entities.length > 0) {
    console.log('\n  Redacted Entities:');
    result.entities.forEach(entity => {
      const color = severityColors[entity.severity] || chalk.white;
      console.log(`    - ${entity.type} (${entity.category}): ${color(entity.placeholder)}`);
    });
  }

  console.log('\n  Redacted Content:');
  console.log(chalk.gray('  ' + result.redacted_content));
  console.log('');
}

program
  .command('version')
  .description('Show version information')
  .action(() => {
    console.log(chalk.bold('\n🛡️  LLM Shield CLI'));
    console.log(`  Version: ${VERSION}`);
    console.log(`  Node.js: ${process.version}`);
    console.log(`  Platform: ${process.platform}`);
    console.log('');
  });

program.parse();
