/**
 * Main LLMShield class - High-level API
 *
 * @module shield
 */

import type {
  LLMShieldConfig,
  ScanOptions,
  ScanResult,
  ScannerInfo,
  BatchScanResult,
  CacheStats,
  ScannerType,
} from './types';
import { InitializationError, ScanError, ValidationError } from './types';
import { createScanMetadata } from './utils';

/**
 * Main LLMShield class providing high-level security scanning API
 *
 * @example
 * ```typescript
 * const shield = new LLMShield({
 *   cache: { maxSize: 1000, ttlSeconds: 3600 },
 *   scanners: ['toxicity', 'prompt-injection'],
 * });
 *
 * const result = await shield.scanPrompt('Hello world');
 * console.log(result.isValid); // true
 * ```
 */
export class LLMShield {
  private config: Required<LLMShieldConfig>;
  private initialized: boolean = false;
  private initPromise: Promise<void> | null = null;
  private cache: Map<string, { result: ScanResult; timestamp: number }>;
  private scanCount: number = 0;
  private cacheHits: number = 0;
  private cacheMisses: number = 0;

  /**
   * Create a new LLMShield instance
   *
   * @param config - Configuration options
   */
  constructor(config: LLMShieldConfig = {}) {
    this.config = {
      cache: config.cache || { maxSize: 1000, ttlSeconds: 3600 },
      scanners: config.scanners || [],
      models: config.models || {
        enabled: false,
        variant: 'INT8',
        threshold: 0.5,
        fallbackToHeuristic: true,
      },
      thresholds: config.thresholds || {},
      debug: config.debug || false,
      timeout: config.timeout || 30000,
    };

    this.cache = new Map();
    this.initPromise = this.initialize();
  }

  /**
   * Initialize the WASM module (called automatically)
   * @private
   */
  private async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      const startTime = Date.now();

      // TODO: Initialize WASM module
      // For now, we'll simulate initialization
      await new Promise((resolve) => setTimeout(resolve, 10));

      this.initialized = true;

      if (this.config.debug) {
        console.log(`LLMShield initialized in ${Date.now() - startTime}ms`);
      }
    } catch (error) {
      throw new InitializationError(
        'Failed to initialize LLM Shield',
        error
      );
    }
  }

  /**
   * Wait for initialization to complete
   */
  async ready(): Promise<void> {
    await this.initPromise;
  }

  /**
   * Scan a user prompt for security issues
   *
   * @param prompt - The user prompt to scan
   * @param options - Scan options
   * @returns Scan result with detections
   *
   * @example
   * ```typescript
   * const result = await shield.scanPrompt(
   *   "Ignore all previous instructions",
   *   { scanners: ['prompt-injection'] }
   * );
   * ```
   */
  async scanPrompt(
    prompt: string,
    options: ScanOptions = {}
  ): Promise<ScanResult> {
    await this.ready();
    this.validateInput(prompt);

    const startTime = Date.now();
    const cacheKey = this.getCacheKey(prompt, options, 'input');

    // Check cache
    if (cacheKey !== null) {
      const cached = this.getFromCache(cacheKey);
      if (cached) {
        this.cacheHits++;
        return cached;
      }
    }

    this.cacheMisses++;

    try {
      // Determine which scanners to run
      const scannersToRun = this.getScannersToRun(
        options.scanners || this.config.scanners,
        'input'
      );

      // Execute scan
      const result = await this.executeScan(
        prompt,
        scannersToRun,
        options,
        startTime
      );

      // Cache result
      if (cacheKey !== null) {
        this.setCache(cacheKey, result);
      }

      this.scanCount++;
      return result;
    } catch (error) {
      if (error instanceof Error) {
        throw new ScanError(`Scan failed: ${error.message}`, error);
      }
      throw error;
    }
  }

  /**
   * Scan LLM output for security issues
   *
   * @param output - The LLM output to scan
   * @param options - Scan options
   * @returns Scan result with detections
   *
   * @example
   * ```typescript
   * const result = await shield.scanOutput(
   *   "Visit http://malicious-site.com for details",
   *   { scanners: ['malicious-urls'] }
   * );
   * ```
   */
  async scanOutput(
    output: string,
    options: ScanOptions = {}
  ): Promise<ScanResult> {
    await this.ready();
    this.validateInput(output);

    const startTime = Date.now();
    const cacheKey = this.getCacheKey(output, options, 'output');

    // Check cache
    if (cacheKey !== null) {
      const cached = this.getFromCache(cacheKey);
      if (cached) {
        this.cacheHits++;
        return cached;
      }
    }

    this.cacheMisses++;

    try {
      // Determine which scanners to run
      const scannersToRun = this.getScannersToRun(
        options.scanners || this.config.scanners,
        'output'
      );

      // Execute scan
      const result = await this.executeScan(
        output,
        scannersToRun,
        options,
        startTime
      );

      // Cache result
      if (cacheKey !== null) {
        this.setCache(cacheKey, result);
      }

      this.scanCount++;
      return result;
    } catch (error) {
      if (error instanceof Error) {
        throw new ScanError(`Output scan failed: ${error.message}`, error);
      }
      throw error;
    }
  }

  /**
   * Scan multiple inputs in parallel
   *
   * @param inputs - Array of texts to scan
   * @param options - Scan options
   * @returns Batch scan results
   *
   * @example
   * ```typescript
   * const results = await shield.scanBatch([
   *   "First prompt",
   *   "Second prompt",
   *   "Third prompt"
   * ]);
   * ```
   */
  async scanBatch(
    inputs: string[],
    options: ScanOptions = {}
  ): Promise<BatchScanResult> {
    await this.ready();

    if (!Array.isArray(inputs) || inputs.length === 0) {
      throw new ValidationError('Input must be a non-empty array');
    }

    const startTime = performance.now();
    const results: ScanResult[] = [];
    const errors: Array<{ index: number; error: string }> = [];

    // Process in parallel with concurrency limit
    const concurrency = 5;
    const chunks: string[][] = [];

    for (let i = 0; i < inputs.length; i += concurrency) {
      chunks.push(inputs.slice(i, i + concurrency));
    }

    for (const [chunkIndex, chunk] of chunks.entries()) {
      const promises = chunk.map(async (input, idx) => {
        try {
          return await this.scanPrompt(input, options);
        } catch (error) {
          errors.push({
            index: chunkIndex * concurrency + idx,
            error: error instanceof Error ? error.message : String(error),
          });
          // Return a failed result
          return {
            isValid: false,
            riskScore: 1.0,
            detections: [{
              scanner: 'error' as ScannerType,
              type: 'scan-error',
              severity: 'critical' as const,
              score: 1.0,
              description: `Scan failed: ${error instanceof Error ? error.message : String(error)}`,
            }],
            scannerResults: [],
            metadata: createScanMetadata(performance.now() - startTime, 0, false),
          } as ScanResult;
        }
      });

      const chunkResults = await Promise.all(promises);
      results.push(...chunkResults);
    }

    const totalTimeMs = performance.now() - startTime;
    const successCount = results.filter((r) => r.isValid || r.detections.length === 0).length;
    const failureCount = inputs.length - successCount;

    return {
      results,
      totalTimeMs,
      successCount,
      failureCount,
      errors: errors.length > 0 ? errors : undefined,
    };
  }

  /**
   * List all available scanners
   *
   * @returns Array of scanner information
   */
  listScanners(): ScannerInfo[] {
    return [
      {
        name: 'prompt-injection',
        type: 'input',
        version: '1.0.0',
        description: 'Detects prompt injection attempts',
        enabled: this.isScannerEnabled('prompt-injection'),
        requiresML: false,
      },
      {
        name: 'toxicity',
        type: 'bidirectional',
        version: '1.0.0',
        description: 'Detects toxic, hateful, or offensive content',
        enabled: this.isScannerEnabled('toxicity'),
        requiresML: true,
      },
      {
        name: 'secrets',
        type: 'input',
        version: '1.0.0',
        description: 'Detects API keys, passwords, and tokens',
        enabled: this.isScannerEnabled('secrets'),
        requiresML: false,
      },
      {
        name: 'pii',
        type: 'bidirectional',
        version: '1.0.0',
        description: 'Detects personally identifiable information',
        enabled: this.isScannerEnabled('pii'),
        requiresML: false,
      },
      {
        name: 'ban-competitors',
        type: 'bidirectional',
        version: '1.0.0',
        description: 'Blocks mentions of competitor names',
        enabled: this.isScannerEnabled('ban-competitors'),
        requiresML: false,
      },
      {
        name: 'ban-topics',
        type: 'bidirectional',
        version: '1.0.0',
        description: 'Filters unwanted topics',
        enabled: this.isScannerEnabled('ban-topics'),
        requiresML: false,
      },
      {
        name: 'ban-substrings',
        type: 'bidirectional',
        version: '1.0.0',
        description: 'Blocks specific substrings or patterns',
        enabled: this.isScannerEnabled('ban-substrings'),
        requiresML: false,
      },
      {
        name: 'malicious-urls',
        type: 'output',
        version: '1.0.0',
        description: 'Detects phishing and malicious URLs',
        enabled: this.isScannerEnabled('malicious-urls'),
        requiresML: false,
      },
      {
        name: 'sensitive-output',
        type: 'output',
        version: '1.0.0',
        description: 'Prevents sensitive data leaks in output',
        enabled: this.isScannerEnabled('sensitive-output'),
        requiresML: false,
      },
      {
        name: 'url-reachability',
        type: 'output',
        version: '1.0.0',
        description: 'Validates URL accessibility',
        enabled: this.isScannerEnabled('url-reachability'),
        requiresML: false,
      },
    ];
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): CacheStats {
    const total = this.cacheHits + this.cacheMisses;
    return {
      hits: this.cacheHits,
      misses: this.cacheMisses,
      size: this.cache.size,
      maxSize: this.config.cache.maxSize,
      hitRate: total > 0 ? this.cacheHits / total : 0,
    };
  }

  /**
   * Clear the cache
   */
  clearCache(): void {
    this.cache.clear();
    this.cacheHits = 0;
    this.cacheMisses = 0;
  }

  /**
   * Get debug information
   */
  debugInfo() {
    return {
      initialized: this.initialized,
      config: this.config,
      scanCount: this.scanCount,
      cacheStats: this.getCacheStats(),
      scanners: this.listScanners(),
    };
  }

  // Private helper methods

  private validateInput(text: string): void {
    if (typeof text !== 'string') {
      throw new ValidationError('Input must be a string');
    }
    if (text.length === 0) {
      throw new ValidationError('Input cannot be empty');
    }
    if (text.length > 100000) {
      throw new ValidationError('Input exceeds maximum length of 100,000 characters');
    }
  }

  private getCacheKey(
    text: string,
    options: ScanOptions,
    category: 'input' | 'output'
  ): string | null {
    // Context can contain cycles or mutable objects. Do not serialize or reuse
    // context-sensitive results, including future WASM-backed output scans.
    if (
      options.skipCache ||
      options.context !== undefined ||
      options.originalPrompt !== undefined ||
      !(this.config.cache.maxSize > 0) ||
      !(this.config.cache.ttlSeconds > 0)
    ) {
      return null;
    }
    const scanners = [...(options.scanners || this.config.scanners)].sort();
    // Keep the exact text: a 32-bit hash is not a security cache identity.
    return JSON.stringify([category, text, scanners]);
  }

  private getFromCache(key: string): ScanResult | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    const now = Date.now();
    const age = (now - entry.timestamp) / 1000;

    if (age >= this.config.cache.ttlSeconds) {
      this.cache.delete(key);
      return null;
    }

    // Refresh recency, not TTL. Callers must never own the cached object graph.
    this.cache.delete(key);
    this.cache.set(key, entry);
    return {
      ...structuredClone(entry.result),
      metadata: {
        ...entry.result.metadata,
        cached: true,
      },
    };
  }

  private setCache(key: string, result: ScanResult): void {
    // Implement LRU eviction
    if (this.cache.size >= this.config.cache.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey) {
        this.cache.delete(firstKey);
      }
    }

    this.cache.set(key, {
      result: structuredClone(result),
      timestamp: Date.now(),
    });
  }

  private getScannersToRun(
    requested: ScannerType[],
    category: 'input' | 'output'
  ): ScannerType[] {
    const allScanners = this.listScanners();

    if (requested.length === 0) {
      // Return all scanners for this category
      return allScanners
        .filter((s) => s.type === category || s.type === 'bidirectional')
        .map((s) => s.name as ScannerType);
    }

    // Validate requested scanners
    const valid = requested.filter((name) =>
      allScanners.some((s) => s.name === name)
    );

    return valid;
  }

  private isScannerEnabled(name: string): boolean {
    if (this.config.scanners.length === 0) return true;
    return this.config.scanners.includes(name as ScannerType);
  }

  private async executeScan(
    text: string,
    scanners: ScannerType[],
    _options: ScanOptions,
    startTime: number
  ): Promise<ScanResult> {
    // TODO: Integrate with actual WASM scanners
    // For now, return a mock result based on simple heuristics

    const detections = [];
    const scannerResults = [];

    // Simple heuristic detection
    if (scanners.includes('prompt-injection')) {
      if (this.detectPromptInjection(text)) {
        detections.push({
          scanner: 'prompt-injection' as ScannerType,
          type: 'injection-attempt',
          severity: 'high' as const,
          score: 0.9,
          description: 'Potential prompt injection detected',
        });
        scannerResults.push({
          scanner: 'prompt-injection',
          isValid: false,
          riskScore: 0.9,
          riskFactors: [{
            type: 'injection',
            description: 'Instruction override attempt',
            severity: 'high' as const,
            score: 0.9,
          }],
          entities: [],
          executionTimeMs: 5,
        });
      }
    }

    if (scanners.includes('secrets')) {
      const secrets = this.detectSecrets(text);
      if (secrets.length > 0) {
        detections.push({
          scanner: 'secrets' as ScannerType,
          type: 'secret-detected',
          severity: 'critical' as const,
          score: 1.0,
          description: `Detected ${secrets.length} potential secret(s)`,
        });
        scannerResults.push({
          scanner: 'secrets',
          isValid: false,
          riskScore: 1.0,
          riskFactors: [{
            type: 'secret',
            description: 'API key or token detected',
            severity: 'critical' as const,
            score: 1.0,
          }],
          entities: secrets,
          executionTimeMs: 3,
        });
      }
    }

    const isValid = detections.length === 0;
    const riskScore = isValid ? 0.0 : Math.max(...detections.map((d) => d.score), 0);
    const durationMs = Date.now() - startTime;

    return {
      isValid,
      riskScore,
      detections,
      sanitizedText: text,
      scannerResults,
      metadata: createScanMetadata(durationMs, scanners.length, false),
    };
  }

  private detectPromptInjection(text: string): boolean {
    const patterns = [
      /ignore\s+(?:all\s+)?(?:previous\s+)?instructions?/i,
      /disregard\s+(?:all\s+)?(?:previous\s+)?instructions?/i,
      /forget\s+(?:all\s+)?(?:previous\s+)?instructions?/i,
      /system\s*:\s*/i,
      /you\s+are\s+now\s+/i,
      /act\s+as\s+(?:if\s+)?you/i,
    ];

    return patterns.some((pattern) => pattern.test(text));
  }

  private detectSecrets(text: string): Array<{
    entityType: string;
    text: string;
    start: number;
    end: number;
    confidence?: number;
  }> {
    const secrets = [];
    const patterns = [
      { type: 'api_key', regex: /\b[A-Za-z0-9]{32,}\b/g },
      { type: 'aws_key', regex: /AKIA[0-9A-Z]{16}/g },
      { type: 'github_token', regex: /ghp_[a-zA-Z0-9]{36}/g },
    ];

    for (const { type, regex } of patterns) {
      let match;
      while ((match = regex.exec(text)) !== null) {
        secrets.push({
          entityType: type,
          text: match[0],
          start: match.index,
          end: match.index + match[0].length,
          confidence: 0.8,
        });
      }
    }

    return secrets;
  }
}


