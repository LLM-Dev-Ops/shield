import { AsyncLocalStorage } from 'async_hooks';
import type { Scanner, ScanResult, ShieldConfig, ScanOptions, RiskFactor, Entity, Severity } from './types.js';
import { PromptInjectionScanner } from './scanners/prompt-injection.js';
import { SecretsScanner } from './scanners/secrets.js';
import { PIIScanner } from './scanners/pii.js';
import { ToxicityScanner } from './scanners/toxicity.js';

/**
 * AsyncLocalStorage for gateway token propagation.
 *
 * When LLM_SHIELD_ENFORCE_GATEWAY=true, Shield's scanning methods
 * require this store to contain a valid token, ensuring all invocations
 * go through @llm-shield/security-core SecurityCore.
 */
export const gatewayTokenStore = new AsyncLocalStorage<{ token: unknown }>();

/**
 * Shield - Main security facade for LLM applications
 *
 * @example
 * ```typescript
 * // Using presets
 * const shield = Shield.standard();
 * const result = await shield.scanPrompt("User input");
 *
 * // Custom configuration
 * const shield = Shield.builder()
 *   .addInputScanner(new SecretsScanner())
 *   .addInputScanner(new PIIScanner())
 *   .withParallelExecution(true)
 *   .build();
 * ```
 */
export class Shield {
  private inputScanners: Scanner[];
  private outputScanners: Scanner[];
  private config: ShieldConfig;

  private constructor(config: ShieldConfig, inputScanners: Scanner[], outputScanners: Scanner[]) {
    this.config = config;
    this.inputScanners = inputScanners;
    this.outputScanners = outputScanners;
  }

  /**
   * Create a Shield with strict security settings
   * Maximum security for regulated industries (banking, healthcare)
   */
  static strict(): Shield {
    return new Shield(
      {
        preset: 'strict',
        shortCircuitThreshold: 0.7,
        parallelExecution: false,
      },
      [
        new PromptInjectionScanner(),
        new SecretsScanner(),
        new PIIScanner(),
        new ToxicityScanner(),
      ],
      [
        new SecretsScanner(),
        new PIIScanner(),
      ]
    );
  }

  /**
   * Create a Shield with standard security settings
   * Balanced security for general-purpose applications (recommended)
   */
  static standard(): Shield {
    return new Shield(
      {
        preset: 'standard',
        shortCircuitThreshold: 0.9,
        parallelExecution: true,
        maxConcurrent: 4,
      },
      [
        new PromptInjectionScanner(),
        new SecretsScanner(),
        new PIIScanner({ piiTypes: ['email', 'ssn', 'credit-card'] }),
      ],
      [
        new SecretsScanner(),
        new PIIScanner({ piiTypes: ['email', 'ssn', 'credit-card'] }),
      ]
    );
  }

  /**
   * Create a Shield with permissive security settings
   * Minimal security for development/testing
   */
  static permissive(): Shield {
    return new Shield(
      {
        preset: 'permissive',
        shortCircuitThreshold: 1.0,
        parallelExecution: true,
      },
      [
        new SecretsScanner({ secretTypes: ['aws', 'private-key'] }),
      ],
      []
    );
  }

  /**
   * Create a ShieldBuilder for custom configuration
   */
  static builder(): ShieldBuilder {
    return new ShieldBuilder();
  }

  /**
   * Scan a prompt before sending to LLM
   */
  async scanPrompt(text: string, options?: ScanOptions): Promise<ScanResult> {
    return this.runScanners(text, this.inputScanners, options);
  }

  /**
   * Scan LLM output before returning to user
   */
  async scanOutput(text: string, options?: ScanOptions): Promise<ScanResult> {
    return this.runScanners(text, this.outputScanners, options);
  }

  /**
   * Scan both prompt and output in sequence
   */
  async scanPromptAndOutput(
    prompt: string,
    output: string,
    options?: ScanOptions
  ): Promise<{ promptResult: ScanResult; outputResult: ScanResult }> {
    const promptResult = await this.scanPrompt(prompt, options);

    // Short-circuit if prompt is invalid
    if (!promptResult.isValid && promptResult.riskScore >= (this.config.shortCircuitThreshold ?? 0.9)) {
      return {
        promptResult,
        outputResult: {
          isValid: false,
          riskScore: 0,
          sanitizedText: '',
          entities: [],
          riskFactors: [{
            category: 'prompt-injection',
            description: 'Output scan skipped due to invalid prompt',
            severity: 'none',
            confidence: 1.0,
          }],
          severity: 'none',
          metadata: { skipped: 'true' },
          durationMs: 0,
        },
      };
    }

    const outputResult = await this.scanOutput(output, options);
    return { promptResult, outputResult };
  }

  /**
   * Scan multiple texts in batch
   */
  async scanBatch(texts: string[], options?: ScanOptions): Promise<ScanResult[]> {
    if (this.config.parallelExecution) {
      return Promise.all(texts.map(text => this.scanPrompt(text, options)));
    }

    const results: ScanResult[] = [];
    for (const text of texts) {
      results.push(await this.scanPrompt(text, options));
    }
    return results;
  }

  private async runScanners(
    text: string,
    scanners: Scanner[],
    options?: ScanOptions
  ): Promise<ScanResult> {
    // Gateway enforcement: reject direct calls when enabled
    if (process.env.LLM_SHIELD_ENFORCE_GATEWAY === 'true') {
      const store = gatewayTokenStore.getStore();
      if (!store?.token) {
        throw new Error(
          'Direct call to Shield is forbidden. Use @llm-shield/security-core SecurityCore instead. '
          + 'Set LLM_SHIELD_ENFORCE_GATEWAY=false to disable this check.'
        );
      }
    }

    if (scanners.length === 0) {
      return {
        isValid: true,
        riskScore: 0,
        sanitizedText: text,
        entities: [],
        riskFactors: [],
        severity: 'none',
        metadata: {},
        durationMs: 0,
      };
    }

    const startTime = performance.now();
    const processedText = options?.maxLength ? text.slice(0, options.maxLength) : text;

    let results: ScanResult[];

    if (this.config.parallelExecution) {
      const maxConcurrent = this.config.maxConcurrent ?? 4;
      results = await this.runParallel(processedText, scanners, maxConcurrent);
    } else {
      results = await this.runSequential(processedText, scanners);
    }

    // Merge results
    const mergedResult = this.mergeResults(processedText, results);
    mergedResult.durationMs = performance.now() - startTime;

    return mergedResult;
  }

  private async runSequential(text: string, scanners: Scanner[]): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    for (const scanner of scanners) {
      const result = await scanner.scan(text);
      results.push(result);

      // Short-circuit if threshold exceeded
      if (result.riskScore >= (this.config.shortCircuitThreshold ?? 0.9)) {
        break;
      }
    }

    return results;
  }

  private async runParallel(
    text: string,
    scanners: Scanner[],
    maxConcurrent: number
  ): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    for (let i = 0; i < scanners.length; i += maxConcurrent) {
      const batch = scanners.slice(i, i + maxConcurrent);
      const batchResults = await Promise.all(batch.map(s => s.scan(text)));
      results.push(...batchResults);

      // Check for short-circuit
      const maxRisk = Math.max(...batchResults.map(r => r.riskScore));
      if (maxRisk >= (this.config.shortCircuitThreshold ?? 0.9)) {
        break;
      }
    }

    return results;
  }

  private mergeResults(originalText: string, results: ScanResult[]): ScanResult {
    if (results.length === 0) {
      return {
        isValid: true,
        riskScore: 0,
        sanitizedText: originalText,
        entities: [],
        riskFactors: [],
        severity: 'none',
        metadata: {},
        durationMs: 0,
      };
    }

    const allEntities: Entity[] = [];
    const allRiskFactors: RiskFactor[] = [];
    let maxRiskScore = 0;
    let maxSeverity: Severity = 'none';

    const severityOrder: Severity[] = ['none', 'low', 'medium', 'high', 'critical'];

    for (const result of results) {
      allEntities.push(...result.entities);
      allRiskFactors.push(...result.riskFactors);

      if (result.riskScore > maxRiskScore) {
        maxRiskScore = result.riskScore;
      }

      const severityIndex = severityOrder.indexOf(result.severity);
      if (severityIndex > severityOrder.indexOf(maxSeverity)) {
        maxSeverity = result.severity;
      }
    }

    // Deduplicate entities by position
    const uniqueEntities = this.deduplicateEntities(allEntities);

    // Get sanitized text from the last result that modified it
    let sanitizedText = originalText;
    for (const result of results) {
      if (result.sanitizedText !== originalText) {
        sanitizedText = result.sanitizedText;
      }
    }

    return {
      isValid: allRiskFactors.length === 0,
      riskScore: maxRiskScore,
      sanitizedText,
      entities: uniqueEntities,
      riskFactors: allRiskFactors,
      severity: maxSeverity,
      metadata: {},
      durationMs: 0,
    };
  }

  private deduplicateEntities(entities: Entity[]): Entity[] {
    const seen = new Set<string>();
    return entities.filter(entity => {
      const key = `${entity.start}-${entity.end}-${entity.entityType}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
}

/**
 * Builder for creating custom Shield configurations
 */
export class ShieldBuilder {
  private inputScanners: Scanner[] = [];
  private outputScanners: Scanner[] = [];
  private config: ShieldConfig = {
    parallelExecution: true,
    maxConcurrent: 4,
    shortCircuitThreshold: 0.9,
  };

  /**
   * Add an input scanner
   */
  addInputScanner(scanner: Scanner): this {
    this.inputScanners.push(scanner);
    return this;
  }

  /**
   * Add an output scanner
   */
  addOutputScanner(scanner: Scanner): this {
    this.outputScanners.push(scanner);
    return this;
  }

  /**
   * Set the short-circuit threshold
   */
  withShortCircuit(threshold: number): this {
    this.config.shortCircuitThreshold = threshold;
    return this;
  }

  /**
   * Enable or disable parallel execution
   */
  withParallelExecution(enabled: boolean): this {
    this.config.parallelExecution = enabled;
    return this;
  }

  /**
   * Set maximum concurrent scanners
   */
  withMaxConcurrent(max: number): this {
    this.config.maxConcurrent = max;
    return this;
  }

  /**
   * Build the Shield instance
   */
  build(): Shield {
    // Use private constructor via closure
    return (Shield as any)['strict']().constructor['call'](
      Object.create(Shield.prototype),
      this.config,
      this.inputScanners,
      this.outputScanners
    ) || new (Shield as any)(this.config, this.inputScanners, this.outputScanners);
  }
}

// Fix the build method to work properly
ShieldBuilder.prototype.build = function(this: ShieldBuilder): Shield {
  const shield = Shield.strict();
  (shield as any).config = (this as any).config;
  (shield as any).inputScanners = (this as any).inputScanners;
  (shield as any).outputScanners = (this as any).outputScanners;
  return shield;
};
