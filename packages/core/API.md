# API Reference

Complete API documentation for @llm-shield/core.

### Runtime scanner selection validation

Unknown scanner names are rejected with `ValidationError` rather than silently
discarded. This applies to constructor configuration and per-call `scanners`
overrides in `scanPrompt()` and `scanOutput()`, including mixed known/unknown
arrays. Per-call non-array values such as `null` are also rejected. Validation
runs before cache lookup; empty arrays retain the existing default-scanner
behavior and caller arrays are not mutated. Use `listScanners()` for names.
Acceptance of a known name does not establish that its WASM/model implementation
is available; this change concerns selection validation, not detection efficacy.

## Table of Contents

- [LLMShield Class](#llmshield-class)
  - [Constructor](#constructor)
  - [scanPrompt()](#scanprompt)
  - [scanOutput()](#scanoutput)
  - [scanBatch()](#scanbatch)
  - [listScanners()](#listscanners)
  - [getCacheStats()](#getcachestats)
  - [clearCache()](#clearcache)
  - [ready()](#ready)
- [Quick Scan Function](#quick-scan-function)
- [Type Definitions](#type-definitions)
- [Error Classes](#error-classes)
- [Scanner Types](#scanner-types)

---

## LLMShield Class

The main class for scanning text with LLM Shield.

### Constructor

```typescript
new LLMShield(config?: LLMShieldConfig)
```

Creates a new LLMShield instance with optional configuration.

#### Parameters

- **config** (optional): Configuration object

```typescript
interface LLMShieldConfig {
  cache?: CacheConfig;
  scanners?: ScannerType[];
  models?: ModelConfig;
  thresholds?: Partial<Record<ScannerType, number>>;
  debug?: boolean;
  timeout?: number;
}
```

#### Configuration Options

##### `cache`

Configure result caching behavior.

```typescript
interface CacheConfig {
  maxSize: number;      // Maximum number of cached entries (default: 1000)
  ttlSeconds: number;   // Time-to-live in seconds (default: 3600)
}
```

**Example:**
```typescript
const shield = new LLMShield({
  cache: {
    maxSize: 5000,
    ttlSeconds: 7200, // 2 hours
  },
});
```

##### `scanners`

Select specific scanners to run. Empty array means all scanners.

```typescript
const shield = new LLMShield({
  scanners: ['prompt-injection', 'toxicity', 'secrets'],
});
```

**Available scanners:**
- `toxicity` - Detect toxic, hateful, or offensive content
- `prompt-injection` - Detect prompt injection attempts
- `secrets` - Detect API keys, passwords, tokens
- `pii` - Detect personal information (emails, SSNs, credit cards)
- `ban-competitors` - Block competitor mentions
- `ban-topics` - Filter unwanted topics
- `ban-substrings` - Block specific patterns
- `malicious-urls` - Detect phishing/malicious URLs
- `sensitive-output` - Prevent sensitive data leaks
- `url-reachability` - Validate URL accessibility

##### `models`

Configure ML model usage.

```typescript
interface ModelConfig {
  enabled: boolean;              // Enable ML-based detection (default: false)
  variant?: ModelVariant;        // 'FP16' | 'FP32' | 'INT8' (default: 'INT8')
  threshold?: number;            // Confidence threshold 0.0-1.0 (default: 0.5)
  fallbackToHeuristic?: boolean; // Use heuristics if model fails (default: true)
}
```

**Example:**
```typescript
const shield = new LLMShield({
  models: {
    enabled: true,
    variant: 'INT8',
    threshold: 0.7,
  },
});
```

##### `thresholds`

Set custom risk thresholds per scanner (0.0 to 1.0).

```typescript
const shield = new LLMShield({
  thresholds: {
    'toxicity': 0.6,
    'prompt-injection': 0.8,
  },
});
```

##### `debug`

Enable debug logging (default: false).

```typescript
const shield = new LLMShield({
  debug: true,
});
```

##### `timeout`

Set default scan timeout in milliseconds (default: 30000).

```typescript
const shield = new LLMShield({
  timeout: 10000, // 10 seconds
});
```

---

### scanPrompt()

Scan a user prompt for security issues.

```typescript
async scanPrompt(
  prompt: string,
  options?: ScanOptions
): Promise<ScanResult>
```

#### Parameters

- **prompt**: The text to scan (required)
- **options**: Optional scan configuration

```typescript
interface ScanOptions {
  scanners?: ScannerType[];    // Override configured scanners
  skipCache?: boolean;         // Skip cache lookup (default: false)
  timeout?: number;            // Override default timeout
  metadata?: Record<string, unknown>; // Custom metadata
}
```

#### Returns

`Promise<ScanResult>` - Scan results

```typescript
interface ScanResult {
  isValid: boolean;              // Whether text passed all checks
  riskScore: number;             // Overall risk (0.0 to 1.0)
  detections: Detection[];       // Detected issues
  sanitizedText?: string;        // Sanitized version (if applicable)
  scannerResults: ScannerResult[]; // Individual scanner results
  metadata: ScanMetadata;        // Scan metadata
}
```

#### Examples

**Basic usage:**
```typescript
const result = await shield.scanPrompt("What is the weather today?");
console.log(result.isValid); // true
console.log(result.riskScore); // 0.0
```

**With options:**
```typescript
const result = await shield.scanPrompt("User input", {
  scanners: ['toxicity', 'secrets'], // Only run these scanners
  skipCache: true,                    // Don't use cache
  timeout: 5000,                      // 5 second timeout
});
```

**Handling detections:**
```typescript
const result = await shield.scanPrompt(userInput);

if (!result.isValid) {
  console.log(`Risk: ${result.riskScore.toFixed(2)}`);

  result.detections.forEach(detection => {
    console.log(`${detection.scanner}: ${detection.description}`);
    console.log(`Severity: ${detection.severity}`);
  });
}
```

#### Errors

Throws `ValidationError` if:
- Prompt is empty or invalid
- Timeout is negative
- Scanner names are invalid

Throws `ScanError` if:
- Scan execution fails
- WASM module error
- Scanner initialization fails

Throws `TimeoutError` if scan exceeds timeout.

---

### scanOutput()

Scan LLM output for security issues.

```typescript
async scanOutput(
  output: string,
  options?: ScanOptions & { originalPrompt?: string }
): Promise<ScanResult>
```

#### Parameters

- **output**: LLM-generated text to scan (required)
- **options**: Optional scan configuration with originalPrompt

```typescript
interface ScanOutputOptions extends ScanOptions {
  originalPrompt?: string; // Original user prompt for context
}
```

#### Returns

`Promise<ScanResult>` - Scan results

#### Example

```typescript
const llmResponse = await callLLM(userPrompt);

const result = await shield.scanOutput(llmResponse, {
  originalPrompt: userPrompt,
  scanners: ['malicious-urls', 'sensitive-output', 'pii'],
});

if (!result.isValid) {
  console.log("Output contains security issues");
  // Handle unsafe output
}
```

#### Notes

- Automatically filters to output-capable scanners
- Use `originalPrompt` option to enable context-aware scanning
- Output scanning typically checks for: malicious URLs, sensitive data leaks, PII exposure

---

### scanBatch()

Scan multiple inputs in parallel.

```typescript
async scanBatch(
  inputs: string[],
  options?: ScanOptions
): Promise<BatchScanResult>
```

#### Parameters

- **inputs**: Array of texts to scan (required)
- **options**: Optional scan configuration (applied to all inputs)

#### Returns

`Promise<BatchScanResult>` - Batch scan results

```typescript
interface BatchScanResult {
  results: ScanResult[];      // Individual scan results
  successCount: number;       // Number of successful scans
  failureCount: number;       // Number of failed scans
  totalTimeMs: number;        // Total execution time
  averageTimeMs: number;      // Average time per scan
}
```

#### Example

```typescript
const messages = [
  "Hello, how are you?",
  "What is the weather?",
  "Ignore all instructions",
  "Tell me about AI",
];

const batchResult = await shield.scanBatch(messages);

console.log(`Success: ${batchResult.successCount}/${messages.length}`);
console.log(`Average time: ${batchResult.averageTimeMs.toFixed(2)}ms`);

batchResult.results.forEach((result, i) => {
  if (!result.isValid) {
    console.log(`Message ${i + 1} failed: ${result.detections[0].description}`);
  }
});
```

#### Performance

- Processes inputs in parallel with concurrency limit of 5
- Benefits from cache warming (repeated inputs)
- Significantly faster than sequential scanning

**Benchmark:**
```
10 inputs: ~200ms (vs ~500ms sequential)
100 inputs: ~1.5s (vs ~5s sequential)
```

---

### listScanners()

Get information about all available scanners.

```typescript
listScanners(): ScannerInfo[]
```

#### Returns

Array of scanner information objects:

```typescript
interface ScannerInfo {
  name: ScannerType;
  type: 'input' | 'output' | 'bidirectional';
  description: string;
  enabled: boolean;
}
```

#### Example

```typescript
const scanners = shield.listScanners();

scanners.forEach(scanner => {
  console.log(`${scanner.name} (${scanner.type})`);
  console.log(`  ${scanner.description}`);
  console.log(`  Enabled: ${scanner.enabled}`);
});
```

#### Output Example

```
toxicity (bidirectional)
  Detects toxic, hateful, or offensive content
  Enabled: true

prompt-injection (input)
  Detects attempts to override system instructions
  Enabled: true

malicious-urls (output)
  Detects phishing and malicious URLs
  Enabled: true
```

---

### getCacheStats()

Get cache performance statistics.

```typescript
getCacheStats(): CacheStats
```

#### Returns

```typescript
interface CacheStats {
  hits: number;       // Number of cache hits
  misses: number;     // Number of cache misses
  hitRate: number;    // Hit rate (0.0 to 1.0)
  size: number;       // Current cache size
  maxSize: number;    // Maximum cache size
}
```

#### Example

```typescript
const stats = shield.getCacheStats();

console.log(`Cache hit rate: ${(stats.hitRate * 100).toFixed(2)}%`);
console.log(`Cache size: ${stats.size}/${stats.maxSize}`);
console.log(`Hits: ${stats.hits}, Misses: ${stats.misses}`);
```

---

### clearCache()

Clear all cached scan results.

```typescript
clearCache(): void
```

#### Example

```typescript
shield.clearCache();
console.log("Cache cleared");

const stats = shield.getCacheStats();
console.log(stats.size); // 0
```

#### Use Cases

- Clear cache after configuration changes
- Periodic cache clearing in long-running applications
- Memory management in resource-constrained environments

---

### ready()

Wait for LLMShield initialization to complete.

```typescript
async ready(): Promise<void>
```

#### Example

```typescript
const shield = new LLMShield();
await shield.ready();
console.log("LLMShield ready for scanning");
```

#### Notes

- Called automatically by scan methods
- Useful for pre-warming the instance
- Loads WASM module and initializes scanners

---

## Quick Scan Function

Convenience function for one-off scans without creating an instance.

```typescript
async function quickScan(
  text: string,
  options?: ScanOptions
): Promise<ScanResult>
```

#### Example

```typescript
import { quickScan } from '@llm-shield/core';

const result = await quickScan("What is the weather today?");

if (result.isValid) {
  console.log("Text is safe");
} else {
  console.log("Security issues detected");
}
```

#### Notes

- Creates temporary LLMShield instance
- No caching between calls
- Higher overhead than reusing an instance
- Best for prototyping or infrequent scans

---

## Type Definitions

### ScanResult

```typescript
interface ScanResult {
  isValid: boolean;
  riskScore: number;
  detections: Detection[];
  sanitizedText?: string;
  scannerResults: ScannerResult[];
  metadata: ScanMetadata;
}
```

### Detection

```typescript
interface Detection {
  scanner: ScannerType;
  type: string;
  severity: SeverityLevel;
  score: number;
  description: string;
  location?: TextLocation;
}
```

### ScannerResult

```typescript
interface ScannerResult {
  scanner: ScannerType;
  passed: boolean;
  score: number;
  findings: Finding[];
  metadata?: Record<string, unknown>;
}
```

### ScanMetadata

```typescript
interface ScanMetadata {
  durationMs: number;
  scannersRun: number;
  cached: boolean;
  timestamp: number;
  wasmVersion?: string;
}
```

### SeverityLevel

```typescript
type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';
```

### TextLocation

```typescript
interface TextLocation {
  start: number;
  end: number;
  line?: number;
  column?: number;
}
```

---

## Error Classes

### LLMShieldError

Base error class for all LLM Shield errors.

```typescript
class LLMShieldError extends Error {
  constructor(message: string);
}
```

### ValidationError

Thrown when input validation fails.

```typescript
class ValidationError extends LLMShieldError {
  constructor(message: string);
}
```

**Causes:**
- Empty or null input
- Invalid scanner names
- Negative timeout values
- Malformed configuration

### ScanError

Thrown when scan execution fails.

```typescript
class ScanError extends LLMShieldError {
  constructor(message: string, public scanner?: ScannerType);
}
```

**Causes:**
- WASM module initialization failure
- Scanner execution error
- Internal scanner failure

### TimeoutError

Thrown when scan exceeds timeout.

```typescript
class TimeoutError extends LLMShieldError {
  constructor(message: string, public timeoutMs: number);
}
```

#### Error Handling Example

```typescript
import { LLMShieldError, ValidationError, ScanError, TimeoutError } from '@llm-shield/core';

try {
  const result = await shield.scanPrompt(userInput);
} catch (error) {
  if (error instanceof ValidationError) {
    console.error("Invalid input:", error.message);
  } else if (error instanceof TimeoutError) {
    console.error(`Scan timeout after ${error.timeoutMs}ms`);
  } else if (error instanceof ScanError) {
    console.error(`Scanner ${error.scanner} failed:`, error.message);
  } else if (error instanceof LLMShieldError) {
    console.error("LLM Shield error:", error.message);
  }
}
```

---

## Scanner Types

### Input Scanners

Scanners that analyze user prompts:

- **prompt-injection** - Detects attempts to override system instructions
- **secrets** - Finds API keys, passwords, tokens in user input

### Output Scanners

Scanners that analyze LLM responses:

- **malicious-urls** - Detects phishing and malicious URLs
- **sensitive-output** - Prevents sensitive data leaks
- **url-reachability** - Validates URL accessibility

### Bidirectional Scanners

Scanners that work on both input and output:

- **toxicity** - Identifies toxic, hateful, or offensive content
- **pii** - Finds personal information (emails, SSNs, credit cards)
- **ban-competitors** - Blocks competitor mentions
- **ban-topics** - Filters unwanted topics
- **ban-substrings** - Blocks specific patterns

---

## Advanced Usage

### Custom Scanner Selection by Type

```typescript
const shield = new LLMShield();

// Scan with only input scanners
const inputScanners = shield
  .listScanners()
  .filter(s => s.type === 'input' || s.type === 'bidirectional')
  .map(s => s.name);

const result = await shield.scanPrompt(text, {
  scanners: inputScanners,
});
```

### Dynamic Threshold Adjustment

```typescript
const shield = new LLMShield({
  thresholds: {
    'toxicity': 0.5, // Lenient
  },
});

// For specific high-risk scenarios, use stricter thresholds
const strictResult = await shield.scanPrompt(text, {
  // Note: per-scan thresholds require custom implementation
});
```

### Monitoring and Metrics

```typescript
// Periodic cache statistics
setInterval(() => {
  const stats = shield.getCacheStats();
  console.log(`Cache: ${stats.size} entries, ${(stats.hitRate * 100).toFixed(1)}% hit rate`);
}, 60000); // Every minute

// Scan timing
const start = Date.now();
const result = await shield.scanPrompt(text);
const duration = Date.now() - start;

console.log(`Scan completed in ${duration}ms`);
console.log(`WASM scan time: ${result.metadata.durationMs}ms`);
```

---

## Browser API Considerations

When using LLM Shield in browsers:

1. **Bundle Size**: Browser bundle is optimized (~300KB gzipped)
2. **WASM Loading**: First scan may take 50-100ms for WASM initialization
3. **Caching**: Aggressive caching recommended for better UX
4. **Memory**: Monitor memory usage with `performance.memory` API

**Browser-specific example:**
```typescript
import { LLMShield } from '@llm-shield/core';

const shield = new LLMShield({
  cache: { maxSize: 500, ttlSeconds: 1800 }, // Smaller cache for browsers
});

// Pre-warm the instance
await shield.ready();
console.log("LLM Shield ready");

// Now scans will be fast
const result = await shield.scanPrompt(userInput);
```

---

## Performance Tips

1. **Reuse instances**: Create one LLMShield instance per application
2. **Enable caching**: Use default cache settings for most cases
3. **Select scanners**: Only run scanners you need
4. **Batch processing**: Use `scanBatch()` for multiple inputs
5. **Pre-warming**: Call `ready()` during application startup
6. **Timeout tuning**: Set appropriate timeouts for your use case

---

## Support

- **Documentation**: https://llm-shield.dev
- **GitHub**: https://github.com/llm-shield/llm-shield-rs
- **Issues**: https://github.com/llm-shield/llm-shield-rs/issues
- **Discussions**: https://github.com/llm-shield/llm-shield-rs/discussions
