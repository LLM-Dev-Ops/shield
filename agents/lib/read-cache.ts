/**
 * @module read-cache
 * @description Read-only in-memory caching for LLM-Shield agents
 *
 * Phase 1 / Layer 1 - Foundational Tooling
 *
 * Caching is ONLY for read-only operations:
 * - Telemetry reads
 * - Registry lookups
 * - Schema checks
 *
 * TTL: 30-60 seconds (conservative)
 */

// =============================================================================
// TYPES
// =============================================================================

export interface CacheEntry<T> {
  value: T;
  expiresAt: number;
  createdAt: number;
}

export interface CacheStats {
  hits: number;
  misses: number;
  entries: number;
  hitRate: number;
}

// =============================================================================
// CONSTANTS
// =============================================================================

const DEFAULT_TTL_MS = 30000; // 30 seconds
const MAX_TTL_MS = 60000; // 60 seconds
const MAX_ENTRIES = 1000; // Prevent unbounded growth

// =============================================================================
// READ-ONLY CACHE IMPLEMENTATION
// =============================================================================

export class ReadOnlyCache<T> {
  private cache: Map<string, CacheEntry<T>> = new Map();
  private hits: number = 0;
  private misses: number = 0;
  private readonly ttlMs: number;
  private readonly maxEntries: number;

  constructor(ttlMs: number = DEFAULT_TTL_MS, maxEntries: number = MAX_ENTRIES) {
    // Enforce TTL limits
    this.ttlMs = Math.min(Math.max(ttlMs, 1000), MAX_TTL_MS);
    this.maxEntries = Math.min(Math.max(maxEntries, 10), MAX_ENTRIES);
  }

  /**
   * Get a value from cache
   */
  get(key: string): T | undefined {
    const entry = this.cache.get(key);

    if (!entry) {
      this.misses++;
      return undefined;
    }

    // Check expiration
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      this.misses++;
      return undefined;
    }

    this.hits++;
    return entry.value;
  }

  /**
   * Set a value in cache
   */
  set(key: string, value: T): void {
    // Enforce max entries (LRU-like eviction)
    if (this.cache.size >= this.maxEntries) {
      this.evictOldest();
    }

    const now = Date.now();
    this.cache.set(key, {
      value,
      expiresAt: now + this.ttlMs,
      createdAt: now,
    });
  }

  /**
   * Check if key exists and is not expired
   */
  has(key: string): boolean {
    const entry = this.cache.get(key);
    if (!entry) return false;
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return false;
    }
    return true;
  }

  /**
   * Delete a specific key
   */
  delete(key: string): boolean {
    return this.cache.delete(key);
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.cache.clear();
    this.hits = 0;
    this.misses = 0;
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    const total = this.hits + this.misses;
    return {
      hits: this.hits,
      misses: this.misses,
      entries: this.cache.size,
      hitRate: total > 0 ? this.hits / total : 0,
    };
  }

  /**
   * Clean up expired entries
   */
  cleanup(): number {
    const now = Date.now();
    let removed = 0;

    for (const [key, entry] of this.cache) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Evict oldest entries to make room
   */
  private evictOldest(): void {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;

    for (const [key, entry] of this.cache) {
      if (entry.createdAt < oldestTime) {
        oldestTime = entry.createdAt;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.cache.delete(oldestKey);
    }
  }
}

// =============================================================================
// SPECIALIZED CACHES
// =============================================================================

/**
 * Cache for Ruvector health checks
 */
export const ruvectorHealthCache = new ReadOnlyCache<boolean>(30000); // 30s TTL

/**
 * Cache for schema lookups
 */
export const schemaCache = new ReadOnlyCache<unknown>(60000); // 60s TTL

/**
 * Cache for registry lookups
 */
export const registryCache = new ReadOnlyCache<unknown>(45000); // 45s TTL

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Get or compute a cached value
 */
export async function getOrCompute<T>(
  cache: ReadOnlyCache<T>,
  key: string,
  compute: () => Promise<T>
): Promise<T> {
  const cached = cache.get(key);
  if (cached !== undefined) {
    return cached;
  }

  const value = await compute();
  cache.set(key, value);
  return value;
}

/**
 * Create a cache key from multiple parts
 */
export function createCacheKey(...parts: (string | number | boolean)[]): string {
  return parts.map(String).join(':');
}

// =============================================================================
// PERIODIC CLEANUP
// =============================================================================

let cleanupInterval: NodeJS.Timeout | null = null;

/**
 * Start periodic cache cleanup
 */
export function startCacheCleanup(intervalMs: number = 60000): void {
  if (cleanupInterval) return;

  cleanupInterval = setInterval(() => {
    ruvectorHealthCache.cleanup();
    schemaCache.cleanup();
    registryCache.cleanup();
  }, intervalMs);

  // Ensure cleanup doesn't prevent process exit
  if (cleanupInterval.unref) {
    cleanupInterval.unref();
  }
}

/**
 * Stop periodic cache cleanup
 */
export function stopCacheCleanup(): void {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
  }
}
