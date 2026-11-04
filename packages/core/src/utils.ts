/**
 * Utility functions
 *
 * @module utils
 */

import type { ScanMetadata } from './types';

/**
 * Get the library version
 */
export function version(): string {
  return '0.1.0';
}

/**
 * Initialize the WASM module manually
 *
 * This is called automatically by LLMShield, but can be called
 * explicitly for custom initialization timing.
 */
export async function initialize(): Promise<void> {
  // TODO: Initialize WASM module
  // For now, this is a no-op
  return Promise.resolve();
}

/**
 * Create a deterministic hash of text for caching
 *
 * @param text - Text to hash
 * @returns Hash string
 */
export function hashText(text: string): string {
  // Simple hash function (should be replaced with better hash in production)
  let hash = 0;
  for (let i = 0; i < text.length; i++) {
    const char = text.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash).toString(36);
}

/**
 * Create scan metadata
 *
 * @param durationMs - Scan duration in milliseconds
 * @param scannersRun - Number of scanners executed
 * @param cached - Whether result was from cache
 * @returns Scan metadata
 */
export function createScanMetadata(
  durationMs: number,
  scannersRun: number,
  cached: boolean
): ScanMetadata {
  return {
    durationMs,
    scannersRun,
    cached,
    timestamp: Date.now(),
  };
}

/**
 * Format bytes to human-readable string
 *
 * @param bytes - Number of bytes
 * @returns Formatted string
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

/**
 * Sleep for specified milliseconds
 *
 * @param ms - Milliseconds to sleep
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Check if running in browser environment
 */
export function isBrowser(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.document !== 'undefined'
  );
}

/**
 * Check if running in Node.js environment
 */
export function isNode(): boolean {
  return (
    typeof process !== 'undefined' &&
    process.versions != null &&
    process.versions.node != null
  );
}

/**
 * Check if running in Deno environment
 */
export function isDeno(): boolean {
  return 'Deno' in globalThis;
}

/**
 * Get runtime environment name
 */
export function getRuntime(): 'node' | 'browser' | 'deno' | 'unknown' {
  if (isNode()) return 'node';
  if (isDeno()) return 'deno';
  if (isBrowser()) return 'browser';
  return 'unknown';
}

