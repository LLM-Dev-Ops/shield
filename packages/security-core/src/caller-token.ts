/**
 * @module caller-token
 * @description CallerToken creation and validation using HMAC-SHA256.
 */

import { createHmac, timingSafeEqual } from 'crypto';
import type { CallerToken } from './types.js';
import { CallerTokenError } from './errors.js';

const DEFAULT_TTL_SECONDS = 300; // 5 minutes

/**
 * Create a signed CallerToken for a given caller ID.
 *
 * @param callerId - Unique identifier for the caller (e.g., "agentics-core")
 * @param sharedSecret - Shared secret for HMAC signing
 * @returns A signed CallerToken
 */
export function createCallerToken(callerId: string, sharedSecret: string): CallerToken {
  if (!callerId) {
    throw new CallerTokenError('caller_id must not be empty');
  }
  if (!sharedSecret) {
    throw new CallerTokenError('sharedSecret must not be empty');
  }

  const issuedAt = new Date().toISOString();
  const signature = computeSignature(callerId, issuedAt, sharedSecret);

  return {
    caller_id: callerId,
    signature,
    issued_at: issuedAt,
  };
}

/**
 * Validate a CallerToken's signature and expiry.
 *
 * @param token - The CallerToken to validate
 * @param sharedSecret - Shared secret for HMAC verification
 * @param ttlSeconds - Maximum token age in seconds (default: 300)
 * @throws CallerTokenError if the token is invalid or expired
 */
export function validateCallerToken(
  token: CallerToken,
  sharedSecret: string,
  ttlSeconds: number = DEFAULT_TTL_SECONDS,
): void {
  if (!token || !token.caller_id || !token.signature || !token.issued_at) {
    throw new CallerTokenError('CallerToken is missing required fields');
  }

  // Verify signature using constant-time comparison
  const expectedSignature = computeSignature(token.caller_id, token.issued_at, sharedSecret);

  const sigBuffer = Buffer.from(token.signature, 'hex');
  const expectedBuffer = Buffer.from(expectedSignature, 'hex');

  if (sigBuffer.length !== expectedBuffer.length || !timingSafeEqual(sigBuffer, expectedBuffer)) {
    throw new CallerTokenError('Invalid CallerToken signature');
  }

  // Check expiry
  const issuedAt = new Date(token.issued_at);
  if (isNaN(issuedAt.getTime())) {
    throw new CallerTokenError('Invalid issued_at timestamp');
  }

  const ageMs = Date.now() - issuedAt.getTime();
  if (ageMs > ttlSeconds * 1000) {
    throw new CallerTokenError(`CallerToken expired (age: ${Math.round(ageMs / 1000)}s, TTL: ${ttlSeconds}s)`);
  }

  if (ageMs < -30_000) {
    // Allow 30s clock skew, but reject tokens from the future beyond that
    throw new CallerTokenError('CallerToken issued_at is in the future');
  }
}

/**
 * Compute HMAC-SHA256 signature for a caller token.
 */
function computeSignature(callerId: string, issuedAt: string, secret: string): string {
  const payload = `${callerId}|${issuedAt}`;
  return createHmac('sha256', secret).update(payload).digest('hex');
}
