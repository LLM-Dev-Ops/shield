/**
 * @module gateway-store
 * @description AsyncLocalStorage for gateway token propagation.
 *
 * The SecurityCore sets the token before delegating to the inner Shield.
 * The Shield can optionally check this store to verify it was called through the gateway.
 */

import { AsyncLocalStorage } from 'async_hooks';
import type { CallerToken } from './types.js';

export interface GatewayStoreContext {
  token: CallerToken;
}

export const gatewayTokenStore = new AsyncLocalStorage<GatewayStoreContext>();
