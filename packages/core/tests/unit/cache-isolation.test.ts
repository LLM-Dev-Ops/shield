import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// The same frozen probe runs against independently built baseline/candidate
// bundles. No scanner, cache, WASM or HTTP execution is mocked here.
describe('built wrapper cache isolation', async () => {
  const moduleUrl = pathToFileURL(resolve('security/probe-cache.mjs')).href;
  const { contract, probeCache } = await import(/* @vite-ignore */ moduleUrl);
  for (const name of [...contract.holdout, ...contract.anchor]) {
    it(name, async () => {
      const [result] = await probeCache(process.cwd(), [name]);
      expect(result.pass, result.error).toBe(true);
    });
  }
});
