import { describe, expect, it } from 'vitest';
import { LLMShield } from '../../src/shield';
import { ValidationError } from '../../src/types';
import type { ScannerType } from '../../src/types';

describe('explicit constructor scanner configuration', () => {
  for (const [name, scanners] of [
    ['null', null], ['false', false], ['zero', 0], ['empty string', ''], ['NaN', NaN],
  ] as const) {
    it(`rejects ${name} instead of silently selecting defaults`, () => {
      expect(() => new LLMShield({ scanners: scanners as unknown as ScannerType[] }))
        .toThrow(ValidationError);
    });
  }
});
