import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { probeCache } from './probe-cache.mjs';
const [baseline, candidate, output] = process.argv.slice(2).map(x => resolve(x));
const trials = [];
for (let i = 0; i < 5; i++) for (const variant of i % 2 ? ['candidate', 'baseline'] : ['baseline', 'candidate']) {
  const start = performance.now(); const cases = await probeCache(variant === 'baseline' ? baseline : candidate);
  trials.push({ trial: i, variant, ms: performance.now() - start, cases });
}
const summary = Object.fromEntries(['baseline', 'candidate'].map(variant => { const rows = trials.filter(x => x.variant === variant); const sorted = rows.map(x => x.ms).sort((a,b) => a-b); return [variant, { suiteMedianMs: sorted[2], passed: rows.flatMap(x => x.cases).filter(x => x.pass).length, total: 100 }]; }));
writeFileSync(output, JSON.stringify({ trials, summary, scope: 'Five alternating fresh-instance wrapper contract trials, including initialization. Not WASM/model throughput, production latency or cost. No speedup claimed.' }, null, 2) + '\n');
console.log(JSON.stringify(summary));
