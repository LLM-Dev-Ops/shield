import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { contract, probeCache } from './probe-cache.mjs';
const [baseline, candidate, tools, output] = process.argv.slice(2).map(x => resolve(x));
const fw = await import(pathToFileURL(join(tools, 'node_modules/@metaharness/flywheel/dist/index.js')));
assert.equal(JSON.parse(readFileSync(join(tools, 'node_modules/@metaharness/flywheel/package.json'))).version, '0.1.12');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const source = root => readFileSync(join(root, 'src/shield.ts'), 'utf8');
const parentHash = hash(source(baseline)), candidateHash = hash(source(candidate));
assert.notEqual(parentHash, candidateHash);
const measurements = [];
let oldNames;
function regression(root) {
  const reportPath = join(mkdtempSync(join(tmpdir(), 'shield-cache-')), 'vitest.json');
  const run = spawnSync(process.execPath, [join(root, 'node_modules/vitest/vitest.mjs'), 'run', 'tests/unit', 'tests/integration', '--maxWorkers=2', '--minWorkers=1', '--reporter=json', '--outputFile=' + reportPath], { cwd: root, encoding: 'utf8', timeout: 60000, maxBuffer: 8 * 1024 * 1024, env: { PATH: process.env.PATH } });
  assert.equal(run.signal, null); assert.equal(run.status, 0, run.stderr);
  const assertions = JSON.parse(readFileSync(reportPath)).testResults.flatMap(x => x.assertionResults);
  assert(assertions.every(x => x.status === 'passed'));
  const names = assertions.map(x => x.fullName).sort();
  if (root === baseline) { assert.equal(names.length, 42); oldNames = names; }
  else { assert.equal(names.length, 62); assert(oldNames.every(x => names.includes(x))); }
  return { exit: run.status, assertions: names.length, retainedNames: oldNames, skipped: 0 };
}
const result = await fw.runFlywheelGenerations({
  rootPolicy: { cache: parentHash },
  proposer: async () => ({ value: candidateHash, summary: 'Isolate exact cache identities and result ownership; bypass contextual caching and honor disabled/LRU semantics', inverse: { path: 'src/shield.ts', parentBytes: source(baseline), hash: parentHash } }),
  evaluator: async (policy, suite) => {
    const root = policy.cache === parentHash ? baseline : candidate;
    assert.equal(hash(source(root)), policy.cache);
    const report = await probeCache(root, suite.id === 'holdout' ? contract.holdout : contract.anchor);
    const retained = suite.id === 'anchor' ? regression(root) : undefined;
    const wins = report.map(x => x.pass);
    if (retained) wins.push(true);
    const primary = wins.filter(Boolean).length / wins.length;
    const score = { primary, noopRate: 1 - primary, costPerWin: 0, regressed: suite.id === 'anchor' && wins.some(x => !x), itemWins: wins };
    measurements.push({ source: policy.cache, suite: suite.id, report, retained, score });
    assert.equal(hash(source(root)), policy.cache);
    return score;
  },
  holdout: { id: 'holdout', items: contract.holdout }, anchor: { id: 'anchor', items: [...contract.anchor, '42 original assertions retained'] },
  maxGenerations: 1, signer: fw.makeSigner(), promotionRule: fw.meetsPromotionRule, dataSource: 'LIVE_BUILT_WRAPPER_CACHE_BEHAVIOR',
});
const fingerprint = fw.gateFingerprint(fw.meetsPromotionRule);
const replay = fw.verifyReplayBundle(result.replayBundle, { pinnedGateFingerprint: fingerprint });
assert.equal(replay.pass, true); assert.equal(result.promotions.length, 1);
const evidence = { contract, contractSha256: hash(readFileSync(new URL('./cache-contract.json', import.meta.url))), probeSha256: hash(readFileSync(new URL('./probe-cache.mjs', import.meta.url))), parentHash, candidateHash, measurements, fingerprint, replay, replayBundle: result.replayBundle,
  scope: 'Component cache correctness only. Actual wrapper heuristics, not Rust/WASM/model efficacy or merge approval. No scanner mocks or production data. Zero costPerWin is a neutral gate input, not measured cost. Signed inverse restores exact parent source bytes; no deployed data rollback performed.' };
writeFileSync(output, JSON.stringify(evidence, null, 2) + '\n');
console.log(JSON.stringify({ promotions: result.promotions.length, replay, measurements: measurements.map(x => ({ suite: x.suite, passes: x.report.filter(y => y.pass).length, total: x.report.length, retained: x.retained?.assertions })) }));
