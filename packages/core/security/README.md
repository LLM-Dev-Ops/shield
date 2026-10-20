# Wrapper cache isolation

`cache-contract.json` and `probe-cache.mjs` were frozen against PR parent
`60bcd3c463228ee8c8ccadc4c7c560502d73e273` before the source correction.
The baseline passes 0/12 holdout cases, 8/8 anchors and all 42 original assertions.
Acceptance is 12/12, unchanged anchors, all original test names retained and zero
production npm advisories. Repository Rust/CI gates remain independently required.

This fixes the real TypeScript wrapper's cache, not its currently unimplemented
WASM initialization. Its existing heuristics are exercised without scanner mocks;
passing this contract is not evidence of Rust/model detection accuracy.

Keys preserve exact text, direction and an independently sorted scanner list.
This avoids 32-bit collisions and caller-array mutation. Result graphs are copied
on insertion and retrieval. Context/original-prompt scans bypass caching because
arbitrary context can be cyclic or mutable. Zero/negative capacity or TTL disables
caching, hits refresh LRU order without extending TTL, and expiration is inclusive.
Exact keys trade additional bounded in-process memory for collision-free identity;
the existing 100,000-character input and maximum-entry bounds still apply. No new
database or service persistence is added.

From `packages/core`, build before running `npm test` or the built-bundle probe:

```sh
npm ci --ignore-scripts
npm run build:rollup && npm run build:types
npm test
node security/probe-cache.mjs /absolute/path/to/packages/core
node security/evaluate-cache.mjs BASELINE_CORE CANDIDATE_CORE PINNED_TOOLS_PREFIX OUTPUT_JSON
node security/benchmark-cache.mjs BASELINE_CORE CANDIDATE_CORE OUTPUT_JSON
```

The evaluator requires Flywheel 0.1.12 and executes both revisions live, preserves
all original Vitest assertion names, signs one-generation lineage with exact parent
source bytes as its inverse, and verifies the frozen gate and replay. Cost is not
measured: zero is a neutral gate input. Five alternating contract trials retain raw
samples and do not claim production speedup. No production traffic/data is used.

Rollback before merge: close the PR. After an authorized merge, revert the cache
correction commit, rebuild and revalidate. The signed source inverse permits exact
byte restoration, but also restores the cache bugs; it is evidence, not an automatic
production rollback mechanism. Cached entries are ephemeral; no migration is needed.
