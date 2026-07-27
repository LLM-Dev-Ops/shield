# ADR-0001: Wire the Real ML Detection Path and Re-baseline Benchmarks on Real Hardware

**Status:** Proposed
**Date:** 2026-07-27

## Context

LLM Shield is positioned as an "Enterprise-grade LLM security framework" and "a high-performance rewrite of llm-guard in Rust, delivering **10x faster** prompt and output scanning" (`README.md:7-9`). Two classes of claim in that positioning are not supported by the code as it stands: the **ML detection** claims and the **performance** claims. Investigation found that these two claim sets describe mutually exclusive code paths — the numbers come from the heuristic path, the capability claims describe the ML path, and the two are presented as if they were one system.

### 1. The flagship scanner never attempts ML detection

`crates/llm-shield-scanners/src/input/prompt_injection.rs` documents itself as ML-based:

- `:7` — `//! This scanner detects prompt injection attacks using ML-based classification (DeBERTa model).`
- `:57` — `/// - ML-based detection using DeBERTa transformer model`

No model is ever loaded. The model fields are commented out of the struct entirely (`:78-83`):

```rust
pub struct PromptInjection {
    config: PromptInjectionConfig,
    // ML model would be loaded here in production
    // model: Option<Arc<InferenceEngine>>,
    // tokenizer: Option<Arc<TokenizerWrapper>>,
}
```

The constructor declines to load one (`:92-93`):

```rust
// In production, load ML model here if paths are provided
// For now, use fallback heuristic detection
```

And `detect_ml` is `#[allow(dead_code)]` and unconditionally returns an error without performing inference (`:236-245`):

```rust
#[allow(dead_code)]
fn detect_ml(&self, _text: &str) -> Result<(f32, Vec<InjectionIndicator>)> {
    // In production, this would:
    // 1. Tokenize input text
    // ...
    // For now, fall back to heuristic detection
    Err(Error::model("ML model not loaded, using fallback".to_string()))
}
```

**The control flow is inverted relative to its own documented intent.** `use_fallback` is documented as "Use fallback heuristic detection **if model unavailable**" (`:37-38`) and defaults to `true` (`:48`). But in `scan` (`:262-272`), that flag does not act as a fallback — it short-circuits *past* ML before ML is ever tried:

```rust
// Try ML detection first, fall back to heuristic
let (score, indicators) = if self.config.use_fallback {
    self.detect_heuristic(input)
} else {
    // In production, try ML first
    match self.detect_ml(input) { ... }
};
```

Under default configuration the `else` branch is unreachable. The comment says "Try ML detection first" directly above code that does the opposite.

**Detection method metadata is actively misleading** (`:319`):

```rust
.with_metadata("detection_method", if self.config.use_fallback { "heuristic" } else { "ml" })
```

This labels by *configuration flag*, not by *what actually ran*. Setting `use_fallback: false` makes `detect_ml` fail and fall through to `detect_heuristic` at `:269` — while the result is still stamped `detection_method: "ml"`. A downstream consumer auditing which detector fired would be told "ml" for a run that was 100% regex. This is the single most serious defect in the file: it defeats the audit trail a security product exists to provide.

### 2. The ML infrastructure is real, but structurally unreachable

`crates/llm-shield-models/` is **not** scaffolding. It contains genuine ONNX Runtime code — `Session::builder().commit_from_file(model_path)` (`crates/llm-shield-models/src/model_loader.rs:455-474`), real inference via `session.run(ort::inputs!["input_ids" => ..., "attention_mask" => ...])` with `try_extract_tensor::<f32>()` (`crates/llm-shield-models/src/inference.rs:436-456` for sequence classification, `:679-706` for token classification), a real HuggingFace tokenizer (`crates/llm-shield-models/src/tokenizer.rs:243, :322-324`), and real softmax/argmax/BIO decoding. There are no `todo!()` or `unimplemented!()` calls in these files.

The problem is not code quality. It is that **nothing connects to it.** Four independent breaks:

1. **No dependency edge.** `crates/llm-shield-scanners/Cargo.toml` declares exactly one intra-workspace dependency, `llm-shield-core`. It does not depend on `llm-shield-models`, `ort`, `tokenizers`, or `ndarray`. The scanners crate *cannot* reach the ML path — not "does not by default", but cannot compile a call to it. All scanners in that crate are regex/heuristic-only by construction.
2. **No live consumer.** The only type that consumes `InferenceEngine` is `NerDetector` (`crates/llm-shield-anonymize/src/detector/ner.rs:28, :134, :168`), and `NerDetector::new` is never called from any non-test, non-doc code path.
3. **No model weights.** `models/` contains only `README.md` and `registry.json` (36K total). A repo-wide search for `*.onnx`, `*.safetensors`, and `*.bin` returns nothing.
4. **The download manifest is non-functional.** `models/registry.json:39` carries placeholder checksums that are not valid hex (`"sha256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2"` — note `g`, `h`, `i`, …), which `verify_checksum` (`crates/llm-shield-models/src/registry.rs:473`) would reject, deleting every download at `:405-410`. Its schema also does not match `ModelMetadata` (`crates/llm-shield-models/src/registry.rs:61-75` requires `id`, `variant`, `url`, `checksum`, `size_bytes`; the JSON supplies `name`, `size_mb`, `download_url`), so `ModelRegistry::from_file` would fail to deserialize before reaching the network.

Consequently `README.md:27` — "**PII Detection** - ML-based Named Entity Recognition with DeBERTa-v3 (95-99% accuracy)" — advertises an accuracy figure for a code path that has never executed in this repository.

### 3. The benchmarks do not measure this software

The headline table (`README.md:40-52`) reports `0.03ms` latency, `23,815x faster`, and `15,500 req/sec`, footnoted:

> `README.md:52` — `*Environment: Simulated AWS c5.xlarge (4 vCPU, 8GB RAM), Ubuntu 22.04, Rust 1.75+*`

"Simulated" is a substantially weaker word than what the scripts actually do. **The Rust implementation itself is simulated — in Python.**

`benchmarks/scripts/bench_latency_runner.py:3` is titled `Latency Benchmark Runner (Simulated Rust Implementation)`, and `:31` describes the class as `"""Simulates Rust scanner latency with optimized algorithms."""`. No Rust code is invoked. The PromptInjection scenario times a Python `re.search` loop (`:252-255`):

```python
# Simulate heuristic-based detection (much faster than ML)
# In Rust, this would be even faster with optimized regex
matches = sum(1 for pattern in injection_patterns if pattern.search(prompt))
is_injection = matches >= 2  # Threshold-based detection
```

That measured value is then divided by a **hardcoded** Python baseline of `350.0` ms (`benchmarks/scripts/bench_latency_runner.py:335`: `"1D_PromptInjection": {"target_ms": 7.5, "python_ms": 350.0}`) to produce the `86,279x` figure in `benchmarks/results/LATENCY_BENCHMARK_REPORT.md:148`. So the comparison is: *Python llm-guard running DeBERTa transformer inference* versus *eight Python regex calls* — the ML workload on one side, the heuristic workload on the other, reported as a like-for-like speedup. The `23,815x` headline is the arithmetic mean of that and three sibling ratios (`LATENCY_BENCHMARK_REPORT.md:152`). The report itself concedes the point at `:165`: "Running in Python simulation vs actual Rust implementation may show different absolute numbers."

The throughput figure is not a measurement at all. `benchmarks/scripts/simulate_throughput_benchmark.py:11` states it "is used when actual benchmarks cannot be executed". `15,500` is a **hardcoded input constant** passed into the generator and echoed back as a result (`:131-141`):

```python
elif concurrency == 100:
    target_rps = 15500  # Peak performance
```

with latencies produced by `random.uniform` around an assumed `base_latency_ms` (`:24-37`). No server is contacted. `README.md:986` reports this as "Peak: **15,500 req/sec** at 100 concurrent connections".

Finally, `README.md:44` directs readers to `benchmarks/RESULTS.md` "for detailed methodology and complete data" as evidence that "🎯 **All performance claims validated**" (`README.md:43`). That document reports the opposite: `benchmarks/RESULTS.md:5` — `**Status:** 🚧 FRAMEWORK READY - Awaiting Benchmark Execution` — and `:17` — `| ⏳ **PENDING** | 0/18 | Benchmark infrastructure complete, awaiting execution |`. The cited proof states that zero of eighteen benchmarks have been run.

### Why this matters more than for typical over-claiming

This is a security product. A buyer selecting it for prompt-injection defense is making a risk decision on the strength of "DeBERTa transformer model." What they receive is ~30 hardcoded lowercase substring checks (`prompt_injection.rs:110-209`) with no semantic generalization — trivially evaded by paraphrase, translation, encoding, or typo — and, if they instrument the system to check, it will report `detection_method: "ml"`. Heuristics are a legitimate and genuinely fast first line of defense. Silently substituting them for an advertised classifier, and stamping the output "ml", is not.

## Decision

**We adopt option (a): complete the ML path and gate all "ML-powered" claims behind a runtime check that it is actually live — with an immediate, non-negotiable interim correction of public claims that ships before, and independently of, that engineering work.**

We choose (a) over permanently repositioning to a heuristics-only product because the evidence shows the ML path is **close, not absent**. The hard part — ONNX session management, tensor marshalling, tokenization, post-processing — is written and appears sound (§2). What is missing is four pieces of *wiring*: a Cargo dependency edge, a call site, model artifacts, and a valid registry file. That is a matter of weeks, not a rewrite. Discarding a working inference library because it has no callers would be the wrong trade.

But correctness of the claims cannot wait for that work. Therefore, in strict order:

1. **Immediately, before any ML work:** every ML capability claim and every performance number in public-facing docs is either removed, or relabeled to state plainly what it measures today. The product is described as heuristic-based, with ML as a documented roadmap item. No number derived from a simulation appears without the word "simulated" adjacent to it, and no simulated number appears in a headline comparison table at all.
2. **`detection_method` metadata becomes a fact, not a configuration echo** — reported by the code path that actually executed. This is a bug fix and ships with step 1.
3. **The heuristic path becomes explicit, never silent.** A caller who requests ML and does not get it must receive a loud, structured signal — not a silently downgraded result.
4. **Then** the ML path is wired end-to-end, and the "ML-powered" claims are re-enabled only for configurations where a model is verified loaded at runtime.
5. **All published performance numbers are re-measured on real hardware running real Rust**, or they are not published.

**Standing rule:** a capability claim in `README.md` must correspond to a code path reachable in a default or documented build, and a performance number must originate from an execution of this repository's compiled artifacts on disclosed physical hardware. Numbers from simulations, models, or estimates may exist in the repo for planning purposes but must be labeled `ESTIMATE — NOT MEASURED` at the point of use and must never appear in `README.md`.

## Consequences

**Accepted costs:**

- The headline changes from "10x faster / 23,815x" to real measured figures, which will be dramatically smaller. Real regex scanning in Rust against real Python llm-guard is plausibly a genuine 10–100x on comparable workloads — a strong, defensible result. The 23,815x figure was never real and its loss costs nothing but marketing copy.
- Once ML is live, latency will *increase* by orders of magnitude for ML-enabled scanners (transformer inference is milliseconds, not microseconds). This is the honest cost of the advertised capability and must be presented as a documented ML-vs-heuristic tradeoff, per-mode, rather than hidden.
- Binary size and cold-start claims (`README.md:44-48`) will regress once ONNX Runtime and model weights are actually shipped. The `24MB` native / `1.2MB` WASM figures do not include a model.
- Short-term: the project publicly looks less capable than its current README asserts. It will be *accurately* capable, which is the only durable position for a security vendor.

**Benefits:**

- `detection_method` becomes trustworthy, restoring the audit trail.
- Users can make correct risk decisions: heuristics are a reasonable choice for many threat models when chosen knowingly.
- Removes a material misrepresentation risk. Advertised-but-absent security controls with published accuracy figures (`95-99%`) carry real legal and reputational exposure in enterprise procurement.
- The `llm-shield-models` work stops being dead code and starts earning its maintenance cost.

**Risks if we do not act:** a user relies on advertised DeBERTa-grade injection defense, receives substring matching, is evaded by trivial paraphrase, and their instrumentation reports `detection_method: "ml"` throughout the incident.

## Implementation Plan

**Phase 1 — Truthfulness (blocking; ship before anything else)**

1. Fix the inverted control flow in `crates/llm-shield-scanners/src/input/prompt_injection.rs:262-272` so `use_fallback` means "fall back *if* ML fails" rather than "skip ML". Attempt `detect_ml` first whenever a model path is configured.
2. Replace the `detection_method` metadata at `prompt_injection.rs:319` so the value is set by the branch that actually executed (`"heuristic"` / `"onnx-deberta"`), never derived from a config flag. Apply the same fix to any scanner sharing this pattern — `toxicity.rs` and `sentiment.rs` carry the same `use_fallback` config shape.
3. Add a `detection_mode_degraded: bool` (or equivalent) to `ScanResult` metadata, set whenever ML was requested but heuristics ran, and emit a `tracing::warn!` at that site. Silent substitution must become impossible.
4. Make the strict case strict: when a caller explicitly requests ML (`use_fallback: false`), a missing model must return `Err`, not silently fall through to `detect_heuristic` as `prompt_injection.rs:269` currently allows.
5. `README.md` edits (this ADR does not modify the README; these are the required changes):
   - `:9` — remove "delivering **10x faster**" until re-measured.
   - `:19` — remove "⚡ **10x Performance**" or replace with a measured figure.
   - `:25` — change "🤖 **ML-Ready** - ONNX Runtime integration for transformer models" to state that the ONNX integration exists as a library but is not yet wired to any scanner.
   - `:27` — remove "(95-99% accuracy)" and the DeBERTa-v3 PII claim, or mark both explicitly `ROADMAP — NOT YET ACTIVE`. An accuracy figure for a never-executed path must not appear.
   - `:40-52` — delete the performance comparison table or replace every cell with measured values. At minimum, `:52` must change from "Simulated AWS c5.xlarge" to language that states the Rust implementation itself was simulated in Python and no Rust code was executed.
   - `:43-44` — remove "🎯 **All performance claims validated**"; it cites `benchmarks/RESULTS.md`, which reports `0/18` executed.
   - `:986` — remove or relabel the `15,500 req/sec` figure as a generator input constant.
   - `:1123` — remove "**Validated 10-100x improvement** ... (23,815x for latency)".
   - Add a "Detection Methods" section stating plainly: prompt injection, toxicity, and sentiment are heuristic/regex today; ML is roadmap.
6. Prepend a banner to `benchmarks/results/LATENCY_BENCHMARK_REPORT.md`, `benchmarks/results/THROUGHPUT_ANALYSIS_REPORT.md`, `benchmarks/results/THROUGHPUT_DELIVERABLES.md`, and `docs/archive/THROUGHPUT_BENCHMARK_COMPLETE.md`: `SIMULATED — NOT MEASURED. Generated by a Python model; no Rust code was executed.` Rename `benchmarks/scripts/bench_latency_runner.py` to `simulate_latency_benchmark.py` to match its sibling and stop it reading as a real runner.
7. Correct the word "Validated" wherever it describes a simulated result (`README.md:42-48`, `THROUGHPUT_ANALYSIS_REPORT.md:11`, `THROUGHPUT_DELIVERABLES.md:415`).

**Phase 2 — Real benchmarks on real hardware**

8. Implement a Criterion harness in `crates/llm-shield-benches/` that exercises the actual compiled scanners over `benchmarks/data/test_prompts.json`.
9. Implement a real load test (`oha`/`wrk`/`k6`) against a running `llm-shield-api` binary. Delete or clearly quarantine `simulate_throughput_benchmark.py` so its output can never again be cited as a measurement.
10. Establish the Python llm-guard baseline by *executing* llm-guard on the same hardware and same corpus. Remove the hardcoded `python_ms` constants (`bench_latency_runner.py:335`).
11. Run both on one disclosed physical machine (or a real, named cloud instance). Publish exact CPU model, RAM, OS, kernel, rustc version, and build profile. Compare like for like — heuristic-vs-heuristic, and later ML-vs-ML. Never heuristic-vs-ML.
12. Regenerate `benchmarks/RESULTS.md` from real data and flip its status off `AWAITING EXECUTION`.

**Phase 3 — Wire the ML path**

13. Add `llm-shield-models` as a dependency of `crates/llm-shield-scanners/Cargo.toml`, behind an `ml` feature flag so heuristic-only builds stay small and WASM-compatible.
14. Rewrite `models/registry.json` to match the `ModelMetadata` schema (`crates/llm-shield-models/src/registry.rs:61-75`): real `id`, `variant`, `url`, `size_bytes`, and genuine SHA-256 checksums. Replace the placeholder hash at `:39` and confirm the `ModelTask` serde casing matches.
15. Publish or vendor actual ONNX weights (e.g. `protectai/deberta-v3-base-prompt-injection-v2` exported to ONNX) at real, reachable URLs, with a `scripts/fetch-models.sh` that downloads and checksum-verifies them.
16. Implement `PromptInjection::detect_ml` for real: restore the `model`/`tokenizer` fields removed at `prompt_injection.rs:80-82`, load via `ModelLoader`, tokenize, run `InferenceEngine`, map logits to a score. Remove `#[allow(dead_code)]`.
17. Instantiate `NerDetector` (`crates/llm-shield-anonymize/src/detector/ner.rs`) from the anonymizer's production path so the DeBERTa PII claim has a live caller.
18. Add a startup self-check that logs, per scanner, which detection backend is live, and expose it on the API health endpoint so operators can see at a glance whether they are running ML or heuristics.
19. Only after 13–18 pass verification, restore ML claims to `README.md` — scoped to the `ml` feature build, with measured accuracy from step 22.

**Phase 4 — Guardrails**

20. Add a CI check that fails if `README.md` gains a performance number not present in the generated real-benchmark output, and that greps for the retired literals (`23,815`, `15,500`, `0.03ms`) outside explicitly-labeled historical/archive files.

## Verification

None of the above is complete until the following produce evidence, not assertions:

1. **Corpus-through-live-path detection-method audit (primary).** Assemble a labeled prompt-injection corpus (≥500 positive, ≥500 benign; seed from `benchmarks/data/test_prompts.json` plus a public injection set). Run it through the real compiled scanner via the public `Scanner::scan` API in both `use_fallback: true` and `use_fallback: false` configurations, and log `detection_method` for **every** result. Assert: (a) in default/heuristic mode, 100% of results report `heuristic` and none report `ml`; (b) in ML mode with a model present, 100% report the ML backend; (c) in ML mode with the model *absent*, the call errors — it does not return a result stamped `ml`. Failure of (c) reproduces the current defect and must be a hard test failure. This test must exist as a committed integration test, not a one-off script.
2. **Provenance test for the metadata bug.** A unit test constructing `PromptInjection` with `use_fallback: false` and no model path must assert the result is an `Err` or is stamped `heuristic` + `degraded` — and must fail against today's `prompt_injection.rs:319`, confirming it pins the actual bug.
3. **Reachability proof.** `cargo tree -p llm-shield-scanners --features ml | grep llm-shield-models` must return a match. Independently, remove `llm-shield-models` from the workspace and confirm `--features ml` fails to compile — proving the edge is load-bearing rather than decorative.
4. **Model artifact verification.** `scripts/fetch-models.sh` must download real weights and pass SHA-256 verification via `verify_checksum` (`registry.rs:473`) on a clean checkout. `ModelRegistry::from_file("models/registry.json")` must deserialize without error — a direct test of defect §2.4.
5. **Live inference proof.** An integration test must load a real ONNX model, run a known injection string, and assert a score consistent with the published model card — proving `session.run` (`inference.rs:436-456`) executes on real weights rather than being merely compiled.
6. **Accuracy measurement.** Report precision, recall, and F1 for both the heuristic and ML paths on the held-out corpus. Publish both. If the heuristic path performs acceptably, that is a genuine selling point earned by data. The 95-99% figure at `README.md:27` may only be restored if reproduced by this measurement on this code.
7. **Adversarial robustness.** Include paraphrased, translated, base64-encoded, and typo-perturbed variants of the positive set. The heuristic path is expected to degrade sharply; that delta is the honest quantification of what "ML-powered" is actually worth, and belongs in the docs.
8. **Benchmark provenance audit.** Every number in the final `README.md` table must be traceable to a committed raw output file containing the hardware fingerprint and timestamp of a real run. Any number without such a file is removed. Re-run `grep -rn "Simulated\|simulate" README.md` and confirm no simulated figure remains in a headline table.
