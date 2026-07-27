//! ADR-0001 Verification §1 — corpus-through-live-path detection-method audit.
//!
//! Runs a labeled corpus through the real compiled `Scanner::scan` API in three
//! configurations and asserts that `detection_method` always describes the backend
//! that actually executed. This is the committed integration test the ADR requires
//! in place of a one-off script.

use llm_shield_core::{Error, ScanResult, Scanner, Vault};
use llm_shield_scanners::input::{PromptInjection, PromptInjectionConfig};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(serde::Deserialize)]
struct CorpusEntry {
    id: String,
    text: String,
    category: String,
}

fn load_corpus() -> Vec<CorpusEntry> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../benchmarks/data/test_prompts.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read corpus at {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("corpus is not valid JSON")
}

fn detection_method(result: &ScanResult) -> &str {
    result
        .metadata
        .get("detection_method")
        .and_then(|v| v.as_str())
        .expect("every ScanResult must carry detection_method")
}

fn degraded(result: &ScanResult) -> bool {
    result
        .metadata
        .get("detection_mode_degraded")
        .and_then(|v| v.as_bool())
        .expect("every ScanResult must carry detection_mode_degraded")
}

/// §1(a) — default/heuristic mode: 100% of results report `heuristic`, none report ML.
#[tokio::test]
async fn heuristic_mode_never_reports_ml_over_full_corpus() {
    let corpus = load_corpus();
    assert!(
        corpus.len() >= 1000,
        "corpus unexpectedly small: {}",
        corpus.len()
    );

    let scanner = PromptInjection::default_config().unwrap();
    let vault = Vault::new();

    let mut methods: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_category: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut degraded_count = 0usize;

    for entry in &corpus {
        let result = scanner
            .scan(&entry.text, &vault)
            .await
            .unwrap_or_else(|e| panic!("default config must never error (id={}): {e}", entry.id));

        let method = detection_method(&result).to_string();
        assert_eq!(
            method, "heuristic",
            "id={} reported detection_method={method}, but heuristics ran",
            entry.id
        );
        if degraded(&result) {
            degraded_count += 1;
        }

        *methods.entry(method.clone()).or_default() += 1;
        *by_category
            .entry(entry.category.clone())
            .or_default()
            .entry(method)
            .or_default() += 1;
    }

    println!("[heuristic mode] n={} methods={methods:?}", corpus.len());
    println!("[heuristic mode] by category: {by_category:?}");

    assert_eq!(methods.get("ml"), None, "the literal \"ml\" must never appear");
    assert_eq!(methods.get("onnx-deberta"), None, "no ML backend ran");
    assert_eq!(methods.get("heuristic"), Some(&corpus.len()));
    assert_eq!(
        degraded_count, 0,
        "no ML was requested, so nothing is degraded"
    );
}

/// §1(c) — ML required but model absent: the call errors. It does **not** return a
/// result stamped with an ML backend. Failure here reproduces the ADR-0001 defect.
#[tokio::test]
async fn ml_required_with_model_absent_errors_over_full_corpus() {
    let corpus = load_corpus();

    let scanner = PromptInjection::new(PromptInjectionConfig {
        use_fallback: false,
        model_path: None,
        ..Default::default()
    })
    .unwrap();
    let vault = Vault::new();

    let mut errored = 0usize;
    for entry in &corpus {
        match scanner.scan(&entry.text, &vault).await {
            Err(Error::Model(_)) => errored += 1,
            Err(e) => panic!("id={} expected a model error, got: {e:?}", entry.id),
            Ok(result) => panic!(
                "id={} returned a result stamped detection_method={} despite no model \
                 being available; this is the ADR-0001 audit-trail defect",
                entry.id,
                detection_method(&result)
            ),
        }
    }

    println!("[ml-required, model absent] n={} errored={errored}", corpus.len());
    assert_eq!(errored, corpus.len());
}

/// ML requested with an unloadable model and fallback permitted: heuristics may run,
/// but every result must self-report as heuristic *and* degraded.
#[tokio::test]
async fn ml_unavailable_with_fallback_reports_heuristic_and_degraded() {
    let corpus = load_corpus();

    let scanner = PromptInjection::new(PromptInjectionConfig {
        use_fallback: true,
        model_path: Some(PathBuf::from("/nonexistent/deberta-v3-injection.onnx")),
        ..Default::default()
    })
    .unwrap();
    let vault = Vault::new();

    let mut degraded_count = 0usize;
    for entry in &corpus {
        let result = scanner.scan(&entry.text, &vault).await.unwrap();

        assert_eq!(
            detection_method(&result),
            "heuristic",
            "id={} ran heuristics and must say so",
            entry.id
        );
        assert!(
            degraded(&result),
            "id={} silently substituted heuristics for a requested ML run",
            entry.id
        );
        degraded_count += 1;
    }

    println!(
        "[ml-requested, unavailable] n={} degraded={degraded_count}",
        corpus.len()
    );
    assert_eq!(degraded_count, corpus.len());
}
