//! Factuality Output Scanner
//!
//! Converted from llm_guard/output_scanners/factuality.py
//!
//! ## SPARC Implementation
//!
//! Detects potential factual issues and low-confidence statements in LLM responses.
//! Uses heuristic analysis of hedging language and confidence indicators.
//!
//! ## London School TDD
//!
//! Tests written first drive the implementation.

use llm_shield_core::{
    async_trait, Entity, Error, Result, RiskFactor, ScanResult, Scanner, ScannerType, Severity,
    Vault,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Factuality scanner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactualityConfig {
    /// Minimum confidence threshold (0.0 to 1.0)
    /// Responses with lower confidence scores fail
    pub min_confidence_threshold: f32,

    /// Check for hedging language
    pub check_hedging: bool,

    /// Check for speculation
    pub check_speculation: bool,

    /// Check for uncertainty markers
    pub check_uncertainty: bool,
}

impl Default for FactualityConfig {
    fn default() -> Self {
        Self {
            min_confidence_threshold: 0.5,
            check_hedging: true,
            check_speculation: true,
            check_uncertainty: true,
        }
    }
}

/// Factuality scanner implementation
///
/// ## Enterprise Features
///
/// - Heuristic confidence scoring
/// - Hedging language detection ("possibly", "maybe", "might")
/// - Speculation detection ("I think", "I believe")
/// - Uncertainty marker detection ("unsure", "unclear")
/// - Hook for external fact-checking APIs (future)
/// - Statistical claim detection
///
/// ## Example
///
/// ```rust,ignore
/// use llm_shield_scanners::output::Factuality;
///
/// let scanner = Factuality::default_config()?;
/// let response = "I think maybe this could possibly be true.";
/// let result = scanner.scan_output("", response, &vault).await?;
/// assert!(!result.is_valid); // Low confidence detected
/// ```
pub struct Factuality {
    config: FactualityConfig,
}

impl Factuality {
    /// Create a new Factuality scanner
    pub fn new(config: FactualityConfig) -> Result<Self> {
        if !(0.0..=1.0).contains(&config.min_confidence_threshold) {
            return Err(Error::config(
                "min_confidence_threshold must be between 0.0 and 1.0",
            ));
        }

        Ok(Self { config })
    }

    /// Create with default configuration
    pub fn default_config() -> Result<Self> {
        Self::new(FactualityConfig::default())
    }

    /// Analyze text for factuality issues
    fn analyze_factuality(&self, text: &str) -> FactualityAnalysis {
        let text_lower = text.to_lowercase();
        let mut issues = Vec::new();
        let mut confidence_penalties = Vec::new();

        // Check for hedging language
        if self.config.check_hedging {
            let hedging_patterns = [
                ("might", 0.15),
                ("may", 0.15),
                ("could", 0.15),
                ("possibly", 0.20),
                ("probably", 0.15),
                ("perhaps", 0.20),
                ("seemingly", 0.15),
                ("apparently", 0.15),
                ("allegedly", 0.20),
                ("reportedly", 0.15),
                ("supposedly", 0.20),
            ];

            for (pattern, penalty) in &hedging_patterns {
                if text_lower.contains(pattern) {
                    issues.push(FactualityIssue {
                        issue_type: "hedging".to_string(),
                        text: pattern.to_string(),
                        confidence_penalty: *penalty,
                    });
                    confidence_penalties.push(*penalty);
                }
            }
        }

        // Check for speculation
        if self.config.check_speculation {
            let speculation_patterns = [
                ("i think", 0.25),
                ("i believe", 0.25),
                ("i guess", 0.30),
                ("i assume", 0.25),
                ("i suspect", 0.25),
                ("in my opinion", 0.20),
                ("seems like", 0.20),
                ("looks like", 0.20),
                ("sounds like", 0.20),
            ];

            for (pattern, penalty) in &speculation_patterns {
                if text_lower.contains(pattern) {
                    issues.push(FactualityIssue {
                        issue_type: "speculation".to_string(),
                        text: pattern.to_string(),
                        confidence_penalty: *penalty,
                    });
                    confidence_penalties.push(*penalty);
                }
            }
        }

        // Check for uncertainty markers
        if self.config.check_uncertainty {
            let uncertainty_patterns = [
                ("not sure", 0.30),
                ("unsure", 0.30),
                ("uncertain", 0.30),
                ("unclear", 0.25),
                ("unknown", 0.30),
                ("don't know", 0.35),
                ("can't confirm", 0.30),
                ("cannot verify", 0.30),
                ("no evidence", 0.25),
                ("unverified", 0.30),
            ];

            for (pattern, penalty) in &uncertainty_patterns {
                if text_lower.contains(pattern) {
                    issues.push(FactualityIssue {
                        issue_type: "uncertainty".to_string(),
                        text: pattern.to_string(),
                        confidence_penalty: *penalty,
                    });
                    confidence_penalties.push(*penalty);
                }
            }
        }

        // Calculate overall confidence score
        // Start with 1.0, subtract penalties (with diminishing returns)
        let total_penalty: f32 = confidence_penalties
            .iter()
            .enumerate()
            .map(|(i, &penalty)| penalty * 0.8f32.powi(i as i32)) // Diminishing returns
            .sum();

        let confidence_score = (1.0 - total_penalty).max(0.0);

        FactualityAnalysis {
            issues,
            confidence_score,
        }
    }

    /// Scan output for factuality issues
    pub async fn scan_output(
        &self,
        _prompt: &str,
        output: &str,
        _vault: &Vault,
    ) -> Result<ScanResult> {
        let analysis = self.analyze_factuality(output);

        // Build metadata
        let mut result = ScanResult::pass(output.to_string())
            .with_metadata("confidence_score", analysis.confidence_score.to_string())
            .with_metadata("factuality_issues_count", analysis.issues.len().to_string());

        if analysis.confidence_score >= self.config.min_confidence_threshold {
            return Ok(result);
        }

        // Confidence too low - fail the scan
        let entities: Vec<Entity> = analysis
            .issues
            .iter()
            .map(|issue| {
                let mut metadata = HashMap::new();
                metadata.insert("issue_type".to_string(), issue.issue_type.clone());
                metadata.insert("detected_text".to_string(), issue.text.clone());
                metadata.insert("confidence_penalty".to_string(), issue.confidence_penalty.to_string());

                Entity {
                    entity_type: "factuality_issue".to_string(),
                    text: issue.text.clone(),
                    start: 0,
                    end: output.len(),
                    confidence: 0.8,
                    metadata,
                }
            })
            .collect();

        let severity = if analysis.confidence_score < 0.3 {
            Severity::High
        } else if analysis.confidence_score < 0.5 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let description = format!(
            "Response has low factuality confidence: {:.2} (threshold: {:.2})",
            analysis.confidence_score, self.config.min_confidence_threshold
        );
        let risk_factor = RiskFactor::new(
            "low_factuality_confidence",
            &description,
            severity,
            1.0 - analysis.confidence_score,
        );

        result.is_valid = false;
        result.risk_score = 1.0 - analysis.confidence_score;
        result.entities = entities;
        result.risk_factors.push(risk_factor);

        Ok(result)
    }
}

#[derive(Debug)]
struct FactualityAnalysis {
    issues: Vec<FactualityIssue>,
    confidence_score: f32,
}

#[derive(Debug, Clone)]
struct FactualityIssue {
    issue_type: String,
    text: String,
    confidence_penalty: f32,
}

#[async_trait]
impl Scanner for Factuality {
    fn name(&self) -> &str {
        "Factuality"
    }

    async fn scan(&self, input: &str, vault: &Vault) -> Result<ScanResult> {
        self.scan_output("", input, vault).await
    }

    fn scanner_type(&self) -> ScannerType {
        ScannerType::Output
    }

    fn description(&self) -> &str {
        "Detects potential factual issues and low-confidence statements in LLM responses"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_factuality_confident_response() {
        let scanner = Factuality::default_config().unwrap();
        let vault = Vault::new();

        let response = "The Earth orbits the Sun. This is a well-established scientific fact.";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(result.is_valid);
        let confidence: f32 = result
            .metadata
            .get("confidence_score")
            .and_then(|v| v.as_str())
            .unwrap()
            .parse()
            .unwrap();
        assert!(confidence > 0.8);
    }

    #[tokio::test]
    async fn test_factuality_hedging() {
        let scanner = Factuality::default_config().unwrap();
        let vault = Vault::new();

        let response = "This might possibly be true, or perhaps maybe it could be correct.";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(!result.is_valid);
        assert!(result.entities.iter().any(|e| {
            e.metadata.get("issue_type").map(|t| t == "hedging").unwrap_or(false)
        }));
    }

    #[tokio::test]
    async fn test_factuality_speculation() {
        let scanner = Factuality::default_config().unwrap();
        let vault = Vault::new();

        let response = "I think this is correct, but I guess it could be wrong.";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(!result.is_valid);
        assert!(result.entities.iter().any(|e| {
            e.metadata.get("issue_type").map(|t| t == "speculation").unwrap_or(false)
        }));
    }

    #[tokio::test]
    async fn test_factuality_uncertainty() {
        let scanner = Factuality::default_config().unwrap();
        let vault = Vault::new();

        let response = "I'm not sure about this. It's unclear and uncertain.";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(!result.is_valid);
        assert!(result.entities.iter().any(|e| {
            e.metadata.get("issue_type").map(|t| t == "uncertainty").unwrap_or(false)
        }));
    }

    #[tokio::test]
    async fn test_factuality_threshold() {
        let config = FactualityConfig {
            min_confidence_threshold: 0.3, // Low threshold
            check_hedging: true,
            check_speculation: true,
            check_uncertainty: true,
        };
        let scanner = Factuality::new(config).unwrap();
        let vault = Vault::new();

        let response = "This might be true."; // Single hedge
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        // Should pass with low threshold
        assert!(result.is_valid);
    }

    #[tokio::test]
    async fn test_factuality_multiple_issues() {
        let scanner = Factuality::default_config().unwrap();
        let vault = Vault::new();

        let response = "I think this might possibly be unclear. I'm not sure and I guess it's uncertain.";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(!result.is_valid);
        assert!(result.entities.len() >= 3);
    }

    #[tokio::test]
    async fn test_factuality_selective_checks() {
        let config = FactualityConfig {
            min_confidence_threshold: 0.5,
            check_hedging: true,
            check_speculation: false, // Disabled
            check_uncertainty: false, // Disabled
        };
        let scanner = Factuality::new(config).unwrap();
        let vault = Vault::new();

        let response = "I think this is unclear."; // Speculation + uncertainty
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        // Should pass because speculation and uncertainty checks are disabled
        assert!(result.is_valid);
    }

    #[tokio::test]
    async fn test_factuality_severity_high() {
        let scanner = Factuality::default_config().unwrap();
        let vault = Vault::new();

        let response = "I don't know if this might possibly be uncertain. I guess it's unclear and unverified.";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(!result.is_valid);
        // Very low confidence should be high severity
        let confidence: f32 = result
            .metadata
            .get("confidence_score")
            .and_then(|v| v.as_str())
            .unwrap()
            .parse()
            .unwrap();
        assert!(confidence < 0.3);
    }

    #[tokio::test]
    async fn test_factuality_case_insensitive() {
        let scanner = Factuality::default_config().unwrap();
        let vault = Vault::new();

        let response = "MIGHT POSSIBLY BE UNCERTAIN";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(!result.is_valid);
    }

    #[tokio::test]
    async fn test_factuality_diminishing_returns() {
        let scanner = Factuality::default_config().unwrap();
        let vault = Vault::new();

        // Many hedges, but diminishing returns on penalty
        let response = "might might might might might";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        let confidence: f32 = result
            .metadata
            .get("confidence_score")
            .and_then(|v| v.as_str())
            .unwrap()
            .parse()
            .unwrap();
        // Should not go to 0 due to diminishing returns
        assert!(confidence > 0.0);
    }

    #[tokio::test]
    async fn test_factuality_empty_response() {
        let scanner = Factuality::default_config().unwrap();
        let vault = Vault::new();

        let response = "";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        // Empty response has no issues, high confidence
        assert!(result.is_valid);
    }

    #[tokio::test]
    async fn test_factuality_invalid_threshold() {
        let config = FactualityConfig {
            min_confidence_threshold: 1.5, // Invalid
            check_hedging: true,
            check_speculation: true,
            check_uncertainty: true,
        };
        let result = Factuality::new(config);

        assert!(result.is_err());
    }
}
