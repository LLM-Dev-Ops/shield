//! ReadingTime Output Scanner
//!
//! Converted from llm_guard/output_scanners/reading_time.py
//!
//! ## SPARC Implementation
//!
//! Validates LLM response length based on estimated reading time.
//! Prevents excessively long or short responses.
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

/// ReadingTime scanner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadingTimeConfig {
    /// Maximum reading time in seconds
    pub max_time_seconds: u32,

    /// Minimum reading time in seconds
    pub min_time_seconds: u32,

    /// Average reading speed in words per minute
    pub words_per_minute: u32,
}

impl Default for ReadingTimeConfig {
    fn default() -> Self {
        Self {
            max_time_seconds: 300,  // 5 minutes
            min_time_seconds: 5,    // 5 seconds
            words_per_minute: 200,  // Average adult reading speed
        }
    }
}

/// ReadingTime scanner implementation
///
/// ## Enterprise Features
///
/// - Calculates estimated reading time based on word count
/// - Configurable min/max time limits
/// - Adjustable reading speed (WPM)
/// - Character and sentence counting
/// - Prevents token/cost abuse
///
/// ## Example
///
/// ```rust,ignore
/// use llm_shield_scanners::output::ReadingTime;
///
/// let config = ReadingTimeConfig {
///     max_time_seconds: 60,
///     min_time_seconds: 5,
///     words_per_minute: 200,
/// };
/// let scanner = ReadingTime::new(config)?;
///
/// let response = "Short.";
/// let result = scanner.scan_output("", &response, &vault).await?;
/// assert!(!result.is_valid); // Too short
/// ```
pub struct ReadingTime {
    config: ReadingTimeConfig,
}

impl ReadingTime {
    /// Create a new ReadingTime scanner
    pub fn new(config: ReadingTimeConfig) -> Result<Self> {
        if config.max_time_seconds <= config.min_time_seconds {
            return Err(Error::config(
                "max_time_seconds must be greater than min_time_seconds",
            ));
        }

        if config.words_per_minute == 0 {
            return Err(Error::config("words_per_minute must be greater than 0"));
        }

        Ok(Self { config })
    }

    /// Create with default configuration
    pub fn default_config() -> Result<Self> {
        Self::new(ReadingTimeConfig::default())
    }

    /// Calculate reading time statistics
    fn calculate_reading_time(&self, text: &str) -> ReadingTimeStats {
        // Count words
        let word_count = text
            .split_whitespace()
            .filter(|w| !w.is_empty())
            .count();

        // Count characters (excluding whitespace)
        let char_count = text.chars().filter(|c| !c.is_whitespace()).count();

        // Count sentences (rough heuristic)
        let sentence_count = text
            .chars()
            .filter(|c| matches!(c, '.' | '!' | '?'))
            .count()
            .max(1); // At least 1 sentence

        // Calculate reading time in seconds
        let reading_time_seconds = if word_count > 0 {
            (word_count as f32 / self.config.words_per_minute as f32 * 60.0) as u32
        } else {
            0
        };

        ReadingTimeStats {
            word_count,
            char_count,
            sentence_count,
            reading_time_seconds,
        }
    }

    /// Check if reading time is within acceptable range
    fn is_valid_reading_time(&self, stats: &ReadingTimeStats) -> ValidationResult {
        if stats.reading_time_seconds < self.config.min_time_seconds {
            ValidationResult::TooShort
        } else if stats.reading_time_seconds > self.config.max_time_seconds {
            ValidationResult::TooLong
        } else {
            ValidationResult::Valid
        }
    }

    /// Scan output for reading time constraints
    pub async fn scan_output(
        &self,
        _prompt: &str,
        output: &str,
        _vault: &Vault,
    ) -> Result<ScanResult> {
        let stats = self.calculate_reading_time(output);
        let validation = self.is_valid_reading_time(&stats);

        // Build metadata
        let mut result = ScanResult::pass(output.to_string())
            .with_metadata("word_count", stats.word_count.to_string())
            .with_metadata("char_count", stats.char_count.to_string())
            .with_metadata("sentence_count", stats.sentence_count.to_string())
            .with_metadata("reading_time_seconds", stats.reading_time_seconds.to_string())
            .with_metadata("min_time_seconds", self.config.min_time_seconds.to_string())
            .with_metadata("max_time_seconds", self.config.max_time_seconds.to_string());

        match validation {
            ValidationResult::Valid => Ok(result),
            ValidationResult::TooShort => {
                let mut metadata = HashMap::new();
                metadata.insert("word_count".to_string(), stats.word_count.to_string());
                metadata.insert("reading_time_seconds".to_string(), stats.reading_time_seconds.to_string());
                metadata.insert("min_time_seconds".to_string(), self.config.min_time_seconds.to_string());
                metadata.insert("violation".to_string(), "too_short".to_string());

                let entity = Entity {
                    entity_type: "reading_time_violation".to_string(),
                    text: "Response too short".to_string(),
                    start: 0,
                    end: output.len(),
                    confidence: 0.95,
                    metadata,
                };

                let description = format!(
                    "Response too short: {} seconds (min: {})",
                    stats.reading_time_seconds, self.config.min_time_seconds
                );
                let risk_factor = RiskFactor::new(
                    "reading_time_too_short",
                    &description,
                    Severity::Low,
                    0.7,
                );

                result.is_valid = false;
                result.risk_score = 0.7;
                result.entities.push(entity);
                result.risk_factors.push(risk_factor);

                Ok(result)
            }
            ValidationResult::TooLong => {
                let mut metadata = HashMap::new();
                metadata.insert("word_count".to_string(), stats.word_count.to_string());
                metadata.insert("reading_time_seconds".to_string(), stats.reading_time_seconds.to_string());
                metadata.insert("max_time_seconds".to_string(), self.config.max_time_seconds.to_string());
                metadata.insert("violation".to_string(), "too_long".to_string());

                let entity = Entity {
                    entity_type: "reading_time_violation".to_string(),
                    text: "Response too long".to_string(),
                    start: 0,
                    end: output.len(),
                    confidence: 0.95,
                    metadata,
                };

                let description = format!(
                    "Response too long: {} seconds (max: {})",
                    stats.reading_time_seconds, self.config.max_time_seconds
                );
                let risk_factor = RiskFactor::new(
                    "reading_time_too_long",
                    &description,
                    Severity::Medium,
                    0.8,
                );

                result.is_valid = false;
                result.risk_score = 0.8;
                result.entities.push(entity);
                result.risk_factors.push(risk_factor);

                Ok(result)
            }
        }
    }
}

#[derive(Debug)]
struct ReadingTimeStats {
    word_count: usize,
    char_count: usize,
    sentence_count: usize,
    reading_time_seconds: u32,
}

#[derive(Debug, PartialEq)]
enum ValidationResult {
    Valid,
    TooShort,
    TooLong,
}

#[async_trait]
impl Scanner for ReadingTime {
    fn name(&self) -> &str {
        "ReadingTime"
    }

    async fn scan(&self, input: &str, vault: &Vault) -> Result<ScanResult> {
        self.scan_output("", input, vault).await
    }

    fn scanner_type(&self) -> ScannerType {
        ScannerType::Output
    }

    fn description(&self) -> &str {
        "Validates LLM response length based on estimated reading time"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_reading_time_valid() {
        let scanner = ReadingTime::default_config().unwrap();
        let vault = Vault::new();

        // About 30 words = ~9 seconds reading time at 200 WPM
        let response = "This is a moderate length response with enough content to be useful but not overly verbose. It should pass the reading time validation without any issues. The response provides helpful information in a concise manner.";
        let result = scanner.scan_output("", &response, &vault).await.unwrap();

        assert!(result.is_valid);
        assert!(result.metadata.contains_key("reading_time_seconds"));
    }

    #[tokio::test]
    async fn test_reading_time_too_short() {
        let scanner = ReadingTime::default_config().unwrap();
        let vault = Vault::new();

        let response = "Short.";
        let result = scanner.scan_output("", &response, &vault).await.unwrap();

        assert!(!result.is_valid);
        assert!(result.entities.iter().any(|e| {
            e.metadata.get("violation").map(|v| v == "too_short").unwrap_or(false)
        }));
    }

    #[tokio::test]
    async fn test_reading_time_too_long() {
        let config = ReadingTimeConfig {
            max_time_seconds: 30,
            min_time_seconds: 5,
            words_per_minute: 200,
        };
        let scanner = ReadingTime::new(config).unwrap();
        let vault = Vault::new();

        // Generate very long response (>100 words = >30 seconds)
        let response = "This is a very long response. ".repeat(150);
        let result = scanner.scan_output("", &response, &vault).await.unwrap();

        assert!(!result.is_valid);
        assert!(result.entities.iter().any(|e| {
            e.metadata.get("violation").map(|v| v == "too_long").unwrap_or(false)
        }));
    }

    #[tokio::test]
    async fn test_reading_time_custom_wpm() {
        let config = ReadingTimeConfig {
            max_time_seconds: 60,
            min_time_seconds: 5,
            words_per_minute: 100, // Slower reading speed
        };
        let scanner = ReadingTime::new(config).unwrap();
        let vault = Vault::new();

        let response = "This is a test response with twenty words in total. " .repeat(2);
        let result = scanner.scan_output("", &response, &vault).await.unwrap();

        // At 100 WPM, 20 words = 12 seconds
        assert!(result.is_valid);
        let reading_time = result
            .metadata
            .get("reading_time_seconds")
            .and_then(|v| v.as_str())
            .unwrap()
            .parse::<u32>()
            .unwrap();
        assert!(reading_time > 5 && reading_time < 60);
    }

    #[tokio::test]
    async fn test_reading_time_word_count() {
        let scanner = ReadingTime::default_config().unwrap();
        let vault = Vault::new();

        let response = "One two three four five six seven eight nine ten";
        let result = scanner.scan_output("", &response, &vault).await.unwrap();

        assert_eq!(result.metadata.get("word_count").unwrap(), "10");
    }

    #[tokio::test]
    async fn test_reading_time_sentence_count() {
        let scanner = ReadingTime::default_config().unwrap();
        let vault = Vault::new();

        let response = "First sentence. Second sentence! Third sentence?";
        let result = scanner.scan_output("", &response, &vault).await.unwrap();

        assert_eq!(result.metadata.get("sentence_count").unwrap(), "3");
    }

    #[tokio::test]
    async fn test_reading_time_empty_response() {
        let scanner = ReadingTime::default_config().unwrap();
        let vault = Vault::new();

        let response = "";
        let result = scanner.scan_output("", &response, &vault).await.unwrap();

        assert!(!result.is_valid); // Empty is too short
        assert_eq!(result.metadata.get("word_count").unwrap(), "0");
    }

    #[tokio::test]
    async fn test_reading_time_boundary_min() {
        let config = ReadingTimeConfig {
            max_time_seconds: 300,
            min_time_seconds: 3,
            words_per_minute: 200,
        };
        let scanner = ReadingTime::new(config).unwrap();
        let vault = Vault::new();

        // Exactly at boundary: 10 words at 200 WPM = 3 seconds
        let response = "One two three four five six seven eight nine ten";
        let result = scanner.scan_output("", &response, &vault).await.unwrap();

        assert!(result.is_valid);
    }

    #[tokio::test]
    async fn test_reading_time_boundary_max() {
        let config = ReadingTimeConfig {
            max_time_seconds: 6,
            min_time_seconds: 1,
            words_per_minute: 200,
        };
        let scanner = ReadingTime::new(config).unwrap();
        let vault = Vault::new();

        // Exactly at boundary: 20 words at 200 WPM = 6 seconds
        let response = "word ".repeat(20);
        let result = scanner.scan_output("", &response, &vault).await.unwrap();

        assert!(result.is_valid);
    }

    #[tokio::test]
    async fn test_reading_time_invalid_config() {
        let config = ReadingTimeConfig {
            max_time_seconds: 10,
            min_time_seconds: 20, // Invalid: min > max
            words_per_minute: 200,
        };
        let result = ReadingTime::new(config);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reading_time_zero_wpm() {
        let config = ReadingTimeConfig {
            max_time_seconds: 300,
            min_time_seconds: 5,
            words_per_minute: 0, // Invalid
        };
        let result = ReadingTime::new(config);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reading_time_char_count() {
        let scanner = ReadingTime::default_config().unwrap();
        let vault = Vault::new();

        let response = "Hello World!"; // 10 non-whitespace chars
        let result = scanner.scan_output("", &response, &vault).await.unwrap();

        assert_eq!(result.metadata.get("char_count").unwrap(), "11");
    }
}
