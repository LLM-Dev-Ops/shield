//! Sensitive Output Scanner
//!
//! Converted from llm_guard/output_scanners/sensitive.py
//!
//! ## SPARC Implementation
//!
//! Detects sensitive information in LLM responses to prevent data leakage.
//! This is critical for GDPR, HIPAA, PCI-DSS compliance.
//!
//! ## London School TDD
//!
//! Tests written first drive the implementation.

use llm_shield_core::{
    async_trait, Entity, Error, Result, RiskFactor, ScanResult, Scanner, ScannerType, Severity,
    Vault,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::LazyLock;

/// Sensitive scanner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveConfig {
    /// Entity types to detect
    pub entity_types: Vec<SensitiveEntityType>,

    /// Redact sensitive entities instead of failing
    pub redact_mode: bool,

    /// Redaction placeholder
    pub redaction_placeholder: String,
}

impl Default for SensitiveConfig {
    fn default() -> Self {
        Self {
            entity_types: vec![
                SensitiveEntityType::Email,
                SensitiveEntityType::PhoneNumber,
                SensitiveEntityType::CreditCard,
                SensitiveEntityType::SSN,
                SensitiveEntityType::IPAddress,
            ],
            redact_mode: false,
            redaction_placeholder: "[REDACTED]".to_string(),
        }
    }
}

/// Sensitive entity types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SensitiveEntityType {
    Email,
    PhoneNumber,
    CreditCard,
    SSN,          // Social Security Number
    IPAddress,
    URL,
    BankAccount,
    DateOfBirth,
    PersonName,
}

impl SensitiveEntityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SensitiveEntityType::Email => "email",
            SensitiveEntityType::PhoneNumber => "phone_number",
            SensitiveEntityType::CreditCard => "credit_card",
            SensitiveEntityType::SSN => "ssn",
            SensitiveEntityType::IPAddress => "ip_address",
            SensitiveEntityType::URL => "url",
            SensitiveEntityType::BankAccount => "bank_account",
            SensitiveEntityType::DateOfBirth => "date_of_birth",
            SensitiveEntityType::PersonName => "person_name",
        }
    }
}

// Regex patterns for sensitive entity detection
static EMAIL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap()
});

static PHONE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}").unwrap()
});

static CREDIT_CARD_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Matches common credit card patterns (Visa, MasterCard, Amex, Discover)
    Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{4}\b").unwrap()
});

static SSN_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap()
});

static IP_ADDRESS_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap()
});

static URL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"https?://[^\s<>"]+|www\.[^\s<>"]+"#).unwrap()
});

static DATE_OF_BIRTH_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Matches dates like MM/DD/YYYY, DD-MM-YYYY, YYYY-MM-DD
    Regex::new(r"\b(?:\d{1,2}[-/]\d{1,2}[-/]\d{4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})\b").unwrap()
});

/// Sensitive scanner implementation
///
/// ## Enterprise Features
///
/// - Detects 9 types of sensitive entities:
///   - Email addresses
///   - Phone numbers
///   - Credit card numbers (with Luhn validation)
///   - Social Security Numbers (SSN)
///   - IP addresses
///   - URLs
///   - Bank account numbers
///   - Dates of birth
///   - Person names (heuristic)
/// - Configurable entity types
/// - Redaction mode (optional)
/// - GDPR/HIPAA/PCI-DSS compliance support
/// - Confidence scoring
///
/// ## Example
///
/// ```rust,ignore
/// use llm_shield_scanners::output::Sensitive;
///
/// let scanner = Sensitive::default_config()?;
/// let response = "Contact me at john.doe@example.com or call 555-123-4567";
/// let result = scanner.scan_output("", response, &vault).await?;
/// assert!(!result.is_valid); // Sensitive data detected
///
/// // With redaction mode
/// let config = SensitiveConfig {
///     redact_mode: true,
///     ..Default::default()
/// };
/// let scanner = Sensitive::new(config)?;
/// let result = scanner.scan_output("", response, &vault).await?;
/// assert!(result.is_valid); // Redacted
/// assert!(result.sanitized_text.contains("[REDACTED]"));
/// ```
pub struct Sensitive {
    config: SensitiveConfig,
}

impl Sensitive {
    /// Create a new Sensitive scanner
    pub fn new(config: SensitiveConfig) -> Result<Self> {
        if config.entity_types.is_empty() {
            return Err(Error::config("At least one entity type must be enabled"));
        }

        Ok(Self { config })
    }

    /// Create with default configuration
    pub fn default_config() -> Result<Self> {
        Self::new(SensitiveConfig::default())
    }

    /// Detect sensitive entities in text
    fn detect_sensitive_entities(&self, text: &str) -> Vec<SensitiveMatch> {
        let mut matches = Vec::new();

        for entity_type in &self.config.entity_types {
            let entity_matches = match entity_type {
                SensitiveEntityType::Email => self.detect_emails(text),
                SensitiveEntityType::PhoneNumber => self.detect_phone_numbers(text),
                SensitiveEntityType::CreditCard => self.detect_credit_cards(text),
                SensitiveEntityType::SSN => self.detect_ssn(text),
                SensitiveEntityType::IPAddress => self.detect_ip_addresses(text),
                SensitiveEntityType::URL => self.detect_urls(text),
                SensitiveEntityType::BankAccount => self.detect_bank_accounts(text),
                SensitiveEntityType::DateOfBirth => self.detect_dates_of_birth(text),
                SensitiveEntityType::PersonName => self.detect_person_names(text),
            };

            matches.extend(entity_matches);
        }

        // Sort by position
        matches.sort_by_key(|m| m.start);

        matches
    }

    fn detect_emails(&self, text: &str) -> Vec<SensitiveMatch> {
        EMAIL_PATTERN
            .find_iter(text)
            .map(|m| SensitiveMatch {
                entity_type: SensitiveEntityType::Email,
                text: m.as_str().to_string(),
                start: m.start(),
                end: m.end(),
                confidence: 0.95,
            })
            .collect()
    }

    fn detect_phone_numbers(&self, text: &str) -> Vec<SensitiveMatch> {
        PHONE_PATTERN
            .find_iter(text)
            .map(|m| SensitiveMatch {
                entity_type: SensitiveEntityType::PhoneNumber,
                text: m.as_str().to_string(),
                start: m.start(),
                end: m.end(),
                confidence: 0.90,
            })
            .collect()
    }

    fn detect_credit_cards(&self, text: &str) -> Vec<SensitiveMatch> {
        CREDIT_CARD_PATTERN
            .find_iter(text)
            .filter_map(|m| {
                let card_str = m.as_str().replace(['-', ' '], "");
                if self.validate_luhn(&card_str) {
                    Some(SensitiveMatch {
                        entity_type: SensitiveEntityType::CreditCard,
                        text: m.as_str().to_string(),
                        start: m.start(),
                        end: m.end(),
                        confidence: 0.95,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Luhn algorithm for credit card validation
    fn validate_luhn(&self, number: &str) -> bool {
        let digits: Vec<u32> = number.chars().filter_map(|c| c.to_digit(10)).collect();

        if digits.len() < 13 || digits.len() > 19 {
            return false;
        }

        let sum: u32 = digits
            .iter()
            .rev()
            .enumerate()
            .map(|(idx, &digit)| {
                if idx % 2 == 1 {
                    let doubled = digit * 2;
                    if doubled > 9 {
                        doubled - 9
                    } else {
                        doubled
                    }
                } else {
                    digit
                }
            })
            .sum();

        sum % 10 == 0
    }

    fn detect_ssn(&self, text: &str) -> Vec<SensitiveMatch> {
        SSN_PATTERN
            .find_iter(text)
            .map(|m| SensitiveMatch {
                entity_type: SensitiveEntityType::SSN,
                text: m.as_str().to_string(),
                start: m.start(),
                end: m.end(),
                confidence: 0.95,
            })
            .collect()
    }

    fn detect_ip_addresses(&self, text: &str) -> Vec<SensitiveMatch> {
        IP_ADDRESS_PATTERN
            .find_iter(text)
            .filter_map(|m| {
                // Validate IP address ranges
                let ip_str = m.as_str();
                let parts: Vec<&str> = ip_str.split('.').collect();
                if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                    Some(SensitiveMatch {
                        entity_type: SensitiveEntityType::IPAddress,
                        text: ip_str.to_string(),
                        start: m.start(),
                        end: m.end(),
                        confidence: 0.90,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    fn detect_urls(&self, text: &str) -> Vec<SensitiveMatch> {
        URL_PATTERN
            .find_iter(text)
            .map(|m| SensitiveMatch {
                entity_type: SensitiveEntityType::URL,
                text: m.as_str().to_string(),
                start: m.start(),
                end: m.end(),
                confidence: 0.85,
            })
            .collect()
    }

    fn detect_bank_accounts(&self, text: &str) -> Vec<SensitiveMatch> {
        // Simple pattern for bank account numbers (8-17 digits)
        let pattern = Regex::new(r"\b\d{8,17}\b").unwrap();
        pattern
            .find_iter(text)
            .map(|m| SensitiveMatch {
                entity_type: SensitiveEntityType::BankAccount,
                text: m.as_str().to_string(),
                start: m.start(),
                end: m.end(),
                confidence: 0.70, // Lower confidence - needs context
            })
            .collect()
    }

    fn detect_dates_of_birth(&self, text: &str) -> Vec<SensitiveMatch> {
        DATE_OF_BIRTH_PATTERN
            .find_iter(text)
            .map(|m| SensitiveMatch {
                entity_type: SensitiveEntityType::DateOfBirth,
                text: m.as_str().to_string(),
                start: m.start(),
                end: m.end(),
                confidence: 0.75, // Lower confidence - could be any date
            })
            .collect()
    }

    fn detect_person_names(&self, text: &str) -> Vec<SensitiveMatch> {
        // Very simple heuristic: capitalized words that could be names
        // In production, you'd use NER (Named Entity Recognition) models
        let pattern = Regex::new(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b").unwrap();
        pattern
            .find_iter(text)
            .map(|m| SensitiveMatch {
                entity_type: SensitiveEntityType::PersonName,
                text: m.as_str().to_string(),
                start: m.start(),
                end: m.end(),
                confidence: 0.60, // Low confidence - heuristic only
            })
            .collect()
    }

    /// Redact sensitive entities in text
    fn redact_text(&self, text: &str, matches: &[SensitiveMatch]) -> String {
        if matches.is_empty() {
            return text.to_string();
        }

        let mut result = String::new();
        let mut last_end = 0;

        for m in matches {
            // Add text before this match
            result.push_str(&text[last_end..m.start]);
            // Add redaction placeholder
            result.push_str(&self.config.redaction_placeholder);
            last_end = m.end;
        }

        // Add remaining text
        result.push_str(&text[last_end..]);

        result
    }

    /// Scan output for sensitive information
    pub async fn scan_output(
        &self,
        _prompt: &str,
        output: &str,
        _vault: &Vault,
    ) -> Result<ScanResult> {
        let matches = self.detect_sensitive_entities(output);

        if matches.is_empty() {
            return Ok(ScanResult::pass(output.to_string())
                .with_metadata("sensitive_entities_found", "0"));
        }

        // If redaction mode is enabled, redact and return valid result
        if self.config.redact_mode {
            let redacted = self.redact_text(output, &matches);
            return Ok(ScanResult::pass(redacted)
                .with_metadata("sensitive_entities_found", matches.len().to_string())
                .with_metadata("redacted", "true"));
        }

        // Build entities
        let entities: Vec<Entity> = matches
            .iter()
            .map(|m| {
                let mut metadata = HashMap::new();
                metadata.insert("entity_type".to_string(), m.entity_type.as_str().to_string());
                metadata.insert("matched_text".to_string(), m.text.clone());

                Entity {
                    entity_type: m.entity_type.as_str().to_string(),
                    text: m.text.clone(),
                    start: m.start,
                    end: m.end,
                    confidence: m.confidence,
                    metadata,
                }
            })
            .collect();

        let severity = if matches.iter().any(|m| {
            matches!(
                m.entity_type,
                SensitiveEntityType::CreditCard | SensitiveEntityType::SSN
            )
        }) {
            Severity::High
        } else if matches.len() > 3 {
            Severity::High
        } else if matches.len() > 1 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let description = format!("LLM response contains {} sensitive entities", matches.len());
        let risk_factor = RiskFactor::new(
            "sensitive_data_leak",
            &description,
            severity,
            0.9,
        );

        let mut result = ScanResult::new(output.to_string(), false, 0.9)
            .with_risk_factor(risk_factor)
            .with_metadata("sensitive_entities_found", matches.len());

        for entity in entities {
            result = result.with_entity(entity);
        }

        Ok(result)
    }
}

#[derive(Debug, Clone)]
struct SensitiveMatch {
    entity_type: SensitiveEntityType,
    text: String,
    start: usize,
    end: usize,
    confidence: f32,
}

#[async_trait]
impl Scanner for Sensitive {
    fn name(&self) -> &str {
        "Sensitive"
    }

    async fn scan(&self, input: &str, vault: &Vault) -> Result<ScanResult> {
        self.scan_output("", input, vault).await
    }

    fn scanner_type(&self) -> ScannerType {
        ScannerType::Output
    }

    fn description(&self) -> &str {
        "Detects sensitive information in LLM responses (PII, financial data, credentials)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sensitive_email_detection() {
        let scanner = Sensitive::default_config().unwrap();
        let vault = Vault::new();

        let response = "Contact me at john.doe@example.com for more information.";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(!result.is_valid);
        assert_eq!(result.entities.len(), 1);
        assert_eq!(result.entities[0].entity_type, "email");
    }

    #[tokio::test]
    async fn test_sensitive_phone_detection() {
        let scanner = Sensitive::default_config().unwrap();
        let vault = Vault::new();

        let response = "Call me at 555-123-4567 or (555) 987-6543.";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(!result.is_valid);
        assert!(result.entities.len() >= 1);
    }

    #[tokio::test]
    async fn test_sensitive_credit_card_detection() {
        let scanner = Sensitive::default_config().unwrap();
        let vault = Vault::new();

        // Valid credit card number (passes Luhn check)
        let response = "My card number is 4532-1488-0343-6467";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(!result.is_valid);
        assert!(result.entities.iter().any(|e| e.entity_type == "credit_card"));
    }

    #[tokio::test]
    async fn test_sensitive_ssn_detection() {
        let scanner = Sensitive::default_config().unwrap();
        let vault = Vault::new();

        let response = "My SSN is 123-45-6789";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(!result.is_valid);
        assert!(result.entities.iter().any(|e| e.entity_type == "ssn"));
    }

    #[tokio::test]
    async fn test_sensitive_ip_address_detection() {
        let scanner = Sensitive::default_config().unwrap();
        let vault = Vault::new();

        let response = "The server is at 192.168.1.1";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(!result.is_valid);
        assert!(result.entities.iter().any(|e| e.entity_type == "ip_address"));
    }

    #[tokio::test]
    async fn test_sensitive_clean_response() {
        let scanner = Sensitive::default_config().unwrap();
        let vault = Vault::new();

        let response = "Here is some general information about the topic.";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(result.is_valid);
        assert_eq!(result.entities.len(), 0);
    }

    #[tokio::test]
    async fn test_sensitive_redaction_mode() {
        let config = SensitiveConfig {
            redact_mode: true,
            ..Default::default()
        };
        let scanner = Sensitive::new(config).unwrap();
        let vault = Vault::new();

        let response = "Email me at test@example.com or call 555-1234";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(result.is_valid); // Should pass with redaction
        assert!(result.sanitized_text.contains("[REDACTED]"));
        assert!(!result.sanitized_text.contains("test@example.com"));
    }

    #[tokio::test]
    async fn test_sensitive_multiple_entities() {
        let scanner = Sensitive::default_config().unwrap();
        let vault = Vault::new();

        let response = "Contact John Doe at john@example.com or 555-1234. IP: 10.0.0.1";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(!result.is_valid);
        assert!(result.entities.len() >= 2);
    }

    #[tokio::test]
    async fn test_sensitive_url_detection() {
        let config = SensitiveConfig {
            entity_types: vec![SensitiveEntityType::URL],
            ..Default::default()
        };
        let scanner = Sensitive::new(config).unwrap();
        let vault = Vault::new();

        let response = "Visit https://example.com or www.test.com";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(!result.is_valid);
        assert!(result.entities.iter().any(|e| e.entity_type == "url"));
    }

    #[tokio::test]
    async fn test_sensitive_custom_entity_types() {
        let config = SensitiveConfig {
            entity_types: vec![SensitiveEntityType::Email],
            ..Default::default()
        };
        let scanner = Sensitive::new(config).unwrap();
        let vault = Vault::new();

        let response = "Call 555-1234"; // Phone number
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        // Should pass because phone detection is not enabled
        assert!(result.is_valid);
    }

    #[tokio::test]
    async fn test_sensitive_luhn_validation() {
        let scanner = Sensitive::default_config().unwrap();

        // Invalid credit card (fails Luhn check)
        let invalid_card = "1234-5678-9012-3456";
        let matches = scanner.detect_credit_cards(invalid_card);
        assert_eq!(matches.len(), 0); // Should not detect invalid cards

        // Valid credit card (passes Luhn check)
        let valid_card = "4532-1488-0343-6467";
        let matches = scanner.detect_credit_cards(valid_card);
        assert_eq!(matches.len(), 1);
    }

    #[tokio::test]
    async fn test_sensitive_severity_levels() {
        let scanner = Sensitive::default_config().unwrap();
        let vault = Vault::new();

        // High severity: credit card
        let response = "Card: 4532-1488-0343-6467";
        let result = scanner.scan_output("", response, &vault).await.unwrap();
        assert!(result.risk_factors.iter().any(|r| matches!(r.severity, Severity::High)));
    }

    #[tokio::test]
    async fn test_sensitive_custom_redaction_placeholder() {
        let config = SensitiveConfig {
            redact_mode: true,
            redaction_placeholder: "***".to_string(),
            ..Default::default()
        };
        let scanner = Sensitive::new(config).unwrap();
        let vault = Vault::new();

        let response = "Email: test@example.com";
        let result = scanner.scan_output("", response, &vault).await.unwrap();

        assert!(result.sanitized_text.contains("***"));
        assert!(!result.sanitized_text.contains("[REDACTED]"));
    }
}
