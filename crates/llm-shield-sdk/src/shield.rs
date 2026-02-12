//! # Shield - Main API
//!
//! The Shield struct is the main entry point for the LLM Shield SDK.
//!
//! ## Features
//!
//! - Simple, intuitive API
//! - Async-first design
//! - Support for both prompt and output scanning
//! - Batch processing for high throughput
//! - Configurable parallel execution

use crate::builder::ShieldBuilder;
use crate::config::ShieldConfig;
use crate::error::{SdkError, SdkResult};
use crate::preset::Preset;
use futures::future::join_all;
use llm_shield_core::{ScanResult, Scanner, ScannerPipeline, Vault};
use std::sync::Arc;
use std::time::Instant;

/// Task-local gateway token. When the `enforce-gateway` feature is active,
/// Shield's scanning methods require this to be set (via `GATEWAY_TOKEN.scope()`),
/// ensuring all invocations go through `llm-security-core::SecurityCore`.
#[cfg(feature = "enforce-gateway")]
tokio::task_local! {
    pub static GATEWAY_TOKEN: String;
}

/// Main entry point for the LLM Shield SDK
///
/// Shield provides a high-level API for scanning LLM prompts and outputs
/// for security threats, sensitive data, and policy violations.
///
/// ## Quick Start
///
/// ```rust,ignore
/// use llm_shield_sdk::prelude::*;
///
/// #[tokio::main]
/// async fn main() -> SdkResult<()> {
///     // Create a shield with standard security
///     let shield = Shield::standard()?;
///
///     // Scan a prompt
///     let result = shield.scan_prompt("Hello, how are you?").await?;
///
///     if result.is_valid {
///         println!("Prompt is safe!");
///     } else {
///         println!("Risk detected: {:.2}", result.risk_score);
///     }
///
///     Ok(())
/// }
/// ```
///
/// ## Custom Configuration
///
/// ```rust,ignore
/// let shield = Shield::builder()
///     .with_preset(Preset::Standard)
///     .with_short_circuit(0.9)
///     .with_parallel_execution(true)
///     .build()?;
/// ```
pub struct Shield {
    config: ShieldConfig,
    input_scanners: Vec<Arc<dyn Scanner>>,
    output_scanners: Vec<Arc<dyn Scanner>>,
    vault: Vault,
}

impl Shield {
    // ========================================================================
    // Constructors
    // ========================================================================

    /// Create a new Shield with the given configuration and scanners
    pub(crate) fn new(
        config: ShieldConfig,
        input_scanners: Vec<Arc<dyn Scanner>>,
        output_scanners: Vec<Arc<dyn Scanner>>,
    ) -> Self {
        Self {
            config,
            input_scanners,
            output_scanners,
            vault: Vault::new(),
        }
    }

    /// Create a builder for custom configuration
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// let shield = Shield::builder()
    ///     .with_preset(Preset::Standard)
    ///     .build()?;
    /// ```
    pub fn builder() -> ShieldBuilder {
        ShieldBuilder::new()
    }

    /// Create a Shield with strict security (maximum protection)
    ///
    /// Recommended for regulated industries (banking, healthcare).
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// let shield = Shield::strict()?;
    /// ```
    pub fn strict() -> SdkResult<Self> {
        ShieldBuilder::new().with_preset(Preset::Strict).build()
    }

    /// Create a Shield with standard security (balanced protection)
    ///
    /// Recommended for general-purpose applications.
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// let shield = Shield::standard()?;
    /// ```
    pub fn standard() -> SdkResult<Self> {
        ShieldBuilder::new().with_preset(Preset::Standard).build()
    }

    /// Create a Shield with permissive security (minimal protection)
    ///
    /// Recommended for development and testing only.
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// let shield = Shield::permissive()?;
    /// ```
    pub fn permissive() -> SdkResult<Self> {
        ShieldBuilder::new().with_preset(Preset::Permissive).build()
    }

    // ========================================================================
    // Scanning Methods
    // ========================================================================

    /// Scan a prompt before sending to an LLM
    ///
    /// ## Arguments
    ///
    /// * `prompt` - The user prompt to scan
    ///
    /// ## Returns
    ///
    /// A `ScanResult` containing:
    /// - `is_valid`: Whether the prompt passed all security checks
    /// - `risk_score`: Overall risk score (0.0 to 1.0)
    /// - `entities`: Detected entities (PII, secrets, etc.)
    /// - `risk_factors`: Contributing risk factors
    /// - `sanitized_text`: Sanitized version of the prompt
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// let result = shield.scan_prompt("Hello, how are you?").await?;
    ///
    /// if result.is_valid {
    ///     // Safe to send to LLM
    ///     send_to_llm(&result.sanitized_text);
    /// } else {
    ///     // Handle security risk
    ///     log_security_event(&result);
    /// }
    /// ```
    pub async fn scan_prompt(&self, prompt: &str) -> SdkResult<ScanResult> {
        self.scan_with_scanners(prompt, &self.input_scanners).await
    }

    /// Scan an LLM output before showing to the user
    ///
    /// ## Arguments
    ///
    /// * `output` - The LLM response to scan
    ///
    /// ## Returns
    ///
    /// A `ScanResult` containing validation results.
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// let llm_response = call_llm(prompt).await?;
    /// let result = shield.scan_output(&llm_response).await?;
    ///
    /// if result.is_valid {
    ///     // Safe to show to user
    ///     display_to_user(&result.sanitized_text);
    /// } else {
    ///     // Handle security risk
    ///     display_error("Response filtered for security reasons");
    /// }
    /// ```
    pub async fn scan_output(&self, output: &str) -> SdkResult<ScanResult> {
        self.scan_with_scanners(output, &self.output_scanners).await
    }

    /// Scan both prompt and output in one call
    ///
    /// ## Arguments
    ///
    /// * `prompt` - The user prompt
    /// * `output` - The LLM response
    ///
    /// ## Returns
    ///
    /// A tuple of (prompt_result, output_result).
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// let (prompt_result, output_result) = shield
    ///     .scan_prompt_and_output(prompt, llm_response)
    ///     .await?;
    /// ```
    pub async fn scan_prompt_and_output(
        &self,
        prompt: &str,
        output: &str,
    ) -> SdkResult<(ScanResult, ScanResult)> {
        let prompt_result = self.scan_prompt(prompt).await?;
        let output_result = self.scan_output(output).await?;
        Ok((prompt_result, output_result))
    }

    /// Scan multiple prompts in batch
    ///
    /// Optimized for high-throughput scenarios.
    ///
    /// ## Arguments
    ///
    /// * `prompts` - Slice of prompts to scan
    ///
    /// ## Returns
    ///
    /// Vector of `ScanResult` in the same order as input prompts.
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// let prompts = vec!["Hello", "How are you?", "What's the weather?"];
    /// let results = shield.scan_batch(&prompts).await?;
    ///
    /// for (prompt, result) in prompts.iter().zip(results.iter()) {
    ///     println!("{}: {}", prompt, if result.is_valid { "safe" } else { "risky" });
    /// }
    /// ```
    pub async fn scan_batch(&self, prompts: &[&str]) -> SdkResult<Vec<ScanResult>> {
        if prompts.len() > self.config.max_batch_size {
            return Err(SdkError::validation(format!(
                "Batch size {} exceeds maximum {}",
                prompts.len(),
                self.config.max_batch_size
            )));
        }

        // Execute all scans in parallel
        let futures: Vec<_> = prompts
            .iter()
            .map(|prompt| self.scan_prompt(prompt))
            .collect();

        let results: Vec<SdkResult<ScanResult>> = join_all(futures).await;

        // Collect results, returning first error if any
        results.into_iter().collect()
    }

    /// Scan multiple outputs in batch
    ///
    /// ## Arguments
    ///
    /// * `outputs` - Slice of LLM outputs to scan
    ///
    /// ## Returns
    ///
    /// Vector of `ScanResult` in the same order as input outputs.
    pub async fn scan_output_batch(&self, outputs: &[&str]) -> SdkResult<Vec<ScanResult>> {
        if outputs.len() > self.config.max_batch_size {
            return Err(SdkError::validation(format!(
                "Batch size {} exceeds maximum {}",
                outputs.len(),
                self.config.max_batch_size
            )));
        }

        let futures: Vec<_> = outputs
            .iter()
            .map(|output| self.scan_output(output))
            .collect();

        let results: Vec<SdkResult<ScanResult>> = join_all(futures).await;
        results.into_iter().collect()
    }

    // ========================================================================
    // Internal Methods
    // ========================================================================

    /// Execute scanners on input
    async fn scan_with_scanners(
        &self,
        input: &str,
        scanners: &[Arc<dyn Scanner>],
    ) -> SdkResult<ScanResult> {
        // Gateway enforcement: reject direct calls when enforce-gateway is active
        #[cfg(feature = "enforce-gateway")]
        {
            GATEWAY_TOKEN.try_with(|_| ()).map_err(|_| {
                SdkError::unauthorized(
                    "Direct call to Shield is forbidden. \
                     Use llm_security_core::SecurityCore instead.",
                )
            })?;
        }

        if scanners.is_empty() {
            // No scanners configured - pass through
            return Ok(ScanResult::pass(input.to_string()));
        }

        let start = Instant::now();

        // Build pipeline
        let mut pipeline = ScannerPipeline::new();
        for scanner in scanners {
            pipeline = pipeline.add(Arc::clone(scanner));
        }

        // Apply short-circuit if configured
        if let Some(threshold) = self.config.short_circuit_threshold {
            pipeline = pipeline.with_short_circuit(threshold);
        }

        // Execute pipeline
        let result = if self.config.parallel.enabled {
            pipeline
                .execute_parallel(input, &self.vault)
                .await
                .map_err(|e| SdkError::pipeline(e.to_string()))?
        } else {
            pipeline
                .execute(input, &self.vault)
                .await
                .map_err(|e| SdkError::pipeline(e.to_string()))?
        };

        // Combine results
        let combined = ScanResult::combine(result);

        // Add timing metadata
        let elapsed_ms = start.elapsed().as_millis() as u64;
        let final_result = combined.with_metadata("scan_time_ms", elapsed_ms);

        // Check timeout
        if let Some(timeout_ms) = self.config.timeout_ms {
            if elapsed_ms > timeout_ms {
                return Err(SdkError::timeout(timeout_ms));
            }
        }

        Ok(final_result)
    }

    // ========================================================================
    // Configuration Access
    // ========================================================================

    /// Get the current configuration
    pub fn config(&self) -> &ShieldConfig {
        &self.config
    }

    /// Get the number of input scanners
    pub fn input_scanner_count(&self) -> usize {
        self.input_scanners.len()
    }

    /// Get the number of output scanners
    pub fn output_scanner_count(&self) -> usize {
        self.output_scanners.len()
    }

    /// Get input scanner names
    pub fn input_scanner_names(&self) -> Vec<&str> {
        self.input_scanners.iter().map(|s| s.name()).collect()
    }

    /// Get output scanner names
    pub fn output_scanner_names(&self) -> Vec<&str> {
        self.output_scanners.iter().map(|s| s.name()).collect()
    }

    /// Get the vault for advanced usage
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Clear the vault
    pub fn clear_vault(&self) -> SdkResult<()> {
        self.vault.clear().map_err(|e| SdkError::pipeline(e.to_string()))
    }
}

// Safety: Shield is thread-safe
unsafe impl Send for Shield {}
unsafe impl Sync for Shield {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shield_standard() {
        let shield = Shield::standard();
        assert!(shield.is_ok());

        let shield = shield.unwrap();
        assert!(shield.input_scanner_count() > 0);
    }

    #[tokio::test]
    async fn test_shield_strict() {
        let shield = Shield::strict();
        assert!(shield.is_ok());

        let shield = shield.unwrap();
        assert!(shield.input_scanner_count() >= shield.input_scanner_count());
    }

    #[tokio::test]
    async fn test_shield_permissive() {
        let shield = Shield::permissive();
        assert!(shield.is_ok());
    }

    #[tokio::test]
    async fn test_scan_prompt_safe() {
        let shield = Shield::permissive().unwrap();
        let result = shield.scan_prompt("Hello, how are you?").await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_valid);
        assert!(result.risk_score < 0.5);
    }

    #[tokio::test]
    async fn test_scan_prompt_with_secret() {
        let shield = Shield::standard().unwrap();
        let result = shield
            .scan_prompt("My AWS key is AKIAIOSFODNN7EXAMPLE")
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(!result.is_valid);
        assert!(result.risk_score > 0.5);
    }

    #[tokio::test]
    async fn test_scan_output() {
        let shield = Shield::standard().unwrap();
        let result = shield
            .scan_output("Here is the information you requested.")
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_scan_batch() {
        let shield = Shield::permissive().unwrap();
        let prompts = vec!["Hello", "How are you?", "What's the weather?"];
        let results = shield.scan_batch(&prompts).await;

        assert!(results.is_ok());
        let results = results.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn test_scan_batch_exceeds_limit() {
        let shield = Shield::builder()
            .with_preset(Preset::Permissive)
            .with_max_batch_size(2)
            .build()
            .unwrap();

        let prompts = vec!["1", "2", "3"];
        let result = shield.scan_batch(&prompts).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_scanner_names() {
        let shield = Shield::standard().unwrap();

        let input_names = shield.input_scanner_names();
        assert!(!input_names.is_empty());

        let output_names = shield.output_scanner_names();
        assert!(!output_names.is_empty());
    }

    #[tokio::test]
    async fn test_vault_operations() {
        let shield = Shield::permissive().unwrap();

        // Vault should be accessible
        let vault = shield.vault();
        assert!(vault.is_empty());

        // Clear should work
        let result = shield.clear_vault();
        assert!(result.is_ok());
    }
}
