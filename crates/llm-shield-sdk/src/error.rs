//! # SDK Error Types
//!
//! Comprehensive error handling for the LLM Shield SDK.
//!
//! ## Design Principles
//!
//! - Clear, descriptive error messages
//! - Proper error chaining
//! - Easy pattern matching on error types
//! - Integration with core error types

use llm_shield_core::Error as CoreError;
use thiserror::Error;

/// Result type alias for SDK operations
pub type SdkResult<T> = std::result::Result<T, SdkError>;

/// SDK-specific error types
///
/// ## Error Categories
///
/// - **Configuration**: Invalid settings or missing configuration
/// - **Scanner**: Scanner-specific errors during execution
/// - **Pipeline**: Pipeline composition or execution errors
/// - **Validation**: Input validation failures
/// - **Core**: Wrapped errors from llm-shield-core
#[derive(Debug, Error)]
pub enum SdkError {
    /// Configuration error
    #[error("Configuration error: {message}")]
    Config {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Builder error (missing required fields, invalid state)
    #[error("Builder error: {0}")]
    Builder(String),

    /// Scanner initialization error
    #[error("Failed to initialize scanner '{scanner}': {message}")]
    ScannerInit {
        scanner: String,
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Scanner execution error
    #[error("Scanner '{scanner}' failed: {message}")]
    ScannerExecution {
        scanner: String,
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Pipeline execution error
    #[error("Pipeline execution failed: {0}")]
    Pipeline(String),

    /// Input validation error
    #[error("Invalid input: {0}")]
    Validation(String),

    /// Timeout error
    #[error("Operation timed out after {duration_ms}ms")]
    Timeout { duration_ms: u64 },

    /// Preset not found error
    #[error("Unknown preset: {0}")]
    UnknownPreset(String),

    /// Unauthorized access (direct call without gateway)
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Core error wrapper
    #[error(transparent)]
    Core(#[from] CoreError),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl SdkError {
    /// Create a configuration error
    pub fn config<S: Into<String>>(message: S) -> Self {
        Self::Config {
            message: message.into(),
            source: None,
        }
    }

    /// Create a configuration error with source
    pub fn config_with_source<S: Into<String>>(
        message: S,
        source: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        Self::Config {
            message: message.into(),
            source: Some(source),
        }
    }

    /// Create a builder error
    pub fn builder<S: Into<String>>(message: S) -> Self {
        Self::Builder(message.into())
    }

    /// Create a scanner initialization error
    pub fn scanner_init<S: Into<String>, M: Into<String>>(scanner: S, message: M) -> Self {
        Self::ScannerInit {
            scanner: scanner.into(),
            message: message.into(),
            source: None,
        }
    }

    /// Create a scanner initialization error with source
    pub fn scanner_init_with_source<S: Into<String>, M: Into<String>>(
        scanner: S,
        message: M,
        source: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        Self::ScannerInit {
            scanner: scanner.into(),
            message: message.into(),
            source: Some(source),
        }
    }

    /// Create a scanner execution error
    pub fn scanner_execution<S: Into<String>, M: Into<String>>(scanner: S, message: M) -> Self {
        Self::ScannerExecution {
            scanner: scanner.into(),
            message: message.into(),
            source: None,
        }
    }

    /// Create a pipeline error
    pub fn pipeline<S: Into<String>>(message: S) -> Self {
        Self::Pipeline(message.into())
    }

    /// Create a validation error
    pub fn validation<S: Into<String>>(message: S) -> Self {
        Self::Validation(message.into())
    }

    /// Create a timeout error
    pub fn timeout(duration_ms: u64) -> Self {
        Self::Timeout { duration_ms }
    }

    /// Create an unknown preset error
    pub fn unknown_preset<S: Into<String>>(preset: S) -> Self {
        Self::UnknownPreset(preset.into())
    }

    /// Create an unauthorized access error
    pub fn unauthorized<S: Into<String>>(message: S) -> Self {
        Self::Unauthorized(message.into())
    }

    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Timeout { .. } => true,
            Self::Core(core_err) => core_err.is_retryable(),
            Self::Io(_) => true,
            _ => false,
        }
    }

    /// Get error category for metrics/logging
    pub fn category(&self) -> &'static str {
        match self {
            Self::Config { .. } => "config",
            Self::Builder(_) => "builder",
            Self::ScannerInit { .. } => "scanner_init",
            Self::ScannerExecution { .. } => "scanner_execution",
            Self::Pipeline(_) => "pipeline",
            Self::Validation(_) => "validation",
            Self::Timeout { .. } => "timeout",
            Self::UnknownPreset(_) => "unknown_preset",
            Self::Unauthorized(_) => "unauthorized",
            Self::Core(_) => "core",
            Self::Io(_) => "io",
            Self::Serialization(_) => "serialization",
        }
    }
}

/// Extension trait for converting Results to SdkResult
pub trait IntoSdkResult<T> {
    /// Convert to SdkResult
    fn into_sdk_result(self) -> SdkResult<T>;
}

impl<T> IntoSdkResult<T> for llm_shield_core::Result<T> {
    fn into_sdk_result(self) -> SdkResult<T> {
        self.map_err(SdkError::Core)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = SdkError::config("test error");
        assert!(matches!(err, SdkError::Config { .. }));
        assert_eq!(err.category(), "config");
    }

    #[test]
    fn test_error_display() {
        let err = SdkError::scanner_init("BanSubstrings", "missing patterns");
        let msg = format!("{}", err);
        assert!(msg.contains("BanSubstrings"));
        assert!(msg.contains("missing patterns"));
    }

    #[test]
    fn test_error_retryable() {
        assert!(SdkError::timeout(5000).is_retryable());
        assert!(!SdkError::config("test").is_retryable());
    }

    #[test]
    fn test_error_categories() {
        assert_eq!(SdkError::config("test").category(), "config");
        assert_eq!(SdkError::builder("test").category(), "builder");
        assert_eq!(SdkError::pipeline("test").category(), "pipeline");
        assert_eq!(SdkError::validation("test").category(), "validation");
        assert_eq!(SdkError::timeout(1000).category(), "timeout");
    }
}
