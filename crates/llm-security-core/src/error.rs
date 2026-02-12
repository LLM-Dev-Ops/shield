//! Gateway error types for LLM-Security-Core.

use llm_shield_sdk::SdkError;

/// Errors that can occur in the LLM-Security-Core gateway.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// Invalid caller token (bad signature, missing fields).
    #[error("Invalid caller token: {0}")]
    InvalidCallerToken(String),

    /// Caller token has expired.
    #[error("Caller token expired: {0}")]
    ExpiredCallerToken(String),

    /// Missing required execution context field.
    #[error("Missing execution context: {0}")]
    MissingExecutionContext(String),

    /// Operation denied by centralized policy.
    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    /// Direct access to Shield without going through the gateway.
    #[error("Direct access forbidden: {0}")]
    DirectAccess(String),

    /// Error from the inner Shield SDK.
    #[error("Shield error: {0}")]
    Shield(#[from] SdkError),
}
