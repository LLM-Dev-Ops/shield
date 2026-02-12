//! Centralized policy interface for authorization decisions.

use crate::caller_token::CallerToken;
use crate::error::GatewayError;
use async_trait::async_trait;

/// Execution context required for all gateway operations.
#[derive(Debug, Clone)]
pub struct GatewayContext {
    /// Execution ID from the Agentics Core.
    pub execution_id: String,
    /// Parent span ID from the calling Core.
    pub parent_span_id: String,
    /// Authenticated caller token.
    pub caller: CallerToken,
}

/// Result of a policy authorization check.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// Whether the operation is allowed.
    pub allowed: bool,
    /// Optional reason (typically set when denied).
    pub reason: Option<String>,
}

impl PolicyDecision {
    /// Create an "allowed" decision.
    pub fn allow() -> Self {
        Self {
            allowed: true,
            reason: None,
        }
    }

    /// Create a "denied" decision with a reason.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.into()),
        }
    }
}

/// Centralized policy interface for gateway authorization.
///
/// Implement this trait to add custom access control logic
/// (e.g., per-caller permissions, rate limiting by caller, operation restrictions).
#[async_trait]
pub trait CentralizedPolicy: Send + Sync {
    /// Check if a scan operation is allowed given the caller and context.
    ///
    /// # Arguments
    ///
    /// * `context` - The validated gateway context (caller already authenticated)
    /// * `operation` - The operation name (e.g., "scan_prompt", "scan_output", "scan_batch")
    async fn authorize(
        &self,
        context: &GatewayContext,
        operation: &str,
    ) -> Result<PolicyDecision, GatewayError>;
}

/// Default policy that allows all operations.
pub struct DefaultPolicy;

#[async_trait]
impl CentralizedPolicy for DefaultPolicy {
    async fn authorize(
        &self,
        _context: &GatewayContext,
        _operation: &str,
    ) -> Result<PolicyDecision, GatewayError> {
        Ok(PolicyDecision::allow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caller_token::CallerToken;

    fn test_context() -> GatewayContext {
        GatewayContext {
            execution_id: "exec-123".to_string(),
            parent_span_id: "span-456".to_string(),
            caller: CallerToken::create("test", "secret").unwrap(),
        }
    }

    #[tokio::test]
    async fn test_default_policy_allows_all() {
        let policy = DefaultPolicy;
        let ctx = test_context();

        let decision = policy.authorize(&ctx, "scan_prompt").await.unwrap();
        assert!(decision.allowed);
        assert!(decision.reason.is_none());
    }
}
