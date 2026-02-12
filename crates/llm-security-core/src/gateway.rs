//! SecurityCore - The sole authorized gateway for all LLM-Shield scanning.
//!
//! All scanning operations MUST go through SecurityCore.
//! Direct calls to Shield are FORBIDDEN when the `enforce-gateway` feature is active.

use crate::caller_token::CallerToken;
use crate::error::GatewayError;
use crate::policy::{CentralizedPolicy, DefaultPolicy, GatewayContext, PolicyDecision};
use llm_shield_sdk::{Preset, ScanResult, Shield, ShieldBuilder as SdkShieldBuilder};

// Import the gateway token task_local from the SDK
use llm_shield_sdk::shield::GATEWAY_TOKEN;

const DEFAULT_TOKEN_TTL_SECONDS: i64 = 300;

/// SecurityCore - The sole authorized entry point for LLM-Shield scanning.
///
/// Every scan request must provide a valid [`GatewayContext`] containing:
/// - An HMAC-signed [`CallerToken`] (caller authentication)
/// - `execution_id` + `parent_span_id` (Agentics execution context)
///
/// # Example
///
/// ```rust,ignore
/// use llm_security_core::{SecurityCore, CallerToken};
///
/// let core = SecurityCore::standard("my-shared-secret".to_string())?;
///
/// let token = CallerToken::create("my-service", "my-shared-secret")?;
/// let ctx = GatewayContext {
///     execution_id: "exec-123".to_string(),
///     parent_span_id: "span-456".to_string(),
///     caller: token,
/// };
///
/// let result = core.scan_prompt("Hello world", &ctx).await?;
/// ```
pub struct SecurityCore {
    shield: Shield,
    shared_secret: String,
    token_ttl_seconds: i64,
    policy: Box<dyn CentralizedPolicy>,
}

impl SecurityCore {
    /// Create a SecurityCore with standard Shield preset (recommended).
    pub fn standard(shared_secret: String) -> Result<Self, GatewayError> {
        Ok(Self {
            shield: Shield::standard().map_err(GatewayError::Shield)?,
            shared_secret,
            token_ttl_seconds: DEFAULT_TOKEN_TTL_SECONDS,
            policy: Box::new(DefaultPolicy),
        })
    }

    /// Create a SecurityCore with strict Shield preset.
    /// Maximum security for regulated industries.
    pub fn strict(shared_secret: String) -> Result<Self, GatewayError> {
        Ok(Self {
            shield: Shield::strict().map_err(GatewayError::Shield)?,
            shared_secret,
            token_ttl_seconds: DEFAULT_TOKEN_TTL_SECONDS,
            policy: Box::new(DefaultPolicy),
        })
    }

    /// Create a SecurityCore with permissive Shield preset.
    /// Minimal security for development/testing.
    pub fn permissive(shared_secret: String) -> Result<Self, GatewayError> {
        Ok(Self {
            shield: Shield::permissive().map_err(GatewayError::Shield)?,
            shared_secret,
            token_ttl_seconds: DEFAULT_TOKEN_TTL_SECONDS,
            policy: Box::new(DefaultPolicy),
        })
    }

    /// Create a builder for custom SecurityCore configuration.
    pub fn builder() -> SecurityCoreBuilder {
        SecurityCoreBuilder::new()
    }

    /// Scan a prompt. This is the ONLY authorized way to invoke prompt scanning.
    pub async fn scan_prompt(
        &self,
        text: &str,
        ctx: &GatewayContext,
    ) -> Result<ScanResult, GatewayError> {
        self.validate_context(ctx)?;
        self.authorize_operation(ctx, "scan_prompt").await?;

        GATEWAY_TOKEN
            .scope(ctx.caller.caller_id.clone(), async {
                self.shield
                    .scan_prompt(text)
                    .await
                    .map_err(GatewayError::Shield)
            })
            .await
    }

    /// Scan LLM output. This is the ONLY authorized way to invoke output scanning.
    pub async fn scan_output(
        &self,
        text: &str,
        ctx: &GatewayContext,
    ) -> Result<ScanResult, GatewayError> {
        self.validate_context(ctx)?;
        self.authorize_operation(ctx, "scan_output").await?;

        GATEWAY_TOKEN
            .scope(ctx.caller.caller_id.clone(), async {
                self.shield
                    .scan_output(text)
                    .await
                    .map_err(GatewayError::Shield)
            })
            .await
    }

    /// Scan multiple prompts in batch. This is the ONLY authorized way to invoke batch scanning.
    pub async fn scan_batch(
        &self,
        texts: &[&str],
        ctx: &GatewayContext,
    ) -> Result<Vec<ScanResult>, GatewayError> {
        self.validate_context(ctx)?;
        self.authorize_operation(ctx, "scan_batch").await?;

        GATEWAY_TOKEN
            .scope(ctx.caller.caller_id.clone(), async {
                self.shield
                    .scan_batch(texts)
                    .await
                    .map_err(GatewayError::Shield)
            })
            .await
    }

    /// Validate the full gateway context: caller token + execution context.
    fn validate_context(&self, ctx: &GatewayContext) -> Result<(), GatewayError> {
        if ctx.execution_id.is_empty() {
            return Err(GatewayError::MissingExecutionContext(
                "execution_id is required".to_string(),
            ));
        }
        if ctx.parent_span_id.is_empty() {
            return Err(GatewayError::MissingExecutionContext(
                "parent_span_id is required".to_string(),
            ));
        }

        ctx.caller
            .validate(&self.shared_secret, Some(self.token_ttl_seconds))?;

        Ok(())
    }

    /// Run the centralized policy check.
    async fn authorize_operation(
        &self,
        ctx: &GatewayContext,
        operation: &str,
    ) -> Result<(), GatewayError> {
        let decision = self.policy.authorize(ctx, operation).await?;
        if !decision.allowed {
            return Err(GatewayError::PolicyDenied(
                decision.reason.unwrap_or_default(),
            ));
        }
        Ok(())
    }
}

/// Builder for creating custom SecurityCore configurations.
pub struct SecurityCoreBuilder {
    shared_secret: String,
    preset: Preset,
    token_ttl_seconds: i64,
    policy: Option<Box<dyn CentralizedPolicy>>,
}

impl SecurityCoreBuilder {
    fn new() -> Self {
        Self {
            shared_secret: String::new(),
            preset: Preset::Standard,
            token_ttl_seconds: DEFAULT_TOKEN_TTL_SECONDS,
            policy: None,
        }
    }

    /// Set the shared secret for caller token validation (required).
    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.shared_secret = secret.into();
        self
    }

    /// Set the Shield preset.
    pub fn with_preset(mut self, preset: Preset) -> Self {
        self.preset = preset;
        self
    }

    /// Set the token TTL in seconds.
    pub fn with_token_ttl(mut self, seconds: i64) -> Self {
        self.token_ttl_seconds = seconds;
        self
    }

    /// Set a custom centralized policy.
    pub fn with_policy(mut self, policy: Box<dyn CentralizedPolicy>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Build the SecurityCore instance.
    pub fn build(self) -> Result<SecurityCore, GatewayError> {
        if self.shared_secret.is_empty() {
            return Err(GatewayError::InvalidCallerToken(
                "shared_secret is required for SecurityCore".to_string(),
            ));
        }

        let shield = Shield::builder()
            .with_preset(self.preset)
            .build()
            .map_err(GatewayError::Shield)?;

        Ok(SecurityCore {
            shield,
            shared_secret: self.shared_secret,
            token_ttl_seconds: self.token_ttl_seconds,
            policy: self.policy.unwrap_or_else(|| Box::new(DefaultPolicy)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context(secret: &str) -> GatewayContext {
        GatewayContext {
            execution_id: "exec-123".to_string(),
            parent_span_id: "span-456".to_string(),
            caller: CallerToken::create("test-service", secret).unwrap(),
        }
    }

    #[tokio::test]
    async fn test_standard_gateway() {
        let core = SecurityCore::standard("test-secret".to_string()).unwrap();
        let ctx = test_context("test-secret");

        let result = core.scan_prompt("Hello world", &ctx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_missing_execution_id() {
        let core = SecurityCore::standard("test-secret".to_string()).unwrap();
        let ctx = GatewayContext {
            execution_id: "".to_string(),
            parent_span_id: "span-456".to_string(),
            caller: CallerToken::create("test-service", "test-secret").unwrap(),
        };

        let result = core.scan_prompt("Hello", &ctx).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GatewayError::MissingExecutionContext(_)
        ));
    }

    #[tokio::test]
    async fn test_invalid_caller_token() {
        let core = SecurityCore::standard("test-secret".to_string()).unwrap();
        let ctx = GatewayContext {
            execution_id: "exec-123".to_string(),
            parent_span_id: "span-456".to_string(),
            caller: CallerToken::create("test-service", "wrong-secret").unwrap(),
        };

        let result = core.scan_prompt("Hello", &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_missing_secret() {
        let result = SecurityCore::builder()
            .with_preset(Preset::Standard)
            .build();

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_builder_with_secret() {
        let core = SecurityCore::builder()
            .with_secret("my-secret")
            .with_preset(Preset::Permissive)
            .with_token_ttl(600)
            .build()
            .unwrap();

        let ctx = test_context("my-secret");
        let result = core.scan_prompt("Hello", &ctx).await;
        assert!(result.is_ok());
    }
}
