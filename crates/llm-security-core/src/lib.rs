//! # LLM-Security-Core
//!
//! The sole authorized gateway for all LLM-Shield scanning operations.
//!
//! ## Overview
//!
//! LLM-Security-Core enforces that all scanning operations go through a centralized
//! gateway with:
//!
//! - **Caller authentication**: HMAC-signed CallerTokens verify caller identity
//! - **Execution context**: Required `execution_id` + `parent_span_id` for tracing
//! - **Centralized policy**: Pluggable authorization decisions
//!
//! Direct calls to `llm-shield-sdk::Shield` are forbidden when the `enforce-gateway`
//! feature is active.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use llm_security_core::{SecurityCore, CallerToken};
//! use llm_security_core::policy::GatewayContext;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let core = SecurityCore::standard("my-shared-secret".to_string())?;
//!
//!     let token = CallerToken::create("my-service", "my-shared-secret")?;
//!     let ctx = GatewayContext {
//!         execution_id: "exec-123".to_string(),
//!         parent_span_id: "span-456".to_string(),
//!         caller: token,
//!     };
//!
//!     let result = core.scan_prompt("Hello world", &ctx).await?;
//!     println!("Valid: {}, Risk: {}", result.is_valid, result.risk_score);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Custom Policy
//!
//! ```rust,ignore
//! use llm_security_core::policy::{CentralizedPolicy, GatewayContext, PolicyDecision};
//! use async_trait::async_trait;
//!
//! struct MyPolicy;
//!
//! #[async_trait]
//! impl CentralizedPolicy for MyPolicy {
//!     async fn authorize(
//!         &self,
//!         context: &GatewayContext,
//!         operation: &str,
//!     ) -> Result<PolicyDecision, llm_security_core::GatewayError> {
//!         if context.caller.caller_id == "admin-service" {
//!             Ok(PolicyDecision::allow())
//!         } else {
//!             Ok(PolicyDecision::deny("Only admin-service is allowed"))
//!         }
//!     }
//! }
//! ```

pub mod caller_token;
pub mod error;
pub mod gateway;
pub mod policy;

// Primary exports
pub use caller_token::CallerToken;
pub use error::GatewayError;
pub use gateway::{SecurityCore, SecurityCoreBuilder};
pub use policy::{CentralizedPolicy, DefaultPolicy, GatewayContext, PolicyDecision};

// Re-export commonly needed types from llm-shield-sdk
pub use llm_shield_sdk::{Preset, ScanResult, Scanner, ScannerType, Severity};
