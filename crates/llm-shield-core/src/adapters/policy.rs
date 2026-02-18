//! # Policy Engine Adapter
//!
//! Thin adapter layer for consuming policy decisions from LLM-Policy-Engine.
//!
//! ## Purpose
//!
//! This module provides runtime hooks that query the policy engine during
//! message inspection, enabling dynamic policy-driven security decisions.
//!
//! ## Integration Pattern
//!
//! ```text
//! Shield Scanner → PolicyAdapter → LLM-Policy-Engine
//!                       ↓
//!              PolicyDecision (allow/deny/modify)
//!                       ↓
//!              ScanResult (with policy context)
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use llm_shield_core::adapters::policy::{PolicyAdapter, PolicyContext};
//!
//! // Create adapter with policy engine client
//! let adapter = PolicyAdapter::new(policy_client);
//!
//! // Evaluate policy during scan
//! let context = PolicyContext::new("user-123", "prompt-injection-check");
//! let decision = adapter.evaluate(&context, input_text).await?;
//!
//! if decision.should_block() {
//!     return Err(Error::policy_violation(decision.reason()));
//! }
//! ```

use crate::{Error, Result, ScanResult, Vault};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Policy decision returned by the policy engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Whether the content is allowed
    pub allowed: bool,
    /// Enforcement action to take
    pub action: EnforcementAction,
    /// Human-readable reason for the decision
    pub reason: Option<String>,
    /// Risk score adjustment from policy (0.0 to 1.0)
    pub risk_adjustment: Option<f32>,
    /// Matched policy rule IDs
    pub matched_rules: Vec<String>,
    /// Additional metadata from policy evaluation
    pub metadata: HashMap<String, serde_json::Value>,
}

impl PolicyDecision {
    /// Create an allow decision
    pub fn allow() -> Self {
        Self {
            allowed: true,
            action: EnforcementAction::Allow,
            reason: None,
            risk_adjustment: None,
            matched_rules: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Create a deny decision
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            action: EnforcementAction::Block,
            reason: Some(reason.into()),
            risk_adjustment: Some(1.0),
            matched_rules: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Check if the decision blocks the content
    pub fn should_block(&self) -> bool {
        matches!(self.action, EnforcementAction::Block)
    }

    /// Check if content should be modified/sanitized
    pub fn should_modify(&self) -> bool {
        matches!(self.action, EnforcementAction::Modify)
    }

    /// Get the reason for the decision
    pub fn reason(&self) -> &str {
        self.reason.as_deref().unwrap_or("No reason provided")
    }

    /// Add a matched rule
    pub fn with_rule(mut self, rule_id: impl Into<String>) -> Self {
        self.matched_rules.push(rule_id.into());
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.metadata.insert(key.into(), v);
        }
        self
    }
}

impl Default for PolicyDecision {
    fn default() -> Self {
        Self::allow()
    }
}

/// Enforcement actions that can be taken based on policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementAction {
    /// Allow the content through unchanged
    Allow,
    /// Block the content entirely
    Block,
    /// Modify/sanitize the content before proceeding
    Modify,
    /// Log the content but allow it through
    Audit,
    /// Require additional verification
    Challenge,
}

impl Default for EnforcementAction {
    fn default() -> Self {
        Self::Allow
    }
}

/// Context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    /// User or session identifier
    pub user_id: Option<String>,
    /// Tenant/organization identifier for multi-tenant scenarios
    pub tenant_id: Option<String>,
    /// The type of check being performed (e.g., "prompt-injection", "pii-detection")
    pub check_type: String,
    /// Additional context for policy evaluation
    pub attributes: HashMap<String, serde_json::Value>,
    /// Request timestamp
    pub timestamp: u64,
}

impl PolicyContext {
    /// Create a new policy context
    pub fn new(check_type: impl Into<String>) -> Self {
        Self {
            user_id: None,
            tenant_id: None,
            check_type: check_type.into(),
            attributes: HashMap::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }

    /// Set the user ID
    pub fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Set the tenant ID
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Add an attribute
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.attributes.insert(key.into(), v);
        }
        self
    }
}

/// Result type for policy operations
pub type PolicyResult<T> = std::result::Result<T, PolicyError>;

/// Errors specific to policy operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyError {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Whether the error is retryable
    pub retryable: bool,
}

impl PolicyError {
    /// Create a new policy error
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable: false,
        }
    }

    /// Mark the error as retryable
    pub fn retryable(mut self) -> Self {
        self.retryable = true;
        self
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for PolicyError {}

/// Trait for policy evaluation
///
/// Implementations connect to the LLM-Policy-Engine to evaluate
/// policies at runtime.
#[async_trait]
pub trait PolicyEvaluator: Send + Sync {
    /// Evaluate a policy for the given content and context
    async fn evaluate(
        &self,
        context: &PolicyContext,
        content: &str,
    ) -> PolicyResult<PolicyDecision>;

    /// Evaluate multiple policies in batch
    async fn evaluate_batch(
        &self,
        context: &PolicyContext,
        contents: &[&str],
    ) -> PolicyResult<Vec<PolicyDecision>> {
        let mut results = Vec::with_capacity(contents.len());
        for content in contents {
            results.push(self.evaluate(context, content).await?);
        }
        Ok(results)
    }

    /// Check if the policy engine is available
    async fn health_check(&self) -> PolicyResult<bool> {
        Ok(true)
    }
}

/// Main policy adapter for Shield integration
///
/// This adapter wraps a PolicyEvaluator implementation and provides
/// convenience methods for use within Shield scanners.
pub struct PolicyAdapter<E: PolicyEvaluator> {
    evaluator: Arc<E>,
    /// Default context to use when none is provided
    default_context: PolicyContext,
    /// Cache policy decisions in vault
    enable_caching: bool,
    /// Cache TTL in seconds
    cache_ttl: u64,
}

impl<E: PolicyEvaluator> PolicyAdapter<E> {
    /// Create a new policy adapter
    pub fn new(evaluator: E) -> Self {
        Self {
            evaluator: Arc::new(evaluator),
            default_context: PolicyContext::new("default"),
            enable_caching: false,
            cache_ttl: 300, // 5 minutes
        }
    }

    /// Create with a default context
    pub fn with_default_context(mut self, context: PolicyContext) -> Self {
        self.default_context = context;
        self
    }

    /// Enable caching of policy decisions
    pub fn with_caching(mut self, ttl_seconds: u64) -> Self {
        self.enable_caching = true;
        self.cache_ttl = ttl_seconds;
        self
    }

    /// Evaluate policy for content
    pub async fn evaluate(
        &self,
        context: &PolicyContext,
        content: &str,
    ) -> PolicyResult<PolicyDecision> {
        self.evaluator.evaluate(context, content).await
    }

    /// Evaluate policy using default context
    pub async fn evaluate_default(&self, content: &str) -> PolicyResult<PolicyDecision> {
        self.evaluator.evaluate(&self.default_context, content).await
    }

    /// Evaluate policy and apply result to ScanResult
    ///
    /// This is the main integration point for use in Shield scanners.
    /// It evaluates the policy and adjusts the ScanResult accordingly.
    pub async fn apply_policy(
        &self,
        context: &PolicyContext,
        content: &str,
        mut scan_result: ScanResult,
    ) -> Result<ScanResult> {
        let decision = self.evaluate(context, content).await.map_err(|e| {
            Error::scanner("policy", format!("Policy evaluation failed: {}", e))
        })?;

        // Apply risk adjustment if provided
        if let Some(adjustment) = decision.risk_adjustment {
            let current_risk = scan_result.risk_score;
            // Combine scores - take the maximum to be conservative
            scan_result.risk_score = current_risk.max(adjustment);
        }

        // Apply enforcement action
        match decision.action {
            EnforcementAction::Block => {
                scan_result.is_valid = false;
                scan_result = scan_result.with_metadata("policy_action", "block");
            }
            EnforcementAction::Modify => {
                scan_result = scan_result.with_metadata("policy_action", "modify");
            }
            EnforcementAction::Audit => {
                scan_result = scan_result.with_metadata("policy_action", "audit");
            }
            EnforcementAction::Challenge => {
                scan_result = scan_result.with_metadata("policy_action", "challenge");
            }
            EnforcementAction::Allow => {}
        }

        // Add matched rules to metadata
        if !decision.matched_rules.is_empty() {
            scan_result = scan_result.with_metadata("matched_policy_rules", &decision.matched_rules);
        }

        // Add policy reason if content was blocked
        if let Some(reason) = &decision.reason {
            scan_result = scan_result.with_metadata("policy_reason", reason);
        }

        Ok(scan_result)
    }

    /// Store policy decision in vault for later reference
    pub fn cache_decision(
        &self,
        vault: &Vault,
        cache_key: &str,
        decision: &PolicyDecision,
    ) -> Result<()> {
        if self.enable_caching {
            vault.set(format!("policy_cache:{}", cache_key), decision)?;
        }
        Ok(())
    }

    /// Retrieve cached policy decision from vault
    pub fn get_cached_decision(
        &self,
        vault: &Vault,
        cache_key: &str,
    ) -> Result<Option<PolicyDecision>> {
        if self.enable_caching {
            vault.get(format!("policy_cache:{}", cache_key))
        } else {
            Ok(None)
        }
    }

    /// Check if the policy engine is healthy
    pub async fn is_healthy(&self) -> bool {
        self.evaluator.health_check().await.unwrap_or(false)
    }
}

/// Default no-op policy evaluator
///
/// Used when no policy engine is configured. Always allows content.
pub struct NoOpPolicyEvaluator;

#[async_trait]
impl PolicyEvaluator for NoOpPolicyEvaluator {
    async fn evaluate(
        &self,
        _context: &PolicyContext,
        _content: &str,
    ) -> PolicyResult<PolicyDecision> {
        Ok(PolicyDecision::allow())
    }
}

/// Runtime policy hook for scanner integration
///
/// This struct can be stored in the Vault and accessed by scanners
/// to query policies at runtime.
#[derive(Clone)]
pub struct PolicyHook {
    /// The check type for this hook
    pub check_type: String,
    /// Whether the hook is enabled
    pub enabled: bool,
    /// Default action when policy engine is unavailable
    pub fallback_action: EnforcementAction,
}

impl PolicyHook {
    /// Create a new policy hook
    pub fn new(check_type: impl Into<String>) -> Self {
        Self {
            check_type: check_type.into(),
            enabled: true,
            fallback_action: EnforcementAction::Allow,
        }
    }

    /// Disable the hook
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Set fallback action
    pub fn with_fallback(mut self, action: EnforcementAction) -> Self {
        self.fallback_action = action;
        self
    }

    /// Store this hook in the vault
    pub fn register(self, vault: &Vault) -> Result<()> {
        vault.set(format!("policy_hook:{}", self.check_type), &self)
            .map_err(|e| Error::vault(format!("Failed to register policy hook: {}", e)))
    }

    /// Retrieve a hook from the vault
    pub fn get(vault: &Vault, check_type: &str) -> Result<Option<Self>> {
        vault.get(format!("policy_hook:{}", check_type))
    }
}

impl Serialize for PolicyHook {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("PolicyHook", 3)?;
        state.serialize_field("check_type", &self.check_type)?;
        state.serialize_field("enabled", &self.enabled)?;
        state.serialize_field("fallback_action", &self.fallback_action)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PolicyHook {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct PolicyHookHelper {
            check_type: String,
            enabled: bool,
            fallback_action: EnforcementAction,
        }

        let helper = PolicyHookHelper::deserialize(deserializer)?;
        Ok(Self {
            check_type: helper.check_type,
            enabled: helper.enabled,
            fallback_action: helper.fallback_action,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_decision_allow() {
        let decision = PolicyDecision::allow();
        assert!(decision.allowed);
        assert!(!decision.should_block());
        assert!(!decision.should_modify());
    }

    #[test]
    fn test_policy_decision_deny() {
        let decision = PolicyDecision::deny("Test reason");
        assert!(!decision.allowed);
        assert!(decision.should_block());
        assert_eq!(decision.reason(), "Test reason");
    }

    #[test]
    fn test_policy_context() {
        let context = PolicyContext::new("test-check")
            .with_user("user-123")
            .with_tenant("tenant-456")
            .with_attribute("custom", "value");

        assert_eq!(context.check_type, "test-check");
        assert_eq!(context.user_id, Some("user-123".to_string()));
        assert_eq!(context.tenant_id, Some("tenant-456".to_string()));
        assert!(context.attributes.contains_key("custom"));
    }

    #[test]
    fn test_policy_hook_serialization() {
        let hook = PolicyHook::new("prompt-injection")
            .with_fallback(EnforcementAction::Block);

        let json = serde_json::to_string(&hook).unwrap();
        let deserialized: PolicyHook = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.check_type, "prompt-injection");
        assert!(deserialized.enabled);
        assert_eq!(deserialized.fallback_action, EnforcementAction::Block);
    }

    #[tokio::test]
    async fn test_noop_evaluator() {
        let evaluator = NoOpPolicyEvaluator;
        let context = PolicyContext::new("test");
        let decision = evaluator.evaluate(&context, "test content").await.unwrap();

        assert!(decision.allowed);
        assert!(!decision.should_block());
    }

    #[tokio::test]
    async fn test_policy_adapter() {
        let adapter = PolicyAdapter::new(NoOpPolicyEvaluator)
            .with_default_context(PolicyContext::new("default-check"));

        let decision = adapter.evaluate_default("test content").await.unwrap();
        assert!(decision.allowed);

        assert!(adapter.is_healthy().await);
    }
}
