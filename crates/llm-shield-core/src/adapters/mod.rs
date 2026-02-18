//! # Adapter Modules for Upstream Integration
//!
//! This module provides thin, additive adapters for consuming data from
//! upstream LLM-Dev-Ops repositories without modifying existing Shield logic.
//!
//! ## Phase 2B Integration
//!
//! These adapters implement the "consumes-from" pattern, safely importing
//! and consuming data from:
//! - **LLM-Policy-Engine**: Rule evaluation, policy documents, enforcement decisions
//! - **LLM-Config-Manager**: Dynamic configuration, thresholds, patterns
//!
//! ## Design Principles
//!
//! 1. **Additive Only**: No modifications to existing public APIs
//! 2. **Backward Compatible**: All existing functionality remains unchanged
//! 3. **No Circular Imports**: Shield only consumes from upstream, never exports to them
//! 4. **Runtime Hooks**: Query policy engine during message inspection
//! 5. **Config-Driven**: Load shield parameters from config-manager

pub mod policy;
pub mod config;

// Re-export main types for convenience
pub use policy::{
    PolicyAdapter, PolicyDecision, PolicyContext, PolicyEvaluator,
    EnforcementAction, PolicyResult, PolicyHook,
};
pub use config::{
    ConfigAdapter, ShieldParameters, ThresholdConfig, PatternConfig,
    ConfigLoader, ConfigSource, ConfigHook,
};
