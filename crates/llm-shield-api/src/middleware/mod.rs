//! Middleware layers
//!
//! ## Available Middleware
//!
//! - `auth`: API key authentication
//! - `rate_limit`: Rate limiting and concurrent request limiting
//! - `execution_context`: Agentics execution context validation and repo span creation

pub mod auth;
pub mod execution_context;
pub mod rate_limit;

// Re-exports
pub use auth::{auth_middleware, optional_auth_middleware, AuthenticatedUser};
pub use execution_context::execution_context_middleware;
pub use rate_limit::{rate_limit_middleware, ClientTier};
