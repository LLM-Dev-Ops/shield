//! Execution context middleware for the Agentics Foundational Execution Unit.
//!
//! This middleware:
//! 1. Extracts `x-execution-id` and `x-parent-span-id` from request headers
//! 2. Rejects with 400 if either is missing (execution MUST NOT be silent)
//! 3. Creates a repo-level `ExecutionSpan` and inserts it into request extensions
//!
//! Only applied to scan routes -- health/version probes remain unaffected.

use crate::models::ExecutionSpan;
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Middleware that validates execution context and creates a repo-level span.
///
/// Rejects requests missing `x-execution-id` or `x-parent-span-id` headers
/// with a 400 status code and JSON error body.
pub async fn execution_context_middleware(mut request: Request, next: Next) -> Response {
    let execution_id = request
        .headers()
        .get("x-execution-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let parent_span_id = request
        .headers()
        .get("x-parent-span-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    match (execution_id, parent_span_id) {
        (Some(eid), Some(psid)) => {
            let repo_span = ExecutionSpan::new_repo(&eid, &psid);
            request.extensions_mut().insert(repo_span);
            next.run(request).await
        }
        _ => {
            let body = serde_json::json!({
                "error": "Missing Execution Context",
                "message": "x-execution-id and x-parent-span-id headers are required for all scan operations. This repository MUST NOT execute silently.",
                "code": "EXECUTION_CONTEXT_REQUIRED",
            });
            (
                StatusCode::BAD_REQUEST,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "application/json",
                )],
                body.to_string(),
            )
                .into_response()
        }
    }
}
