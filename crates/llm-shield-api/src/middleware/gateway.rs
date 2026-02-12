//! LLM-Security-Core gateway middleware.
//!
//! Validates caller tokens on scan routes to ensure LLM-Shield is ONLY
//! invoked via LLM-Security-Core. This middleware is enabled when the
//! `GATEWAY_SHARED_SECRET` environment variable is set.
//!
//! When the secret is not configured, this middleware is a no-op for
//! backward compatibility.

use axum::{
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde_json::json;
use std::sync::OnceLock;

type HmacSha256 = Hmac<Sha256>;

/// Cached gateway shared secret (loaded once from env).
static GATEWAY_SECRET: OnceLock<Option<String>> = OnceLock::new();

fn get_gateway_secret() -> &'static Option<String> {
    GATEWAY_SECRET.get_or_init(|| {
        std::env::var("GATEWAY_SHARED_SECRET").ok().filter(|s| !s.is_empty())
    })
}

/// Authenticated caller identity, added to request extensions after validation.
#[derive(Debug, Clone)]
pub struct GatewayCaller {
    pub caller_id: String,
}

/// Gateway middleware that validates caller tokens.
///
/// When `GATEWAY_SHARED_SECRET` is configured:
/// - Extracts `x-caller-id`, `x-caller-signature`, `x-caller-issued-at` headers
/// - Validates HMAC-SHA256 signature against the secret
/// - Checks token expiry (5 minute TTL, 30s clock skew tolerance)
/// - Adds `GatewayCaller` to request extensions
/// - Returns 401 if validation fails
///
/// When `GATEWAY_SHARED_SECRET` is NOT configured:
/// - Passes through all requests (backward compatible)
pub async fn gateway_middleware<B>(
    mut request: Request<B>,
    next: Next<B>,
) -> Response {
    let secret = match get_gateway_secret() {
        Some(secret) => secret,
        None => {
            // No secret configured - skip validation (backward compatible)
            return next.run(request).await;
        }
    };

    // Extract caller token headers
    let caller_id = request
        .headers()
        .get("x-caller-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let signature = request
        .headers()
        .get("x-caller-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let issued_at = request
        .headers()
        .get("x-caller-issued-at")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Check required fields
    if caller_id.is_empty() || signature.is_empty() || issued_at.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Missing Caller Token",
                "message": "A valid caller token is required. Provide x-caller-id, x-caller-signature, x-caller-issued-at headers. Direct calls to LLM-Shield are forbidden; use LLM-Security-Core.",
                "code": "CALLER_TOKEN_REQUIRED"
            })),
        )
            .into_response();
    }

    // Verify HMAC signature
    let payload = format!("{}|{}", caller_id, issued_at);
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Gateway configuration error" })),
            )
                .into_response();
        }
    };
    mac.update(payload.as_bytes());

    let sig_bytes = match hex::decode(&signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Invalid Caller Token",
                    "message": "Signature is not valid hex",
                    "code": "INVALID_CALLER_TOKEN"
                })),
            )
                .into_response();
        }
    };

    if mac.verify_slice(&sig_bytes).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid Caller Token",
                "message": "Signature mismatch",
                "code": "INVALID_CALLER_TOKEN"
            })),
        )
            .into_response();
    }

    // Check expiry (5 minute TTL, 30s clock skew)
    if let Ok(issued_time) = chrono::DateTime::parse_from_rfc3339(&issued_at) {
        let now = chrono::Utc::now();
        let age = now.signed_duration_since(issued_time);

        if age.num_seconds() > 300 {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Invalid Caller Token",
                    "message": format!("Token expired (age: {}s, TTL: 300s)", age.num_seconds()),
                    "code": "EXPIRED_CALLER_TOKEN"
                })),
            )
                .into_response();
        }

        if age.num_seconds() < -30 {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Invalid Caller Token",
                    "message": "Token issued_at is in the future",
                    "code": "INVALID_CALLER_TOKEN"
                })),
            )
                .into_response();
        }
    } else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid Caller Token",
                "message": "Invalid issued_at timestamp format (expected RFC 3339)",
                "code": "INVALID_CALLER_TOKEN"
            })),
        )
            .into_response();
    }

    // Add authenticated caller to request extensions
    request.extensions_mut().insert(GatewayCaller { caller_id });

    next.run(request).await
}
