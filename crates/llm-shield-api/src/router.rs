//! Route configuration

use axum::{middleware, routing::{get, post}, Router};

use crate::handlers;
use crate::middleware::{execution_context_middleware, gateway_middleware};
use crate::state::AppState;

/// Create the application router
///
/// ## Routes
/// - GET /health - Basic health check
/// - GET /health/ready - Readiness probe
/// - GET /health/live - Liveness probe
/// - GET /version - Version information
/// - POST /v1/scan/prompt - Scan user prompt
pub fn create_router() -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/health/ready", get(handlers::ready))
        .route("/health/live", get(handlers::live))
        .route("/version", get(handlers::version))
}

/// Create the application router with state
///
/// Scan routes are guarded by two middleware layers:
/// 1. **Gateway middleware**: Validates caller tokens (LLM-Security-Core enforcement).
///    Only active when `GATEWAY_SHARED_SECRET` env var is set. No-op otherwise.
/// 2. **Execution context middleware**: Validates `x-execution-id` and `x-parent-span-id`.
///    Rejects with 400 if either is missing. Creates a repo-level ExecutionSpan.
///
/// Health/version/scanner-list probes are NOT guarded (infrastructure routes).
pub fn create_router_with_state(state: AppState) -> Router {
    // Scan routes: require gateway token + execution context
    let scan_routes = Router::new()
        .route("/v1/scan/prompt", post(handlers::scan_prompt))
        .route("/v1/scan/output", post(handlers::scan_output))
        .route("/v1/scan/batch", post(handlers::scan_batch))
        .layer(middleware::from_fn(execution_context_middleware))
        .layer(middleware::from_fn(gateway_middleware));

    // Infrastructure routes: no execution context required
    Router::new()
        .route("/health", get(handlers::health))
        .route("/health/ready", get(handlers::ready))
        .route("/health/live", get(handlers::live))
        .route("/version", get(handlers::version))
        .route("/v1/scanners", get(handlers::list_scanners))
        .merge(scan_routes)
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt; // For `oneshot`

    #[tokio::test]
    async fn test_health_route() {
        let app = create_router();

        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_ready_route() {
        let app = create_router();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_live_route() {
        let app = create_router();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_version_route() {
        let app = create_router();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_not_found() {
        let app = create_router();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/notfound")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
