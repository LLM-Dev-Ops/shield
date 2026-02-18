//! Internal ingest handler for security-core fanout events

use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

/// Inbound event from security-core fanout
#[derive(Debug, Deserialize)]
pub struct IngestEvent {
    pub source: String,
    pub event_type: String,
    pub execution_id: String,
    pub timestamp: String,
    pub payload: serde_json::Value,
}

/// 202 Accepted response
#[derive(Debug, Serialize)]
pub struct IngestResponse {
    pub status: &'static str,
    pub execution_id: String,
}

/// POST /api/v1/scan — internal ingest endpoint for security-core bundle fanout.
///
/// Accepts scan-request events, logs them, spawns async processing, and
/// returns 202 Accepted immediately. No auth required (Cloud Run IAM perimeter).
pub async fn ingest_scan(
    Json(event): Json<IngestEvent>,
) -> impl IntoResponse {
    tracing::info!(
        execution_id = %event.execution_id,
        source = %event.source,
        event_type = %event.event_type,
        timestamp = %event.timestamp,
        "inbound ingest event received"
    );

    let execution_id = event.execution_id.clone();

    // Process asynchronously — don't block the response
    tokio::spawn(async move {
        tracing::info!(
            execution_id = %event.execution_id,
            "processing ingest event"
        );
        // TODO: wire up to actual scan pipeline / persistence
    });

    (
        StatusCode::ACCEPTED,
        Json(IngestResponse {
            status: "accepted",
            execution_id,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new().route("/api/v1/scan", post(ingest_scan))
    }

    #[tokio::test]
    async fn test_ingest_returns_202() {
        let body = serde_json::json!({
            "source": "security-core",
            "event_type": "scan_request",
            "execution_id": "exec-abc-123",
            "timestamp": "2026-02-18T00:00:00Z",
            "payload": { "key": "value" }
        });

        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/scan")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: IngestResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp.status, "accepted");
        assert_eq!(resp.execution_id, "exec-abc-123");
    }

    #[tokio::test]
    async fn test_ingest_rejects_bad_payload() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/scan")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"bad": "data"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
