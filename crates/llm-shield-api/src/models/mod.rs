//! Data models for API requests and responses

pub mod error;
pub mod execution;
pub mod request;
pub mod response;

pub use error::{ApiError, ErrorResponse};
pub use request::{
    AnonymizeRequest, BatchScanRequest, DeanonymizeRequest, ScanOutputRequest, ScanPromptRequest,
};
pub use response::{
    AnonymizeResponse, AnonymizedEntityDto, BatchScanResponse, DeanonymizeResponse, EntityDto,
    ListScannersResponse, RiskFactorDto, ScanResponse, ScannerMetadataResponse, ScannerResult,
};
pub use execution::{
    EnvelopedBatchScanResponse, EnvelopedScanResponse, ExecutionOutput, ExecutionSpan, SpanArtifact,
    SpanStatus, SpanType,
};

/// Generic API response wrapper
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiResponse<T> {
    /// Indicates if the request was successful
    pub success: bool,

    /// Response data (present on success)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,

    /// Error information (present on failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorResponse>,

    /// Request metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ResponseMetadata>,
}

impl<T> ApiResponse<T> {
    /// Create a successful response
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            metadata: None,
        }
    }

    /// Create a successful response with metadata
    pub fn success_with_metadata(data: T, metadata: ResponseMetadata) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            metadata: Some(metadata),
        }
    }

    /// Create an error response
    pub fn error(error: ErrorResponse) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            metadata: None,
        }
    }
}

/// Response metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseMetadata {
    /// Request ID for tracing
    pub request_id: String,

    /// Processing time in milliseconds
    pub processing_time_ms: u64,

    /// API version
    pub version: String,

    /// Timestamp
    pub timestamp: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response_success() {
        let response = ApiResponse::success("test data");
        assert!(response.success);
        assert_eq!(response.data, Some("test data"));
        assert!(response.error.is_none());
    }

    #[test]
    fn test_api_response_error() {
        let error = ErrorResponse {
            code: "TEST_ERROR".to_string(),
            message: "Test error message".to_string(),
            details: None,
        };
        let response: ApiResponse<()> = ApiResponse::error(error.clone());
        assert!(!response.success);
        assert!(response.data.is_none());
        assert_eq!(response.error.unwrap().code, "TEST_ERROR");
    }

    #[test]
    fn test_api_response_serialization() {
        let response = ApiResponse::success("test");
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"data\":\"test\""));
    }
}
