//! Scan handlers

use crate::models::{
    ApiError, BatchScanRequest, EnvelopedBatchScanResponse, EnvelopedScanResponse,
    ExecutionSpan, ScanOutputRequest, ScanPromptRequest,
};
use crate::services::ScannerService;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use llm_shield_core::ScannerType;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use validator::Validate;

/// POST /v1/scan/prompt - Scan user prompt
///
/// Executes all requested input scanners on the provided prompt.
///
/// ## Request Body
/// ```json
/// {
///   "prompt": "User prompt text to scan",
///   "scanners": ["toxicity", "secrets"],  // Optional, empty = all input scanners
///   "cacheEnabled": true                   // Optional, default true
/// }
/// ```
///
/// ## Response
/// ```json
/// {
///   "isValid": true,
///   "riskScore": 0.0,
///   "sanitizedText": "...",
///   "scannerResults": [...],
///   "scanTimeMs": 50,
///   "cacheHit": false
/// }
/// ```
pub async fn scan_prompt(
    State(state): State<AppState>,
    Extension(mut repo_span): Extension<ExecutionSpan>,
    Json(req): Json<ScanPromptRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate request
    req.validate()
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;

    let start = Instant::now();

    // Check cache if enabled
    if req.cache_enabled {
        let cache_key = format!("prompt:{}", req.prompt);
        if let Some(_cached_result) = state.cache.get(&cache_key) {
            // TODO: Deserialize cached ScanResponse
            // For now, fall through to actual scan
        }
    }

    // Determine which scanners to run
    let scanners_to_run: Vec<_> = if req.scanners.is_empty() {
        // Get all input scanners
        state
            .scanners
            .values()
            .filter(|s| matches!(s.scanner_type(), ScannerType::Input | ScannerType::Bidirectional))
            .cloned()
            .collect()
    } else {
        // Get requested scanners
        let mut scanners = Vec::new();
        for scanner_name in &req.scanners {
            match state.get_scanner(scanner_name) {
                Some(scanner) => scanners.push(scanner),
                None => {
                    return Err(ApiError::NotFound(format!(
                        "Scanner not found: {}",
                        scanner_name
                    )))
                }
            }
        }
        scanners
    };

    if scanners_to_run.is_empty() {
        return Err(ApiError::InvalidRequest(
            "No scanners available or requested".to_string(),
        ));
    }

    // Collect scanner names for agent spans
    let scanner_names: Vec<String> = scanners_to_run.iter().map(|s| s.name().to_string()).collect();

    // Execute scanners
    let scanner_service = ScannerService::new();
    let scanner_results = scanner_service
        .execute_scanners(scanners_to_run, &req.prompt)
        .await
        .map_err(|e| ApiError::ScannerError(e))?;

    let scan_time_ms = start.elapsed().as_millis() as u64;

    // Create agent spans for each scanner that executed
    for (i, scanner_name) in scanner_names.iter().enumerate() {
        let mut agent_span = ExecutionSpan::new_agent(&repo_span, scanner_name);
        if let Some(result) = scanner_results.get(i) {
            agent_span.attach_artifact(
                "detection_signal",
                serde_json::to_value(result).unwrap_or_default(),
            );
        }
        agent_span.complete();
        repo_span.children.push(agent_span);
    }

    // Create response
    let response = scanner_service.create_scan_response(scanner_results, scan_time_ms, false);

    // Cache result if enabled
    if req.cache_enabled {
        // TODO: Cache the response
    }

    // Finalize repo span and build execution output
    let execution = repo_span
        .finalize()
        .map_err(|e| ApiError::InvalidRequest(e))?;

    Ok((
        StatusCode::OK,
        Json(EnvelopedScanResponse {
            result: response,
            execution,
        }),
    ))
}

/// POST /v1/scan/output - Scan LLM output
///
/// Executes all requested output scanners on the provided LLM output.
/// The prompt is provided for context but output is what gets scanned.
///
/// ## Request Body
/// ```json
/// {
///   "prompt": "User prompt text",
///   "output": "LLM response to scan",
///   "scanners": ["malicious_urls", "sensitive"],  // Optional, empty = all output scanners
///   "cacheEnabled": true                          // Optional, default true
/// }
/// ```
///
/// ## Response
/// ```json
/// {
///   "isValid": true,
///   "riskScore": 0.0,
///   "sanitizedText": "...",
///   "scannerResults": [...],
///   "scanTimeMs": 50,
///   "cacheHit": false
/// }
/// ```
pub async fn scan_output(
    State(state): State<AppState>,
    Extension(mut repo_span): Extension<ExecutionSpan>,
    Json(req): Json<ScanOutputRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate request
    req.validate()
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;

    let start = Instant::now();

    // Check cache if enabled
    if req.cache_enabled {
        let cache_key = format!("output:{}:{}", req.prompt, req.output);
        if let Some(_cached_result) = state.cache.get(&cache_key) {
            // TODO: Deserialize cached ScanResponse
            // For now, fall through to actual scan
        }
    }

    // Determine which scanners to run
    let scanners_to_run: Vec<_> = if req.scanners.is_empty() {
        // Get all output scanners
        state
            .scanners
            .values()
            .filter(|s| matches!(s.scanner_type(), ScannerType::Output | ScannerType::Bidirectional))
            .cloned()
            .collect()
    } else {
        // Get requested scanners
        let mut scanners = Vec::new();
        for scanner_name in &req.scanners {
            match state.get_scanner(scanner_name) {
                Some(scanner) => scanners.push(scanner),
                None => {
                    return Err(ApiError::NotFound(format!(
                        "Scanner not found: {}",
                        scanner_name
                    )))
                }
            }
        }
        scanners
    };

    if scanners_to_run.is_empty() {
        return Err(ApiError::InvalidRequest(
            "No scanners available or requested".to_string(),
        ));
    }

    // Collect scanner names for agent spans
    let scanner_names: Vec<String> = scanners_to_run.iter().map(|s| s.name().to_string()).collect();

    // Execute scanners on output (prompt available for context)
    // TODO: Pass prompt as context to scanners that need it
    let scanner_service = ScannerService::new();
    let scanner_results = scanner_service
        .execute_scanners(scanners_to_run, &req.output)
        .await
        .map_err(|e| ApiError::ScannerError(e))?;

    let scan_time_ms = start.elapsed().as_millis() as u64;

    // Create agent spans for each scanner that executed
    for (i, scanner_name) in scanner_names.iter().enumerate() {
        let mut agent_span = ExecutionSpan::new_agent(&repo_span, scanner_name);
        if let Some(result) = scanner_results.get(i) {
            agent_span.attach_artifact(
                "detection_signal",
                serde_json::to_value(result).unwrap_or_default(),
            );
        }
        agent_span.complete();
        repo_span.children.push(agent_span);
    }

    // Create response
    let response = scanner_service.create_scan_response(scanner_results, scan_time_ms, false);

    // Cache result if enabled
    if req.cache_enabled {
        // TODO: Cache the response
    }

    // Finalize repo span and build execution output
    let execution = repo_span
        .finalize()
        .map_err(|e| ApiError::InvalidRequest(e))?;

    Ok((
        StatusCode::OK,
        Json(EnvelopedScanResponse {
            result: response,
            execution,
        }),
    ))
}

/// POST /v1/scan/batch - Scan multiple prompts in parallel
///
/// Executes scans on multiple prompts with controlled concurrency.
///
/// ## Request Body
/// ```json
/// {
///   "items": [
///     {
///       "prompt": "First prompt",
///       "scanners": [],
///       "cacheEnabled": true
///     },
///     {
///       "prompt": "Second prompt",
///       "scanners": ["toxicity"],
///       "cacheEnabled": false
///     }
///   ],
///   "maxConcurrent": 5  // Optional, default 5
/// }
/// ```
///
/// ## Response
/// ```json
/// {
///   "results": [...],
///   "totalTimeMs": 150,
///   "successCount": 2,
///   "failureCount": 0
/// }
/// ```
pub async fn scan_batch(
    State(state): State<AppState>,
    Extension(mut repo_span): Extension<ExecutionSpan>,
    Json(req): Json<BatchScanRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate request
    req.validate()
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;

    let start = Instant::now();

    // Create semaphore for concurrency control
    let semaphore = Arc::new(Semaphore::new(req.max_concurrent));
    let mut handles = Vec::new();

    // Spawn tasks for each item
    for item in req.items {
        let state = state.clone();
        let semaphore = semaphore.clone();

        let handle = tokio::spawn(async move {
            // Acquire semaphore permit
            let _permit = semaphore.acquire().await.unwrap();

            // Process individual scan prompt
            let result = process_scan_prompt_internal(&state, item).await;
            result
        });

        handles.push(handle);
    }

    // Collect results and create agent spans for each batch item
    let mut results = Vec::new();
    let mut success_count = 0;
    let mut failure_count = 0;

    for (i, handle) in handles.into_iter().enumerate() {
        let agent_name = format!("batch-scan-item-{}", i);
        let mut agent_span = ExecutionSpan::new_agent(&repo_span, &agent_name);

        match handle.await {
            Ok(Ok(scan_response)) => {
                agent_span.attach_artifact(
                    "detection_signal",
                    serde_json::to_value(&scan_response).unwrap_or_default(),
                );
                agent_span.complete();
                results.push(scan_response);
                success_count += 1;
            }
            Ok(Err(e)) => {
                agent_span.fail(&e);
                failure_count += 1;
            }
            Err(e) => {
                agent_span.fail(&format!("Task join error: {}", e));
                failure_count += 1;
            }
        }

        repo_span.children.push(agent_span);
    }

    let total_time_ms = start.elapsed().as_millis() as u64;

    let response = crate::models::response::BatchScanResponse {
        results,
        total_time_ms,
        success_count,
        failure_count,
    };

    // Finalize repo span and build execution output
    let execution = repo_span
        .finalize()
        .map_err(|e| ApiError::InvalidRequest(e))?;

    Ok((
        StatusCode::OK,
        Json(EnvelopedBatchScanResponse {
            result: response,
            execution,
        }),
    ))
}

/// Internal helper to process a single scan prompt
async fn process_scan_prompt_internal(
    state: &AppState,
    req: ScanPromptRequest,
) -> Result<crate::models::response::ScanResponse, String> {
    // Validate request
    req.validate()
        .map_err(|e| format!("Validation error: {}", e))?;

    let start = Instant::now();

    // Determine which scanners to run
    let scanners_to_run = if req.scanners.is_empty() {
        // Get all input scanners
        state
            .scanners
            .values()
            .filter(|s| matches!(s.scanner_type(), ScannerType::Input | ScannerType::Bidirectional))
            .cloned()
            .collect()
    } else {
        // Get requested scanners
        let mut scanners = Vec::new();
        for scanner_name in &req.scanners {
            match state.get_scanner(scanner_name) {
                Some(scanner) => scanners.push(scanner),
                None => {
                    return Err(format!("Scanner not found: {}", scanner_name));
                }
            }
        }
        scanners
    };

    if scanners_to_run.is_empty() {
        return Err("No scanners available or requested".to_string());
    }

    // Execute scanners
    let scanner_service = ScannerService::new();
    let scanner_results = scanner_service
        .execute_scanners(scanners_to_run, &req.prompt)
        .await?;

    let scan_time_ms = start.elapsed().as_millis() as u64;

    // Create response
    let response = scanner_service.create_scan_response(scanner_results, scan_time_ms, false);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppStateBuilder;
    use llm_shield_core::{async_trait, Result, ScanResult, Scanner, Vault};
    use std::sync::Arc;

    fn test_repo_span() -> ExecutionSpan {
        ExecutionSpan::new_repo("test-execution-id", "test-parent-span-id")
    }

    struct MockScanner {
        name: String,
        is_valid: bool,
        risk_score: f32,
        scanner_type: ScannerType,
    }

    #[async_trait]
    impl Scanner for MockScanner {
        fn name(&self) -> &str {
            &self.name
        }

        async fn scan(&self, input: &str, _vault: &Vault) -> Result<ScanResult> {
            Ok(ScanResult::new(
                input.to_string(),
                self.is_valid,
                self.risk_score,
            ))
        }

        fn scanner_type(&self) -> ScannerType {
            self.scanner_type
        }
    }

    fn create_test_state() -> AppState {
        let config = crate::config::AppConfig::default();
        AppStateBuilder::new(config)
            .register_scanner(Arc::new(MockScanner {
                name: "toxicity".to_string(),
                is_valid: true,
                risk_score: 0.0,
                scanner_type: ScannerType::Input,
            }))
            .register_scanner(Arc::new(MockScanner {
                name: "secrets".to_string(),
                is_valid: true,
                risk_score: 0.0,
                scanner_type: ScannerType::Input,
            }))
            .build()
    }

    #[tokio::test]
    async fn test_scan_prompt_valid_request() {
        let state = create_test_state();
        let req = ScanPromptRequest {
            prompt: "Hello world".to_string(),
            scanners: vec!["toxicity".to_string()],
            cache_enabled: false,
        };

        let result = scan_prompt(State(state), Extension(test_repo_span()), Json(req)).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_scan_prompt_empty_prompt() {
        let state = create_test_state();
        let req = ScanPromptRequest {
            prompt: "".to_string(),
            scanners: vec![],
            cache_enabled: false,
        };

        let result = scan_prompt(State(state), Extension(test_repo_span()), Json(req)).await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        match err {
            ApiError::ValidationError(_) => {}
            _ => panic!("Expected ValidationError"),
        }
    }

    #[tokio::test]
    async fn test_scan_prompt_nonexistent_scanner() {
        let state = create_test_state();
        let req = ScanPromptRequest {
            prompt: "Test".to_string(),
            scanners: vec!["nonexistent".to_string()],
            cache_enabled: false,
        };

        let result = scan_prompt(State(state), Extension(test_repo_span()), Json(req)).await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        match err {
            ApiError::NotFound(_) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_scan_prompt_all_scanners() {
        let state = create_test_state();
        let req = ScanPromptRequest {
            prompt: "Test prompt".to_string(),
            scanners: vec![], // Empty = all scanners
            cache_enabled: false,
        };

        let result = scan_prompt(State(state), Extension(test_repo_span()), Json(req)).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_scan_prompt_multiple_scanners() {
        let state = create_test_state();
        let req = ScanPromptRequest {
            prompt: "Test prompt".to_string(),
            scanners: vec!["toxicity".to_string(), "secrets".to_string()],
            cache_enabled: false,
        };

        let result = scan_prompt(State(state), Extension(test_repo_span()), Json(req)).await;

        assert!(result.is_ok());
    }

    // Tests for scan_output

    fn create_output_scanner_state() -> AppState {
        let config = crate::config::AppConfig::default();
        AppStateBuilder::new(config)
            .register_scanner(Arc::new(MockScanner {
                name: "malicious_urls".to_string(),
                is_valid: true,
                risk_score: 0.0,
                scanner_type: ScannerType::Output,
            }))
            .register_scanner(Arc::new(MockScanner {
                name: "sensitive".to_string(),
                is_valid: true,
                risk_score: 0.0,
                scanner_type: ScannerType::Output,
            }))
            .build()
    }

    #[tokio::test]
    async fn test_scan_output_valid_request() {
        let state = create_output_scanner_state();
        let req = ScanOutputRequest {
            prompt: "What is the capital of France?".to_string(),
            output: "The capital of France is Paris.".to_string(),
            scanners: vec!["malicious_urls".to_string()],
            cache_enabled: false,
        };

        let result = scan_output(State(state), Extension(test_repo_span()), Json(req)).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_scan_output_empty_prompt() {
        let state = create_output_scanner_state();
        let req = ScanOutputRequest {
            prompt: "".to_string(),
            output: "Some output".to_string(),
            scanners: vec![],
            cache_enabled: false,
        };

        let result = scan_output(State(state), Extension(test_repo_span()), Json(req)).await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        match err {
            ApiError::ValidationError(_) => {}
            _ => panic!("Expected ValidationError"),
        }
    }

    #[tokio::test]
    async fn test_scan_output_empty_output() {
        let state = create_output_scanner_state();
        let req = ScanOutputRequest {
            prompt: "Test prompt".to_string(),
            output: "".to_string(),
            scanners: vec![],
            cache_enabled: false,
        };

        let result = scan_output(State(state), Extension(test_repo_span()), Json(req)).await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        match err {
            ApiError::ValidationError(_) => {}
            _ => panic!("Expected ValidationError"),
        }
    }

    #[tokio::test]
    async fn test_scan_output_nonexistent_scanner() {
        let state = create_output_scanner_state();
        let req = ScanOutputRequest {
            prompt: "Test prompt".to_string(),
            output: "Test output".to_string(),
            scanners: vec!["nonexistent".to_string()],
            cache_enabled: false,
        };

        let result = scan_output(State(state), Extension(test_repo_span()), Json(req)).await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        match err {
            ApiError::NotFound(_) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_scan_output_all_scanners() {
        let state = create_output_scanner_state();
        let req = ScanOutputRequest {
            prompt: "Test prompt".to_string(),
            output: "Test output".to_string(),
            scanners: vec![], // Empty = all output scanners
            cache_enabled: false,
        };

        let result = scan_output(State(state), Extension(test_repo_span()), Json(req)).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_scan_output_multiple_scanners() {
        let state = create_output_scanner_state();
        let req = ScanOutputRequest {
            prompt: "Test prompt".to_string(),
            output: "Test output".to_string(),
            scanners: vec!["malicious_urls".to_string(), "sensitive".to_string()],
            cache_enabled: false,
        };

        let result = scan_output(State(state), Extension(test_repo_span()), Json(req)).await;

        assert!(result.is_ok());
    }

    // Tests for scan_batch

    #[tokio::test]
    async fn test_scan_batch_valid_request() {
        let state = create_test_state();
        let req = BatchScanRequest {
            items: vec![
                ScanPromptRequest {
                    prompt: "First prompt".to_string(),
                    scanners: vec!["toxicity".to_string()],
                    cache_enabled: false,
                },
                ScanPromptRequest {
                    prompt: "Second prompt".to_string(),
                    scanners: vec!["secrets".to_string()],
                    cache_enabled: false,
                },
            ],
            max_concurrent: 2,
        };

        let result = scan_batch(State(state), Json(req)).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_scan_batch_empty_items() {
        let state = create_test_state();
        let req = BatchScanRequest {
            items: vec![],
            max_concurrent: 2,
        };

        let result = scan_batch(State(state), Json(req)).await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        match err {
            ApiError::ValidationError(_) => {}
            _ => panic!("Expected ValidationError"),
        }
    }

    #[tokio::test]
    async fn test_scan_batch_invalid_concurrency() {
        let state = create_test_state();
        let req = BatchScanRequest {
            items: vec![ScanPromptRequest {
                prompt: "Test".to_string(),
                scanners: vec![],
                cache_enabled: false,
            }],
            max_concurrent: 0, // Invalid: must be >= 1
        };

        let result = scan_batch(State(state), Json(req)).await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        match err {
            ApiError::ValidationError(_) => {}
            _ => panic!("Expected ValidationError"),
        }
    }

    #[tokio::test]
    async fn test_scan_batch_multiple_items() {
        let state = create_test_state();
        let items = (0..5)
            .map(|i| ScanPromptRequest {
                prompt: format!("Prompt {}", i),
                scanners: vec![],
                cache_enabled: false,
            })
            .collect();

        let req = BatchScanRequest {
            items,
            max_concurrent: 3,
        };

        let result = scan_batch(State(state), Json(req)).await;

        assert!(result.is_ok());
    }
}
