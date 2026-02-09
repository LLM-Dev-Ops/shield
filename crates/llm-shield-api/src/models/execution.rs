//! Execution span types for the Agentics Foundational Execution Unit.
//!
//! This module implements the span hierarchy for LLM-Shield's participation
//! in the Agentics ExecutionGraph:
//!
//! ```text
//! Core (caller)
//!   └─ Repo (llm-shield)
//!       └─ Agent (one or more scanners)
//! ```
//!
//! ## Invariants
//! - Every external invocation MUST provide `execution_id` and `parent_span_id`
//! - A repo-level span MUST be created on entry
//! - An agent-level span MUST exist for every scanner that executes
//! - Execution is INVALID if no agent-level spans exist
//! - All spans are append-only and causally ordered via `parent_span_id`

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Span type discriminator within the Agentics hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SpanType {
    /// Root span owned by the Agentics Core.
    Core,
    /// Repository-level span (this repo).
    Repo,
    /// Agent/scanner-level span.
    Agent,
}

/// Status of span execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SpanStatus {
    Running,
    Completed,
    Error,
}

/// An artifact or evidence attached to a span.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpanArtifact {
    /// Stable reference identifier.
    pub artifact_id: String,
    /// Classification of the artifact.
    pub artifact_type: String,
    /// Machine-verifiable data payload.
    pub data: serde_json::Value,
    /// ISO 8601 timestamp of when the artifact was produced.
    pub timestamp: String,
}

/// A single execution span in the hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionSpan {
    /// Unique identifier for this span.
    pub span_id: String,
    /// Position in the hierarchy.
    pub span_type: SpanType,
    /// ID of the parent span (establishes causal ordering).
    pub parent_span_id: String,
    /// ID of the execution tree this span belongs to.
    pub execution_id: String,
    /// Human-readable name.
    pub name: String,
    /// Type-specific attributes (repo_name, agent_name, etc.).
    pub attributes: HashMap<String, String>,
    /// ISO 8601 start timestamp.
    pub start_time: String,
    /// ISO 8601 end timestamp (None if still running).
    pub end_time: Option<String>,
    /// Current status.
    pub status: SpanStatus,
    /// Duration in milliseconds (None if still running).
    pub duration_ms: Option<u64>,
    /// Artifacts and evidence attached to this span.
    pub artifacts: Vec<SpanArtifact>,
    /// Child spans (agent spans nested under repo span).
    pub children: Vec<ExecutionSpan>,
}

/// The complete execution output envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionOutput {
    /// Execution tree identifier.
    pub execution_id: String,
    /// Root repo-level span with nested agent spans.
    pub repo_span: ExecutionSpan,
}

impl ExecutionSpan {
    /// Create a new repo-level span.
    pub fn new_repo(execution_id: &str, parent_span_id: &str) -> Self {
        let mut attributes = HashMap::new();
        attributes.insert("repo_name".to_string(), "llm-shield".to_string());

        Self {
            span_id: Uuid::new_v4().to_string(),
            span_type: SpanType::Repo,
            parent_span_id: parent_span_id.to_string(),
            execution_id: execution_id.to_string(),
            name: "llm-shield".to_string(),
            attributes,
            start_time: Utc::now().to_rfc3339(),
            end_time: None,
            status: SpanStatus::Running,
            duration_ms: None,
            artifacts: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Create a new agent-level span as a child of a repo span.
    pub fn new_agent(repo_span: &ExecutionSpan, agent_name: &str) -> Self {
        let mut attributes = HashMap::new();
        attributes.insert("agent_name".to_string(), agent_name.to_string());
        attributes.insert("repo_name".to_string(), "llm-shield".to_string());

        Self {
            span_id: Uuid::new_v4().to_string(),
            span_type: SpanType::Agent,
            parent_span_id: repo_span.span_id.clone(),
            execution_id: repo_span.execution_id.clone(),
            name: agent_name.to_string(),
            attributes,
            start_time: Utc::now().to_rfc3339(),
            end_time: None,
            status: SpanStatus::Running,
            duration_ms: None,
            artifacts: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Attach a machine-verifiable artifact to this span.
    pub fn attach_artifact(&mut self, artifact_type: &str, data: serde_json::Value) {
        self.artifacts.push(SpanArtifact {
            artifact_id: Uuid::new_v4().to_string(),
            artifact_type: artifact_type.to_string(),
            data,
            timestamp: Utc::now().to_rfc3339(),
        });
    }

    /// Mark this span as successfully completed.
    pub fn complete(&mut self) {
        let now = Utc::now();
        self.end_time = Some(now.to_rfc3339());
        self.status = SpanStatus::Completed;

        if let Ok(start) = chrono::DateTime::parse_from_rfc3339(&self.start_time) {
            self.duration_ms = Some((now - start.with_timezone(&Utc)).num_milliseconds() as u64);
        }
    }

    /// Mark this span as failed with an explicit reason.
    pub fn fail(&mut self, error: &str) {
        let now = Utc::now();
        self.end_time = Some(now.to_rfc3339());
        self.status = SpanStatus::Error;

        if let Ok(start) = chrono::DateTime::parse_from_rfc3339(&self.start_time) {
            self.duration_ms = Some((now - start.with_timezone(&Utc)).num_milliseconds() as u64);
        }

        self.artifacts.push(SpanArtifact {
            artifact_id: Uuid::new_v4().to_string(),
            artifact_type: "error".to_string(),
            data: serde_json::json!({ "error_reason": error }),
            timestamp: now.to_rfc3339(),
        });
    }

    /// Finalize the repo span and produce the execution output.
    ///
    /// Returns `None` if invariants are violated (no agent spans).
    pub fn finalize(mut self) -> Result<ExecutionOutput, String> {
        if self.children.is_empty() {
            return Err(
                "Execution invariant violated: no agent-level spans were emitted. \
                 This repository MUST NOT return a successful result without agent spans."
                    .to_string(),
            );
        }

        if self.status == SpanStatus::Running {
            self.complete();
        }

        Ok(ExecutionOutput {
            execution_id: self.execution_id.clone(),
            repo_span: self,
        })
    }
}

/// Enveloped scan response that includes execution span data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopedScanResponse {
    /// The scan result.
    pub result: super::response::ScanResponse,
    /// Execution span tree from the Agentics framework.
    pub execution: ExecutionOutput,
}

/// Enveloped batch scan response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopedBatchScanResponse {
    /// The batch scan result.
    pub result: super::response::BatchScanResponse,
    /// Execution span tree from the Agentics framework.
    pub execution: ExecutionOutput,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_repo_span() {
        let span = ExecutionSpan::new_repo("exec-123", "parent-456");
        assert_eq!(span.span_type, SpanType::Repo);
        assert_eq!(span.execution_id, "exec-123");
        assert_eq!(span.parent_span_id, "parent-456");
        assert_eq!(span.name, "llm-shield");
        assert_eq!(span.status, SpanStatus::Running);
        assert!(span.children.is_empty());
    }

    #[test]
    fn test_new_agent_span() {
        let repo = ExecutionSpan::new_repo("exec-123", "parent-456");
        let agent = ExecutionSpan::new_agent(&repo, "toxicity");
        assert_eq!(agent.span_type, SpanType::Agent);
        assert_eq!(agent.parent_span_id, repo.span_id);
        assert_eq!(agent.execution_id, "exec-123");
        assert_eq!(agent.name, "toxicity");
    }

    #[test]
    fn test_complete_span() {
        let mut span = ExecutionSpan::new_repo("exec-123", "parent-456");
        span.complete();
        assert_eq!(span.status, SpanStatus::Completed);
        assert!(span.end_time.is_some());
        assert!(span.duration_ms.is_some());
    }

    #[test]
    fn test_fail_span() {
        let mut span = ExecutionSpan::new_repo("exec-123", "parent-456");
        span.fail("something went wrong");
        assert_eq!(span.status, SpanStatus::Error);
        assert!(span.end_time.is_some());
        assert_eq!(span.artifacts.len(), 1);
        assert_eq!(span.artifacts[0].artifact_type, "error");
    }

    #[test]
    fn test_attach_artifact() {
        let mut span = ExecutionSpan::new_repo("exec-123", "parent-456");
        span.attach_artifact("detection_signal", serde_json::json!({"risk": 0.5}));
        assert_eq!(span.artifacts.len(), 1);
        assert_eq!(span.artifacts[0].artifact_type, "detection_signal");
    }

    #[test]
    fn test_finalize_without_children_fails() {
        let span = ExecutionSpan::new_repo("exec-123", "parent-456");
        let result = span.finalize();
        assert!(result.is_err());
    }

    #[test]
    fn test_finalize_with_children_succeeds() {
        let mut repo = ExecutionSpan::new_repo("exec-123", "parent-456");
        let mut agent = ExecutionSpan::new_agent(&repo, "toxicity");
        agent.complete();
        repo.children.push(agent);

        let output = repo.finalize().unwrap();
        assert_eq!(output.execution_id, "exec-123");
        assert_eq!(output.repo_span.status, SpanStatus::Completed);
        assert_eq!(output.repo_span.children.len(), 1);
    }

    #[test]
    fn test_json_serialization() {
        let mut repo = ExecutionSpan::new_repo("exec-123", "parent-456");
        let mut agent = ExecutionSpan::new_agent(&repo, "toxicity");
        agent.attach_artifact("detection_signal", serde_json::json!({"risk": 0.5}));
        agent.complete();
        repo.children.push(agent);

        let output = repo.finalize().unwrap();
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"executionId\":\"exec-123\""));
        assert!(json.contains("\"spanType\":\"repo\""));
        assert!(json.contains("\"spanType\":\"agent\""));
    }
}
