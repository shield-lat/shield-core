//! API request and response types.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::{
    AgentAction, EvaluationResult, HitlStatus, HitlTaskDetails, HitlTaskSummary,
};

// ==================== Evaluate Action ====================

/// Request to evaluate an agent action.
#[derive(Debug, Deserialize, ToSchema)]
pub struct EvaluateActionRequest {
    /// The action to evaluate.
    #[serde(flatten)]
    pub action: AgentAction,
}

/// Response from action evaluation.
#[derive(Debug, Serialize, ToSchema)]
pub struct EvaluateActionResponse {
    /// The evaluation result.
    pub evaluation: EvaluationResult,
    /// ID of the HITL task if one was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hitl_task_id: Option<Uuid>,
}

// ==================== HITL Tasks ====================

/// Query parameters for listing HITL tasks.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ListHitlTasksQuery {
    /// Filter by status.
    #[serde(default)]
    pub status: Option<String>,
    /// Maximum number of results.
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

/// Response for listing HITL tasks.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListHitlTasksResponse {
    /// List of task summaries.
    pub tasks: Vec<HitlTaskSummary>,
    /// Total count (for pagination).
    pub total: usize,
    /// Limit used.
    pub limit: i64,
    /// Offset used.
    pub offset: i64,
}

/// Response for getting HITL task details.
#[derive(Debug, Serialize, ToSchema)]
pub struct GetHitlTaskResponse {
    #[serde(flatten)]
    pub details: HitlTaskDetails,
}

/// Request to decide on a HITL task.
#[derive(Debug, Deserialize, ToSchema)]
pub struct HitlDecisionRequest {
    /// Decision: "approve" or "reject".
    pub decision: String,
    /// ID of the reviewer.
    pub reviewer_id: String,
    /// Optional notes.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Response after HITL decision.
#[derive(Debug, Serialize, ToSchema)]
pub struct HitlDecisionResponse {
    /// Updated task ID.
    pub task_id: Uuid,
    /// New status.
    pub status: HitlStatus,
    /// Message.
    pub message: String,
}

// ==================== Health ====================

/// Health check response.
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    /// Service status.
    pub status: String,
    /// Service version.
    pub version: String,
    /// Database connectivity.
    pub database: String,
    /// Timestamp.
    pub timestamp: String,
}

// ==================== Authentication ====================

/// Login request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    /// User email.
    pub email: String,
    /// User password.
    pub password: String,
}

/// Login response.
#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    /// JWT token.
    pub token: String,
    /// User information.
    pub user: UserInfo,
    /// Token expiration in seconds.
    pub expires_in: i64,
}

/// User information.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserInfo {
    /// User ID.
    pub id: String,
    /// User email.
    pub email: String,
    /// User role.
    pub role: String,
}

