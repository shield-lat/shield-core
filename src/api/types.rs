//! API request and response types.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::{
    AgentAction, App, AppStatus, Company, CompanyMember, CompanyRole,
    EvaluationResult, HitlStatus, HitlTaskDetails, HitlTaskSummary,
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

// ==================== Companies ====================

/// Request to create a company.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCompanyRequest {
    /// Company name.
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
}

/// Request to update a company.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCompanyRequest {
    /// New company name.
    #[serde(default)]
    pub name: Option<String>,
    /// New description.
    #[serde(default)]
    pub description: Option<String>,
}

/// Response for company operations.
#[derive(Debug, Serialize, ToSchema)]
pub struct CompanyResponse {
    /// The company.
    pub company: Company,
}

/// Response for listing companies.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListCompaniesResponse {
    /// List of companies.
    pub companies: Vec<Company>,
}

// ==================== Company Members ====================

/// Request to add a member to a company.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddMemberRequest {
    /// User ID to add.
    pub user_id: String,
    /// User email.
    pub email: String,
    /// Role to assign.
    pub role: CompanyRole,
}

/// Request to update a member's role.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateMemberRoleRequest {
    /// New role.
    pub role: CompanyRole,
}

/// Response for member operations.
#[derive(Debug, Serialize, ToSchema)]
pub struct MemberResponse {
    /// The member.
    pub member: CompanyMember,
}

/// Response for listing members.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListMembersResponse {
    /// List of members.
    pub members: Vec<CompanyMember>,
}

// ==================== Apps ====================

/// Request to create an app.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAppRequest {
    /// App name.
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
    /// Rate limit (requests per minute).
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,
}

fn default_rate_limit() -> u32 {
    100
}

/// Request to update an app.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAppRequest {
    /// New app name.
    #[serde(default)]
    pub name: Option<String>,
    /// New description.
    #[serde(default)]
    pub description: Option<String>,
    /// New status.
    #[serde(default)]
    pub status: Option<AppStatus>,
    /// New rate limit.
    #[serde(default)]
    pub rate_limit: Option<u32>,
}

/// Response for app creation (includes API key).
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateAppResponse {
    /// The app.
    pub app: App,
    /// The API key (only shown once).
    pub api_key: String,
    /// Warning about the API key.
    pub warning: String,
}

/// Response for app operations.
#[derive(Debug, Serialize, ToSchema)]
pub struct AppResponse {
    /// The app.
    pub app: App,
}

/// Response for listing apps.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListAppsResponse {
    /// List of apps.
    pub apps: Vec<App>,
}

