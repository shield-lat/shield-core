//! API request and response types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::{
    AgentAction, App, AppStatus, Company, CompanyMember, CompanyRole, EvaluationResult, HitlStatus,
    HitlTaskDetails, HitlTaskSummary, User, UserCompanyMembership, UserRole,
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
    /// User information.
    pub user: UserInfoResponse,
    /// JWT token.
    pub token: String,
    /// Token expiration in seconds.
    pub expires_in: i64,
    /// Companies the user belongs to.
    pub companies: Vec<UserCompanyMembership>,
}

/// User information in API responses.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserInfoResponse {
    /// User ID.
    pub id: Uuid,
    /// User email.
    pub email: String,
    /// User's display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Avatar image URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// User role.
    pub role: UserRole,
    /// Whether email is verified.
    pub email_verified: bool,
    /// When the user was created.
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserInfoResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            name: user.name,
            image: user.image,
            role: user.role,
            email_verified: user.email_verified,
            created_at: user.created_at,
        }
    }
}

/// Legacy user info (for backward compatibility).
#[derive(Debug, Serialize, ToSchema)]
pub struct UserInfo {
    /// User ID.
    pub id: String,
    /// User email.
    pub email: String,
    /// User role.
    pub role: String,
}

// ==================== OAuth ====================

/// OAuth sync request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct OAuthSyncRequest {
    /// OAuth provider (google, github).
    pub provider: String,
    /// Provider's user ID.
    pub provider_id: String,
    /// User's email address.
    pub email: String,
    /// User's display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Avatar image URL.
    #[serde(default)]
    pub image: Option<String>,
    /// Whether the email is verified by the provider.
    #[serde(default)]
    pub email_verified: bool,
}

/// OAuth sync response.
#[derive(Debug, Serialize, ToSchema)]
pub struct OAuthSyncResponse {
    /// User information.
    pub user: UserInfoResponse,
    /// JWT token for Shield Core API.
    pub token: String,
    /// Token expiration in seconds.
    pub expires_in: i64,
    /// Whether this is a newly created user.
    pub is_new_user: bool,
    /// Companies the user belongs to.
    pub companies: Vec<UserCompanyMembership>,
}

/// Token refresh response.
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenRefreshResponse {
    /// New JWT token.
    pub token: String,
    /// Token expiration in seconds.
    pub expires_in: i64,
}

/// Current user response (for /auth/me).
#[derive(Debug, Serialize, ToSchema)]
pub struct CurrentUserResponse {
    /// User information.
    pub user: UserInfoResponse,
    /// Companies the user belongs to.
    pub companies: Vec<UserCompanyMembership>,
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

// ==================== Metrics ====================

use crate::domain::{
    AttackEvent, CompanySettings, MetricsOverview, PolicyThresholds, RiskDistribution,
    TimeSeriesData,
};

/// Query parameters for metrics.
#[derive(Debug, Deserialize, ToSchema)]
pub struct MetricsQuery {
    /// Time range: 24h, 7d, 30d, or 90d.
    #[serde(default = "default_time_range")]
    pub time_range: String,
    /// Optional app filter.
    #[serde(default)]
    pub app_id: Option<Uuid>,
}

fn default_time_range() -> String {
    "7d".to_string()
}

/// Response for metrics overview.
#[derive(Debug, Serialize, ToSchema)]
pub struct MetricsOverviewResponse {
    #[serde(flatten)]
    pub metrics: MetricsOverview,
}

/// Response for time series data.
#[derive(Debug, Serialize, ToSchema)]
pub struct TimeSeriesResponse {
    #[serde(flatten)]
    pub data: TimeSeriesData,
}

/// Response for risk distribution.
#[derive(Debug, Serialize, ToSchema)]
pub struct RiskDistributionResponse {
    #[serde(flatten)]
    pub data: RiskDistribution,
}

// ==================== Actions List ====================

/// Query parameters for listing actions.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ListActionsQuery {
    /// Filter by app.
    #[serde(default)]
    pub app_id: Option<Uuid>,
    /// Filter by decision.
    #[serde(default)]
    pub decision: Option<String>,
    /// Filter by risk tier.
    #[serde(default)]
    pub risk_tier: Option<String>,
    /// Filter by user ID.
    #[serde(default)]
    pub user_id: Option<String>,
    /// Search string.
    #[serde(default)]
    pub search: Option<String>,
    /// Time range filter.
    #[serde(default)]
    pub time_range: Option<String>,
    /// Maximum results.
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Pagination offset.
    #[serde(default)]
    pub offset: i64,
}

/// Action item in list response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ActionListItem {
    pub id: Uuid,
    pub trace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    pub user_id: String,
    pub action_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    pub original_intent: String,
    pub decision: String,
    pub risk_tier: String,
    pub reasons: Vec<String>,
    pub created_at: String,
}

/// Response for listing actions.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListActionsResponse {
    pub actions: Vec<ActionListItem>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

// ==================== Attacks ====================

/// Query parameters for listing attacks.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ListAttacksQuery {
    /// Filter by app.
    #[serde(default)]
    pub app_id: Option<Uuid>,
    /// Filter by attack type.
    #[serde(default)]
    pub attack_type: Option<String>,
    /// Filter by severity.
    #[serde(default)]
    pub severity: Option<String>,
    /// Filter by outcome.
    #[serde(default)]
    pub outcome: Option<String>,
    /// Maximum results.
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Pagination offset.
    #[serde(default)]
    pub offset: i64,
}

/// Response for listing attacks.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListAttacksResponse {
    pub attacks: Vec<AttackEvent>,
    pub total: i64,
}

// ==================== Settings ====================

/// Response for company settings.
#[derive(Debug, Serialize, ToSchema)]
pub struct SettingsResponse {
    #[serde(flatten)]
    pub settings: CompanySettings,
}

/// Request to update settings.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSettingsRequest {
    /// New logo URL.
    #[serde(default)]
    pub logo: Option<String>,
    /// New webhook URL.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// New notification email.
    #[serde(default)]
    pub notification_email: Option<String>,
    /// New policy thresholds.
    #[serde(default)]
    pub policy_thresholds: Option<PolicyThresholds>,
}

