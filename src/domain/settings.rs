//! Company settings domain types.
//!
//! Provides company configuration and policy thresholds.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Policy thresholds for safety rules.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyThresholds {
    /// Maximum amount that can be auto-approved.
    pub max_auto_approve_amount: f64,
    /// Amount threshold requiring HITL review.
    pub hitl_threshold_amount: f64,
    /// Maximum actions per hour per user.
    pub velocity_limit_per_hour: i32,
    /// Maximum actions per day per user.
    pub velocity_limit_per_day: i32,
    /// Whether to block high-risk actions automatically.
    pub block_high_risk_actions: bool,
    /// Whether to require HITL for new beneficiaries.
    pub require_hitl_for_new_beneficiaries: bool,
}

impl Default for PolicyThresholds {
    fn default() -> Self {
        Self {
            max_auto_approve_amount: 100.0,
            hitl_threshold_amount: 1000.0,
            velocity_limit_per_hour: 10,
            velocity_limit_per_day: 50,
            block_high_risk_actions: true,
            require_hitl_for_new_beneficiaries: true,
        }
    }
}

/// Company settings.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CompanySettings {
    /// Company ID.
    pub id: Uuid,
    /// Company name.
    pub name: String,
    /// Logo URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<String>,
    /// Webhook URL for notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    /// Notification email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_email: Option<String>,
    /// Policy thresholds.
    pub policy_thresholds: PolicyThresholds,
}

impl CompanySettings {
    /// Create new settings for a company.
    pub fn new(id: Uuid, name: String) -> Self {
        Self {
            id,
            name,
            logo: None,
            webhook_url: None,
            notification_email: None,
            policy_thresholds: PolicyThresholds::default(),
        }
    }
}

/// Request to update company settings.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateSettingsRequest {
    /// New logo URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<String>,
    /// New webhook URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    /// New notification email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_email: Option<String>,
    /// New policy thresholds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_thresholds: Option<PolicyThresholds>,
}

