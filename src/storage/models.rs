//! Database models for Shield Core.
//!
//! These are the row types returned by SQLx queries.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::domain::{
    AgentAction, App, AppStatus, AttackEvent, AttackOutcome, AttackType, Company, CompanyMember,
    CompanyRole, CompanySettings, EvaluationResult, HitlTask, HitlTaskSummary, OAuthAccount,
    OAuthProvider, PolicyThresholds, RiskTier, User, UserRole,
};

/// Database row for agent_actions table.
#[derive(Debug, Clone, FromRow)]
pub struct AgentActionRow {
    pub id: String,
    pub trace_id: String,
    pub app_id: Option<String>,
    pub user_id: String,
    pub channel: String,
    pub model_name: String,
    pub original_intent: String,
    pub action_type: String,
    pub payload: String,
    pub cot_trace: Option<String>,
    pub metadata: Option<String>,
    pub created_at: String,
}

impl TryFrom<AgentActionRow> for AgentAction {
    type Error = crate::error::ShieldError;

    fn try_from(row: AgentActionRow) -> Result<Self, Self::Error> {
        Ok(AgentAction {
            id: Uuid::parse_str(&row.id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            trace_id: row.trace_id,
            app_id: row
                .app_id
                .map(|s| Uuid::parse_str(&s))
                .transpose()
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            user_id: row.user_id,
            channel: row.channel,
            model_name: row.model_name,
            original_intent: row.original_intent,
            action_type: serde_json::from_str(&format!("\"{}\"", row.action_type))?,
            payload: serde_json::from_str(&row.payload)?,
            cot_trace: row.cot_trace,
            metadata: row.metadata.map(|m| serde_json::from_str(&m)).transpose()?,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?
                .with_timezone(&Utc),
        })
    }
}

/// Database row for evaluations table.
#[derive(Debug, Clone, FromRow)]
pub struct EvaluationRow {
    pub id: String,
    pub agent_action_id: String,
    pub decision: String,
    pub risk_tier: String,
    pub reasons: String,
    pub rule_hits: String,
    pub neural_signals: String,
    pub created_at: String,
}

impl TryFrom<EvaluationRow> for EvaluationResult {
    type Error = crate::error::ShieldError;

    fn try_from(row: EvaluationRow) -> Result<Self, Self::Error> {
        Ok(EvaluationResult {
            id: Uuid::parse_str(&row.id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            agent_action_id: Uuid::parse_str(&row.agent_action_id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            decision: serde_json::from_str(&format!("\"{}\"", row.decision))?,
            risk_tier: serde_json::from_str(&format!("\"{}\"", row.risk_tier))?,
            reasons: serde_json::from_str(&row.reasons)?,
            rule_hits: serde_json::from_str(&row.rule_hits)?,
            neural_signals: serde_json::from_str(&row.neural_signals)?,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?
                .with_timezone(&Utc),
        })
    }
}

/// Database row for hitl_tasks table.
#[derive(Debug, Clone, FromRow)]
pub struct HitlTaskRow {
    pub id: String,
    pub agent_action_id: String,
    pub evaluation_id: String,
    pub status: String,
    pub reviewer_id: Option<String>,
    pub reviewed_at: Option<String>,
    pub review_notes: Option<String>,
    pub created_at: String,
}

impl TryFrom<HitlTaskRow> for HitlTask {
    type Error = crate::error::ShieldError;

    fn try_from(row: HitlTaskRow) -> Result<Self, Self::Error> {
        Ok(HitlTask {
            id: Uuid::parse_str(&row.id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            agent_action_id: Uuid::parse_str(&row.agent_action_id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            evaluation_id: Uuid::parse_str(&row.evaluation_id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            status: row
                .status
                .parse()
                .map_err(|e: String| crate::error::ShieldError::Internal(e))?,
            reviewer_id: row.reviewer_id,
            reviewed_at: row
                .reviewed_at
                .map(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .map(|dt| dt.with_timezone(&Utc))
                        .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))
                })
                .transpose()?,
            review_notes: row.review_notes,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?
                .with_timezone(&Utc),
        })
    }
}

/// Row for HITL task list query (joined data).
#[derive(Debug, Clone, FromRow)]
pub struct HitlTaskSummaryRow {
    pub id: String,
    pub user_id: String,
    pub action_type: String,
    pub amount: Option<f64>,
    pub risk_tier: String,
    pub status: String,
    pub created_at: String,
}

impl TryFrom<HitlTaskSummaryRow> for HitlTaskSummary {
    type Error = crate::error::ShieldError;

    fn try_from(row: HitlTaskSummaryRow) -> Result<Self, Self::Error> {
        Ok(HitlTaskSummary {
            id: Uuid::parse_str(&row.id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            user_id: row.user_id,
            action_type: row.action_type,
            amount: row.amount,
            risk_tier: row.risk_tier,
            status: row
                .status
                .parse()
                .map_err(|e: String| crate::error::ShieldError::Internal(e))?,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?
                .with_timezone(&Utc),
        })
    }
}

// ==================== Company Models ====================

/// Database row for companies table.
#[derive(Debug, Clone, FromRow)]
pub struct CompanyRow {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<CompanyRow> for Company {
    type Error = crate::error::ShieldError;

    fn try_from(row: CompanyRow) -> Result<Self, Self::Error> {
        Ok(Company {
            id: Uuid::parse_str(&row.id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            name: row.name,
            slug: row.slug,
            description: row.description,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?
                .with_timezone(&Utc),
        })
    }
}

/// Database row for company_members table.
#[derive(Debug, Clone, FromRow)]
pub struct CompanyMemberRow {
    pub id: String,
    pub company_id: String,
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub created_at: String,
}

impl TryFrom<CompanyMemberRow> for CompanyMember {
    type Error = crate::error::ShieldError;

    fn try_from(row: CompanyMemberRow) -> Result<Self, Self::Error> {
        Ok(CompanyMember {
            id: Uuid::parse_str(&row.id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            company_id: Uuid::parse_str(&row.company_id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            user_id: row.user_id,
            email: row.email,
            role: row
                .role
                .parse::<CompanyRole>()
                .map_err(crate::error::ShieldError::Internal)?,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?
                .with_timezone(&Utc),
        })
    }
}

/// Database row for apps table.
#[derive(Debug, Clone, FromRow)]
pub struct AppRow {
    pub id: String,
    pub company_id: String,
    pub name: String,
    pub description: Option<String>,
    pub api_key_hash: String,
    pub api_key_prefix: String,
    pub status: String,
    pub rate_limit: i64,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: Option<String>,
}

impl TryFrom<AppRow> for App {
    type Error = crate::error::ShieldError;

    fn try_from(row: AppRow) -> Result<Self, Self::Error> {
        Ok(App {
            id: Uuid::parse_str(&row.id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            company_id: Uuid::parse_str(&row.company_id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            name: row.name,
            description: row.description,
            api_key: None, // Never return the actual key
            api_key_prefix: row.api_key_prefix,
            status: row
                .status
                .parse::<AppStatus>()
                .map_err(crate::error::ShieldError::Internal)?,
            rate_limit: row.rate_limit as u32,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?
                .with_timezone(&Utc),
            last_used_at: row
                .last_used_at
                .map(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .map(|dt| dt.with_timezone(&Utc))
                        .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))
                })
                .transpose()?,
        })
    }
}

// ==================== Attack Events ====================

/// Database row for attack_events table.
#[derive(Debug, Clone, FromRow)]
pub struct AttackEventRow {
    pub id: String,
    pub company_id: String,
    pub app_id: Option<String>,
    pub agent_action_id: String,
    pub attack_type: String,
    pub severity: String,
    pub blocked: i32,
    pub outcome: String,
    pub user_id: String,
    pub description: String,
    pub details: Option<String>,
    pub created_at: String,
}

impl TryFrom<AttackEventRow> for AttackEvent {
    type Error = crate::error::ShieldError;

    fn try_from(row: AttackEventRow) -> Result<Self, Self::Error> {
        Ok(AttackEvent {
            id: Uuid::parse_str(&row.id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            company_id: Uuid::parse_str(&row.company_id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            app_id: row
                .app_id
                .map(|s| Uuid::parse_str(&s))
                .transpose()
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            app_name: None,
            agent_action_id: Uuid::parse_str(&row.agent_action_id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            attack_type: row
                .attack_type
                .parse::<AttackType>()
                .map_err(crate::error::ShieldError::Internal)?,
            severity: row
                .severity
                .parse::<RiskTier>()
                .map_err(crate::error::ShieldError::Internal)?,
            blocked: row.blocked != 0,
            outcome: row
                .outcome
                .parse::<AttackOutcome>()
                .map_err(crate::error::ShieldError::Internal)?,
            user_id: row.user_id,
            description: row.description,
            details: row.details,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?
                .with_timezone(&Utc),
        })
    }
}

// ==================== Company Settings ====================

/// Database row for company_settings table.
#[derive(Debug, Clone, FromRow)]
pub struct CompanySettingsRow {
    pub company_id: String,
    pub logo: Option<String>,
    pub webhook_url: Option<String>,
    pub notification_email: Option<String>,
    pub max_auto_approve_amount: f64,
    pub hitl_threshold_amount: f64,
    pub velocity_limit_per_hour: i32,
    pub velocity_limit_per_day: i32,
    pub block_high_risk_actions: i32,
    pub require_hitl_for_new_beneficiaries: i32,
}

impl CompanySettingsRow {
    /// Convert to CompanySettings with company info.
    pub fn into_settings(
        self,
        company_id: Uuid,
        company_name: String,
    ) -> Result<CompanySettings, crate::error::ShieldError> {
        Ok(CompanySettings {
            id: company_id,
            name: company_name,
            logo: self.logo,
            webhook_url: self.webhook_url,
            notification_email: self.notification_email,
            policy_thresholds: PolicyThresholds {
                max_auto_approve_amount: self.max_auto_approve_amount,
                hitl_threshold_amount: self.hitl_threshold_amount,
                velocity_limit_per_hour: self.velocity_limit_per_hour,
                velocity_limit_per_day: self.velocity_limit_per_day,
                block_high_risk_actions: self.block_high_risk_actions != 0,
                require_hitl_for_new_beneficiaries: self.require_hitl_for_new_beneficiaries != 0,
            },
        })
    }
}

// ==================== Action List View ====================

/// Row for action list query with evaluation data.
#[derive(Debug, Clone, FromRow)]
pub struct ActionListRow {
    pub id: String,
    pub trace_id: String,
    pub app_id: Option<String>,
    pub user_id: String,
    pub action_type: String,
    pub original_intent: String,
    pub amount: Option<f64>,
    pub currency: Option<String>,
    pub decision: String,
    pub risk_tier: String,
    pub reasons: String,
    pub created_at: String,
}

// ==================== Users ====================

/// Database row for users table.
#[derive(Debug, Clone, FromRow)]
pub struct UserRow {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub image: Option<String>,
    pub role: String,
    pub email_verified: i32,
    pub password_hash: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<UserRow> for User {
    type Error = crate::error::ShieldError;

    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        Ok(User {
            id: Uuid::parse_str(&row.id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            email: row.email,
            name: row.name,
            image: row.image,
            role: row
                .role
                .parse::<UserRole>()
                .map_err(crate::error::ShieldError::Internal)?,
            email_verified: row.email_verified != 0,
            password_hash: row.password_hash,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?
                .with_timezone(&Utc),
        })
    }
}

/// Database row for oauth_accounts table.
#[derive(Debug, Clone, FromRow)]
pub struct OAuthAccountRow {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    pub provider_account_id: String,
    pub created_at: String,
}

impl TryFrom<OAuthAccountRow> for OAuthAccount {
    type Error = crate::error::ShieldError;

    fn try_from(row: OAuthAccountRow) -> Result<Self, Self::Error> {
        Ok(OAuthAccount {
            id: Uuid::parse_str(&row.id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            user_id: Uuid::parse_str(&row.user_id)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?,
            provider: row
                .provider
                .parse::<OAuthProvider>()
                .map_err(crate::error::ShieldError::Internal)?,
            provider_account_id: row.provider_account_id,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| crate::error::ShieldError::Internal(e.to_string()))?
                .with_timezone(&Utc),
        })
    }
}
