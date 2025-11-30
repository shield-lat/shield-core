//! Attack event domain types.
//!
//! Represents detected security threats and attack attempts.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::RiskTier;

/// Types of attacks that Shield can detect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttackType {
    /// Prompt injection attempt.
    PromptInjection,
    /// Jailbreak attempt.
    JailbreakAttempt,
    /// Data exfiltration attempt.
    DataExfiltration,
    /// Privilege escalation attempt.
    PrivilegeEscalation,
    /// Action misalignment with user intent.
    Misalignment,
    /// Social engineering attempt.
    SocialEngineering,
    /// Unknown attack type.
    Unknown,
}

impl std::fmt::Display for AttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackType::PromptInjection => write!(f, "prompt_injection"),
            AttackType::JailbreakAttempt => write!(f, "jailbreak_attempt"),
            AttackType::DataExfiltration => write!(f, "data_exfiltration"),
            AttackType::PrivilegeEscalation => write!(f, "privilege_escalation"),
            AttackType::Misalignment => write!(f, "misalignment"),
            AttackType::SocialEngineering => write!(f, "social_engineering"),
            AttackType::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::str::FromStr for AttackType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "prompt_injection" => Ok(AttackType::PromptInjection),
            "jailbreak_attempt" => Ok(AttackType::JailbreakAttempt),
            "data_exfiltration" => Ok(AttackType::DataExfiltration),
            "privilege_escalation" => Ok(AttackType::PrivilegeEscalation),
            "misalignment" => Ok(AttackType::Misalignment),
            "social_engineering" => Ok(AttackType::SocialEngineering),
            "unknown" => Ok(AttackType::Unknown),
            _ => Err(format!("Unknown attack type: {}", s)),
        }
    }
}

/// Outcome of an attack attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttackOutcome {
    /// Attack was blocked.
    Blocked,
    /// Attack was escalated to HITL.
    Escalated,
    /// Attack was allowed (not detected in time).
    Allowed,
}

impl std::fmt::Display for AttackOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackOutcome::Blocked => write!(f, "blocked"),
            AttackOutcome::Escalated => write!(f, "escalated"),
            AttackOutcome::Allowed => write!(f, "allowed"),
        }
    }
}

impl std::str::FromStr for AttackOutcome {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "blocked" => Ok(AttackOutcome::Blocked),
            "escalated" => Ok(AttackOutcome::Escalated),
            "allowed" => Ok(AttackOutcome::Allowed),
            _ => Err(format!("Unknown attack outcome: {}", s)),
        }
    }
}

/// A detected attack event.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AttackEvent {
    /// Unique identifier.
    pub id: Uuid,
    /// Company this attack belongs to.
    pub company_id: Uuid,
    /// App that was attacked (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<Uuid>,
    /// App name (denormalized for convenience).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    /// Related agent action ID.
    pub agent_action_id: Uuid,
    /// Type of attack detected.
    pub attack_type: AttackType,
    /// Severity of the attack.
    pub severity: RiskTier,
    /// Whether the attack was blocked.
    pub blocked: bool,
    /// Outcome of the attack.
    pub outcome: AttackOutcome,
    /// User ID that was targeted.
    pub user_id: String,
    /// Brief description of the attack.
    pub description: String,
    /// Detailed information about the attack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// When the attack was detected.
    pub created_at: DateTime<Utc>,
}

impl AttackEvent {
    /// Create a new attack event.
    pub fn new(
        company_id: Uuid,
        app_id: Option<Uuid>,
        agent_action_id: Uuid,
        attack_type: AttackType,
        severity: RiskTier,
        outcome: AttackOutcome,
        user_id: String,
        description: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            company_id,
            app_id,
            app_name: None,
            agent_action_id,
            attack_type,
            severity,
            blocked: matches!(outcome, AttackOutcome::Blocked),
            outcome,
            user_id,
            description,
            details: None,
            created_at: Utc::now(),
        }
    }

    /// Set the app name.
    pub fn with_app_name(mut self, name: String) -> Self {
        self.app_name = Some(name);
        self
    }

    /// Set additional details.
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }
}

