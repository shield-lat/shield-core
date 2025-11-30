//! Evaluation-related domain types.
//!
//! Represents Shield's decision for a proposed action.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Risk tier classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    /// Low risk - safe to auto-approve.
    Low,
    /// Medium risk - some signals present.
    Medium,
    /// High risk - requires human review.
    High,
    /// Critical risk - should be blocked.
    Critical,
}

impl std::fmt::Display for RiskTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskTier::Low => write!(f, "low"),
            RiskTier::Medium => write!(f, "medium"),
            RiskTier::High => write!(f, "high"),
            RiskTier::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for RiskTier {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(RiskTier::Low),
            "medium" => Ok(RiskTier::Medium),
            "high" => Ok(RiskTier::High),
            "critical" => Ok(RiskTier::Critical),
            _ => Err(format!("Unknown risk tier: {}", s)),
        }
    }
}

/// Decision status for an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DecisionStatus {
    /// Action is allowed to proceed.
    Allow,
    /// Action requires human-in-the-loop review.
    RequireHitl,
    /// Action is blocked.
    Block,
}

impl std::fmt::Display for DecisionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecisionStatus::Allow => write!(f, "allow"),
            DecisionStatus::RequireHitl => write!(f, "require_hitl"),
            DecisionStatus::Block => write!(f, "block"),
        }
    }
}

/// Result of evaluating an agent action.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EvaluationResult {
    /// Unique identifier for this evaluation.
    pub id: Uuid,

    /// ID of the agent action that was evaluated.
    pub agent_action_id: Uuid,

    /// Final decision.
    pub decision: DecisionStatus,

    /// Assessed risk tier.
    pub risk_tier: RiskTier,

    /// Human-readable reasons for the decision.
    pub reasons: Vec<String>,

    /// IDs/keys of rules that triggered.
    pub rule_hits: Vec<String>,

    /// Names of neural detectors that fired (stub for MVP).
    pub neural_signals: Vec<String>,

    /// When this evaluation was created.
    pub created_at: DateTime<Utc>,
}

impl EvaluationResult {
    /// Create a new EvaluationResult.
    pub fn new(
        agent_action_id: Uuid,
        decision: DecisionStatus,
        risk_tier: RiskTier,
        reasons: Vec<String>,
        rule_hits: Vec<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            agent_action_id,
            decision,
            risk_tier,
            reasons,
            rule_hits,
            neural_signals: Vec::new(),
            created_at: Utc::now(),
        }
    }

    /// Create an Allow result with Low risk.
    pub fn allow(agent_action_id: Uuid) -> Self {
        Self::new(
            agent_action_id,
            DecisionStatus::Allow,
            RiskTier::Low,
            vec!["Action passed all safety checks".to_string()],
            Vec::new(),
        )
    }

    /// Create a Block result with Critical risk.
    pub fn block(agent_action_id: Uuid, reasons: Vec<String>, rule_hits: Vec<String>) -> Self {
        Self::new(
            agent_action_id,
            DecisionStatus::Block,
            RiskTier::Critical,
            reasons,
            rule_hits,
        )
    }

    /// Create a RequireHitl result with High risk.
    pub fn require_hitl(
        agent_action_id: Uuid,
        reasons: Vec<String>,
        rule_hits: Vec<String>,
    ) -> Self {
        Self::new(
            agent_action_id,
            DecisionStatus::RequireHitl,
            RiskTier::High,
            reasons,
            rule_hits,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_status_serialization() {
        let status = DecisionStatus::RequireHitl;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"require_hitl\"");
    }

    #[test]
    fn test_risk_tier_ordering() {
        // Just verify they're distinct
        assert_ne!(RiskTier::Low, RiskTier::High);
        assert_ne!(RiskTier::Medium, RiskTier::Critical);
    }
}
