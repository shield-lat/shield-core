//! Human-in-the-loop (HITL) task domain types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{AgentAction, EvaluationResult};

/// Status of a HITL task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HitlStatus {
    /// Awaiting human review.
    Pending,
    /// Approved by human reviewer.
    Approved,
    /// Rejected by human reviewer.
    Rejected,
}

impl std::fmt::Display for HitlStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HitlStatus::Pending => write!(f, "pending"),
            HitlStatus::Approved => write!(f, "approved"),
            HitlStatus::Rejected => write!(f, "rejected"),
        }
    }
}

impl std::str::FromStr for HitlStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(HitlStatus::Pending),
            "approved" => Ok(HitlStatus::Approved),
            "rejected" => Ok(HitlStatus::Rejected),
            _ => Err(format!("Invalid HITL status: {}", s)),
        }
    }
}

/// A task requiring human review.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HitlTask {
    /// Unique identifier for this task.
    pub id: Uuid,

    /// ID of the agent action being reviewed.
    pub agent_action_id: Uuid,

    /// ID of the evaluation that triggered HITL.
    pub evaluation_id: Uuid,

    /// Current status of the task.
    pub status: HitlStatus,

    /// ID of the human reviewer (if reviewed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_id: Option<String>,

    /// When the task was reviewed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<DateTime<Utc>>,

    /// Notes from the reviewer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_notes: Option<String>,

    /// When this task was created.
    pub created_at: DateTime<Utc>,
}

impl HitlTask {
    /// Create a new pending HITL task.
    pub fn new(agent_action_id: Uuid, evaluation_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            agent_action_id,
            evaluation_id,
            status: HitlStatus::Pending,
            reviewer_id: None,
            reviewed_at: None,
            review_notes: None,
            created_at: Utc::now(),
        }
    }

    /// Approve the task.
    pub fn approve(&mut self, reviewer_id: String, notes: Option<String>) {
        self.status = HitlStatus::Approved;
        self.reviewer_id = Some(reviewer_id);
        self.reviewed_at = Some(Utc::now());
        self.review_notes = notes;
    }

    /// Reject the task.
    pub fn reject(&mut self, reviewer_id: String, notes: Option<String>) {
        self.status = HitlStatus::Rejected;
        self.reviewer_id = Some(reviewer_id);
        self.reviewed_at = Some(Utc::now());
        self.review_notes = notes;
    }
}

/// Full details of a HITL task including related entities.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HitlTaskDetails {
    pub task: HitlTask,
    pub agent_action: AgentAction,
    pub evaluation: EvaluationResult,
}

/// Summary of a HITL task for list views.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HitlTaskSummary {
    pub id: Uuid,
    pub user_id: String,
    pub action_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<f64>,
    pub risk_tier: String,
    pub status: HitlStatus,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hitl_task_lifecycle() {
        let action_id = Uuid::new_v4();
        let eval_id = Uuid::new_v4();

        let mut task = HitlTask::new(action_id, eval_id);
        assert_eq!(task.status, HitlStatus::Pending);
        assert!(task.reviewer_id.is_none());

        task.approve(
            "admin@example.com".to_string(),
            Some("Looks good".to_string()),
        );
        assert_eq!(task.status, HitlStatus::Approved);
        assert_eq!(task.reviewer_id, Some("admin@example.com".to_string()));
        assert!(task.reviewed_at.is_some());
    }

    #[test]
    fn test_hitl_status_from_str() {
        assert_eq!(
            "pending".parse::<HitlStatus>().unwrap(),
            HitlStatus::Pending
        );
        assert_eq!(
            "APPROVED".parse::<HitlStatus>().unwrap(),
            HitlStatus::Approved
        );
        assert!("invalid".parse::<HitlStatus>().is_err());
    }
}
