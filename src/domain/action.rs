//! Action-related domain types.
//!
//! Represents what an LLM/agent proposes to do.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Types of actions an agent can propose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    /// Query account balance.
    GetBalance,
    /// Transfer funds between accounts.
    TransferFunds,
    /// Pay a bill.
    PayBill,
    /// View transaction history.
    GetTransactions,
    /// Request a loan.
    RequestLoan,
    /// Add a new beneficiary.
    AddBeneficiary,
    /// Update user profile.
    UpdateProfile,
    /// Close an account.
    CloseAccount,
    /// Refund a transaction.
    RefundTransaction,
    /// Unknown or unclassified action.
    Unknown,
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionType::GetBalance => write!(f, "get_balance"),
            ActionType::TransferFunds => write!(f, "transfer_funds"),
            ActionType::PayBill => write!(f, "pay_bill"),
            ActionType::GetTransactions => write!(f, "get_transactions"),
            ActionType::RequestLoan => write!(f, "request_loan"),
            ActionType::AddBeneficiary => write!(f, "add_beneficiary"),
            ActionType::UpdateProfile => write!(f, "update_profile"),
            ActionType::CloseAccount => write!(f, "close_account"),
            ActionType::RefundTransaction => write!(f, "refund_transaction"),
            ActionType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Payload for TransferFunds action.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransferFundsPayload {
    pub from_account_id: String,
    pub to_account_id: String,
    pub amount: f64,
    pub currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Payload for GetBalance action.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GetBalancePayload {
    pub account_id: String,
}

/// Payload for PayBill action.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PayBillPayload {
    pub from_account_id: String,
    pub biller_id: String,
    pub amount: f64,
    pub currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// An action proposed by an LLM/agent.
///
/// This is the primary input to the Shield evaluation pipeline.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AgentAction {
    /// Unique identifier for this action.
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,

    /// Trace ID for distributed tracing (provided by caller or generated).
    #[serde(default = "default_trace_id")]
    pub trace_id: String,

    /// ID of the app/agent that initiated this action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<Uuid>,

    /// ID of the user on whose behalf the action is being performed.
    pub user_id: String,

    /// Channel through which the action was initiated.
    pub channel: String,

    /// Name of the model that generated this action.
    pub model_name: String,

    /// Original natural-language request from the user.
    pub original_intent: String,

    /// Type of action being proposed.
    pub action_type: ActionType,

    /// Action-specific payload (JSON).
    pub payload: serde_json::Value,

    /// Chain of thought or reasoning trace (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cot_trace: Option<String>,

    /// Additional metadata for future extensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,

    /// When this action was created.
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
}

fn default_trace_id() -> String {
    Uuid::new_v4().to_string()
}

impl AgentAction {
    /// Create a new AgentAction with required fields.
    pub fn new(
        user_id: impl Into<String>,
        channel: impl Into<String>,
        model_name: impl Into<String>,
        original_intent: impl Into<String>,
        action_type: ActionType,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            trace_id: Uuid::new_v4().to_string(),
            app_id: None,
            user_id: user_id.into(),
            channel: channel.into(),
            model_name: model_name.into(),
            original_intent: original_intent.into(),
            action_type,
            payload,
            cot_trace: None,
            metadata: None,
            created_at: Utc::now(),
        }
    }

    /// Set the app ID for this action.
    pub fn with_app_id(mut self, app_id: Uuid) -> Self {
        self.app_id = Some(app_id);
        self
    }

    /// Try to extract the amount from the payload (for monetary actions).
    pub fn extract_amount(&self) -> Option<f64> {
        match self.action_type {
            ActionType::TransferFunds
            | ActionType::PayBill
            | ActionType::RequestLoan
            | ActionType::RefundTransaction => self.payload.get("amount").and_then(|v| v.as_f64()),
            _ => None,
        }
    }

    /// Try to extract the currency from the payload.
    pub fn extract_currency(&self) -> Option<&str> {
        self.payload.get("currency").and_then(|v| v.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_type_serialization() {
        let action_type = ActionType::TransferFunds;
        let json = serde_json::to_string(&action_type).unwrap();
        assert_eq!(json, "\"transfer_funds\"");

        let parsed: ActionType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ActionType::TransferFunds);
    }

    #[test]
    fn test_extract_amount() {
        let action = AgentAction::new(
            "user123",
            "chatbot",
            "gpt-4",
            "transfer $500 to savings",
            ActionType::TransferFunds,
            serde_json::json!({
                "from_account_id": "checking",
                "to_account_id": "savings",
                "amount": 500.0,
                "currency": "USD"
            }),
        );

        assert_eq!(action.extract_amount(), Some(500.0));
        assert_eq!(action.extract_currency(), Some("USD"));
    }

    #[test]
    fn test_extract_amount_non_monetary() {
        let action = AgentAction::new(
            "user123",
            "chatbot",
            "gpt-4",
            "check my balance",
            ActionType::GetBalance,
            serde_json::json!({ "account_id": "checking" }),
        );

        assert_eq!(action.extract_amount(), None);
    }
}
