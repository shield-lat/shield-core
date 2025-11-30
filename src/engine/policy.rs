//! Policy Engine - applies symbolic rules for decision making.
//!
//! This layer applies deterministic, configurable rules based on
//! action properties like amount, frequency, and type.

use crate::config::SafetyConfig;
use crate::domain::{ActionType, AgentAction, DecisionStatus};

/// Outcome of policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyOutcome {
    /// Suggested decision (can be overridden by other layers).
    pub decision_hint: Option<DecisionStatus>,
    /// List of rules that triggered.
    pub triggered_rules: Vec<TriggeredRule>,
}

/// A rule that was triggered during evaluation.
#[derive(Debug, Clone)]
pub struct TriggeredRule {
    /// Unique identifier for the rule.
    pub rule_id: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this rule suggests blocking.
    pub suggests_block: bool,
    /// Whether this rule requires HITL.
    pub requires_hitl: bool,
}

impl PolicyOutcome {
    pub fn allow() -> Self {
        Self {
            decision_hint: Some(DecisionStatus::Allow),
            triggered_rules: Vec::new(),
        }
    }

    pub fn require_hitl(rules: Vec<TriggeredRule>) -> Self {
        Self {
            decision_hint: Some(DecisionStatus::RequireHitl),
            triggered_rules: rules,
        }
    }

    pub fn block(rules: Vec<TriggeredRule>) -> Self {
        Self {
            decision_hint: Some(DecisionStatus::Block),
            triggered_rules: rules,
        }
    }

    /// Get the strictest decision from triggered rules.
    pub fn strictest_decision(&self) -> Option<DecisionStatus> {
        if self.triggered_rules.iter().any(|r| r.suggests_block) {
            return Some(DecisionStatus::Block);
        }
        if self.triggered_rules.iter().any(|r| r.requires_hitl) {
            return Some(DecisionStatus::RequireHitl);
        }
        self.decision_hint
    }

    /// Get rule IDs that triggered.
    pub fn rule_ids(&self) -> Vec<String> {
        self.triggered_rules.iter().map(|r| r.rule_id.clone()).collect()
    }

    /// Get human-readable descriptions of triggered rules.
    pub fn descriptions(&self) -> Vec<String> {
        self.triggered_rules
            .iter()
            .map(|r| r.description.clone())
            .collect()
    }
}

/// Trait for policy engine implementations.
pub trait PolicyEngine: Send + Sync {
    /// Evaluate policies against an action.
    fn evaluate_policies(&self, action: &AgentAction) -> PolicyOutcome;
}

/// Configuration-driven policy engine.
///
/// Applies rules based on thresholds and limits from config.
pub struct ConfigPolicyEngine {
    config: SafetyConfig,
}

impl ConfigPolicyEngine {
    pub fn new(config: SafetyConfig) -> Self {
        Self { config }
    }

    /// Check amount-based rules for monetary actions.
    fn check_amount_rules(&self, action: &AgentAction) -> Vec<TriggeredRule> {
        let mut rules = Vec::new();

        // Only applies to monetary actions
        if !matches!(
            action.action_type,
            ActionType::TransferFunds | ActionType::PayBill
        ) {
            return rules;
        }

        let amount = match action.extract_amount() {
            Some(a) => a,
            None => {
                // Missing amount on monetary action is suspicious
                rules.push(TriggeredRule {
                    rule_id: "AMOUNT_MISSING".to_string(),
                    description: "Monetary action missing amount field".to_string(),
                    suggests_block: false,
                    requires_hitl: true,
                });
                return rules;
            }
        };

        // Check against thresholds
        if amount > self.config.hitl_threshold {
            rules.push(TriggeredRule {
                rule_id: "AMOUNT_EXCEEDS_HITL_THRESHOLD".to_string(),
                description: format!(
                    "Amount ${:.2} exceeds HITL threshold ${:.2}",
                    amount, self.config.hitl_threshold
                ),
                suggests_block: false,
                requires_hitl: true,
            });
        } else if amount > self.config.max_auto_amount {
            rules.push(TriggeredRule {
                rule_id: "AMOUNT_EXCEEDS_AUTO_LIMIT".to_string(),
                description: format!(
                    "Amount ${:.2} exceeds auto-approval limit ${:.2}",
                    amount, self.config.max_auto_amount
                ),
                suggests_block: false,
                requires_hitl: true,
            });
        }

        // Check for negative or zero amounts
        if amount <= 0.0 {
            rules.push(TriggeredRule {
                rule_id: "AMOUNT_INVALID".to_string(),
                description: format!("Invalid amount: ${:.2}", amount),
                suggests_block: true,
                requires_hitl: false,
            });
        }

        // Check for suspiciously round numbers (potential automation)
        if amount > 1000.0 && amount == amount.round() && amount % 1000.0 == 0.0 {
            rules.push(TriggeredRule {
                rule_id: "AMOUNT_SUSPICIOUS_ROUND".to_string(),
                description: format!(
                    "Suspiciously round amount ${:.2} may indicate automation",
                    amount
                ),
                suggests_block: false,
                requires_hitl: true,
            });
        }

        rules
    }

    /// Check action-type-specific rules.
    fn check_action_type_rules(&self, action: &AgentAction) -> Vec<TriggeredRule> {
        let mut rules = Vec::new();

        match action.action_type {
            ActionType::TransferFunds => {
                // Check for same source and destination
                if let Some(payload) = action.payload.as_object() {
                    let from = payload.get("from_account_id").and_then(|v| v.as_str());
                    let to = payload.get("to_account_id").and_then(|v| v.as_str());

                    if from.is_some() && from == to {
                        rules.push(TriggeredRule {
                            rule_id: "TRANSFER_SAME_ACCOUNT".to_string(),
                            description: "Transfer source and destination are the same".to_string(),
                            suggests_block: true,
                            requires_hitl: false,
                        });
                    }
                }
            }
            // High-risk action types always require HITL
            ActionType::AddBeneficiary => {
                rules.push(TriggeredRule {
                    rule_id: "ACTION_ADD_BENEFICIARY".to_string(),
                    description: "Adding new beneficiary requires human approval".to_string(),
                    suggests_block: false,
                    requires_hitl: true,
                });
            }
            ActionType::CloseAccount => {
                rules.push(TriggeredRule {
                    rule_id: "ACTION_CLOSE_ACCOUNT".to_string(),
                    description: "Account closure is a critical action requiring review".to_string(),
                    suggests_block: false,
                    requires_hitl: true,
                });
            }
            ActionType::UpdateProfile => {
                rules.push(TriggeredRule {
                    rule_id: "ACTION_UPDATE_PROFILE".to_string(),
                    description: "Profile updates should be reviewed".to_string(),
                    suggests_block: false,
                    requires_hitl: true,
                });
            }
            ActionType::RequestLoan => {
                rules.push(TriggeredRule {
                    rule_id: "ACTION_REQUEST_LOAN".to_string(),
                    description: "Loan requests require human verification".to_string(),
                    suggests_block: false,
                    requires_hitl: true,
                });
            }
            ActionType::RefundTransaction => {
                rules.push(TriggeredRule {
                    rule_id: "ACTION_REFUND".to_string(),
                    description: "Refunds require human approval".to_string(),
                    suggests_block: false,
                    requires_hitl: true,
                });
            }
            ActionType::Unknown => {
                rules.push(TriggeredRule {
                    rule_id: "ACTION_TYPE_UNKNOWN".to_string(),
                    description: "Action type could not be classified".to_string(),
                    suggests_block: false,
                    requires_hitl: true,
                });
            }
            // Read-only actions are generally safe
            ActionType::GetBalance | ActionType::GetTransactions => {}
            // Payment actions are handled by amount rules
            ActionType::PayBill => {}
        }

        rules
    }
}

impl PolicyEngine for ConfigPolicyEngine {
    fn evaluate_policies(&self, action: &AgentAction) -> PolicyOutcome {
        let mut all_rules = Vec::new();

        // Run all rule checks
        all_rules.extend(self.check_amount_rules(action));
        all_rules.extend(self.check_action_type_rules(action));

        // Determine outcome based on triggered rules
        if all_rules.is_empty() {
            PolicyOutcome::allow()
        } else if all_rules.iter().any(|r| r.suggests_block) {
            PolicyOutcome::block(all_rules)
        } else if all_rules.iter().any(|r| r.requires_hitl) {
            PolicyOutcome::require_hitl(all_rules)
        } else {
            PolicyOutcome {
                decision_hint: Some(DecisionStatus::Allow),
                triggered_rules: all_rules,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> SafetyConfig {
        SafetyConfig {
            max_auto_amount: 100.0,
            hitl_threshold: 1000.0,
            max_transfers_per_hour: 3,
            suspicious_keywords: vec![],
        }
    }

    fn make_transfer(amount: f64) -> AgentAction {
        AgentAction::new(
            "user123",
            "chatbot",
            "gpt-4",
            "transfer money",
            ActionType::TransferFunds,
            serde_json::json!({
                "from_account_id": "checking",
                "to_account_id": "savings",
                "amount": amount,
                "currency": "USD"
            }),
        )
    }

    #[test]
    fn test_small_amount_allowed() {
        let engine = ConfigPolicyEngine::new(make_config());
        let action = make_transfer(50.0);

        let result = engine.evaluate_policies(&action);
        assert_eq!(result.strictest_decision(), Some(DecisionStatus::Allow));
        assert!(result.triggered_rules.is_empty());
    }

    #[test]
    fn test_medium_amount_hitl() {
        let engine = ConfigPolicyEngine::new(make_config());
        let action = make_transfer(500.0);

        let result = engine.evaluate_policies(&action);
        assert_eq!(result.strictest_decision(), Some(DecisionStatus::RequireHitl));
        assert!(result.rule_ids().contains(&"AMOUNT_EXCEEDS_AUTO_LIMIT".to_string()));
    }

    #[test]
    fn test_large_amount_hitl() {
        let engine = ConfigPolicyEngine::new(make_config());
        let action = make_transfer(5000.0);

        let result = engine.evaluate_policies(&action);
        assert_eq!(result.strictest_decision(), Some(DecisionStatus::RequireHitl));
        assert!(result.rule_ids().contains(&"AMOUNT_EXCEEDS_HITL_THRESHOLD".to_string()));
    }

    #[test]
    fn test_negative_amount_blocked() {
        let engine = ConfigPolicyEngine::new(make_config());
        let action = make_transfer(-100.0);

        let result = engine.evaluate_policies(&action);
        assert_eq!(result.strictest_decision(), Some(DecisionStatus::Block));
        assert!(result.rule_ids().contains(&"AMOUNT_INVALID".to_string()));
    }

    #[test]
    fn test_same_account_transfer_blocked() {
        let engine = ConfigPolicyEngine::new(make_config());
        let action = AgentAction::new(
            "user123",
            "chatbot",
            "gpt-4",
            "transfer money",
            ActionType::TransferFunds,
            serde_json::json!({
                "from_account_id": "checking",
                "to_account_id": "checking",
                "amount": 50.0,
                "currency": "USD"
            }),
        );

        let result = engine.evaluate_policies(&action);
        assert_eq!(result.strictest_decision(), Some(DecisionStatus::Block));
    }

    #[test]
    fn test_get_balance_allowed() {
        let engine = ConfigPolicyEngine::new(make_config());
        let action = AgentAction::new(
            "user123",
            "chatbot",
            "gpt-4",
            "check balance",
            ActionType::GetBalance,
            serde_json::json!({"account_id": "checking"}),
        );

        let result = engine.evaluate_policies(&action);
        assert_eq!(result.strictest_decision(), Some(DecisionStatus::Allow));
    }
}

