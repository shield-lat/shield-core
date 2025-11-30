//! Alignment Checker - verifies intent matches the proposed action.
//!
//! This layer checks whether the LLM's proposed action actually aligns
//! with what the user requested. Misalignment can indicate:
//! - Hallucination
//! - Prompt injection that changed the action
//! - Model confusion

use crate::domain::{ActionType, AgentAction};

/// Outcome of alignment checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlignmentOutcome {
    /// The action aligns with the stated intent.
    Aligned,
    /// The action does not match the stated intent.
    Misaligned { reasons: Vec<String> },
    /// Cannot determine alignment (insufficient context or disabled).
    Unknown,
}

impl AlignmentOutcome {
    pub fn is_misaligned(&self) -> bool {
        matches!(self, AlignmentOutcome::Misaligned { .. })
    }

    pub fn reasons(&self) -> Vec<String> {
        match self {
            AlignmentOutcome::Misaligned { reasons } => reasons.clone(),
            _ => Vec::new(),
        }
    }
}

/// Trait for alignment checker implementations.
///
/// Implementations can range from heuristic rules to LLM-based judges.
pub trait AlignmentChecker: Send + Sync {
    /// Check if the action aligns with the user's intent.
    fn check_alignment(&self, action: &AgentAction) -> AlignmentOutcome;
}

/// Heuristic-based alignment checker.
///
/// Uses keyword matching and action type inference to detect misalignment.
pub struct HeuristicAlignmentChecker {
    /// Whether to enable strict checking.
    strict_mode: bool,
}

impl HeuristicAlignmentChecker {
    pub fn new(strict_mode: bool) -> Self {
        Self { strict_mode }
    }

    /// Infer what action type the user likely intended from their message.
    fn infer_intent_type(&self, intent: &str) -> Option<ActionType> {
        let intent_lower = intent.to_lowercase();

        // Balance-related keywords
        if intent_lower.contains("balance")
            || intent_lower.contains("how much")
            || intent_lower.contains("check account")
            || intent_lower.contains("account status")
        {
            return Some(ActionType::GetBalance);
        }

        // Transfer-related keywords
        if intent_lower.contains("transfer")
            || intent_lower.contains("send money")
            || intent_lower.contains("move funds")
            || intent_lower.contains("wire")
        {
            return Some(ActionType::TransferFunds);
        }

        // Bill payment keywords
        if intent_lower.contains("pay bill")
            || intent_lower.contains("pay my")
            || intent_lower.contains("payment to")
        {
            return Some(ActionType::PayBill);
        }

        // Transaction history keywords
        if intent_lower.contains("transaction")
            || intent_lower.contains("history")
            || intent_lower.contains("recent activity")
            || intent_lower.contains("statement")
        {
            return Some(ActionType::GetTransactions);
        }

        None
    }

    /// Check for obvious misalignment between inferred intent and action.
    fn check_action_intent_mismatch(
        &self,
        inferred: &ActionType,
        actual: &ActionType,
        intent: &str,
    ) -> Option<String> {
        // Read-only intent but write action
        let is_read_intent = matches!(inferred, ActionType::GetBalance | ActionType::GetTransactions);
        let is_write_action = matches!(
            actual,
            ActionType::TransferFunds | ActionType::PayBill | ActionType::CloseAccount
        );

        if is_read_intent && is_write_action {
            return Some(format!(
                "User intent '{}' suggests read-only operation, but action is '{}'",
                intent, actual
            ));
        }

        // Critical actions require explicit matching intent
        let is_critical_action = matches!(
            actual,
            ActionType::CloseAccount | ActionType::AddBeneficiary | ActionType::RequestLoan
        );

        if is_critical_action && inferred != actual {
            return Some(format!(
                "Critical action '{}' does not match user intent '{}'",
                actual, intent
            ));
        }

        // Specific mismatches
        if inferred != actual {
            // In strict mode, any mismatch is flagged
            if self.strict_mode {
                return Some(format!(
                    "Inferred intent type '{}' does not match action type '{}'",
                    inferred, actual
                ));
            }
        }

        None
    }
}

impl AlignmentChecker for HeuristicAlignmentChecker {
    fn check_alignment(&self, action: &AgentAction) -> AlignmentOutcome {
        let intent = &action.original_intent;

        // Try to infer what the user wanted
        let inferred_type = match self.infer_intent_type(intent) {
            Some(t) => t,
            None => {
                // Can't infer intent - return Unknown in non-strict mode
                if !self.strict_mode {
                    return AlignmentOutcome::Unknown;
                }
                // In strict mode, unknown intent with write action is suspicious
                if matches!(
                    action.action_type,
                    ActionType::TransferFunds | ActionType::PayBill
                ) {
                    return AlignmentOutcome::Misaligned {
                        reasons: vec![format!(
                            "Cannot verify intent for high-risk action '{}'",
                            action.action_type
                        )],
                    };
                }
                return AlignmentOutcome::Unknown;
            }
        };

        // Check for misalignment
        if let Some(reason) =
            self.check_action_intent_mismatch(&inferred_type, &action.action_type, intent)
        {
            return AlignmentOutcome::Misaligned {
                reasons: vec![reason],
            };
        }

        AlignmentOutcome::Aligned
    }
}

/// Stub LLM-based alignment checker for future implementation.
///
/// This would call an external LLM to judge alignment.
#[allow(dead_code)]
pub struct LlmAlignmentChecker {
    /// Whether the checker is enabled.
    enabled: bool,
    // Future: endpoint, api_key, etc.
}

#[allow(dead_code)]
impl LlmAlignmentChecker {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }
}

impl AlignmentChecker for LlmAlignmentChecker {
    fn check_alignment(&self, _action: &AgentAction) -> AlignmentOutcome {
        if !self.enabled {
            return AlignmentOutcome::Unknown;
        }
        // TODO: Implement actual LLM call
        // For now, return Unknown to indicate we can't verify
        AlignmentOutcome::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_action(intent: &str, action_type: ActionType) -> AgentAction {
        AgentAction::new(
            "user123",
            "chatbot",
            "gpt-4",
            intent,
            action_type,
            serde_json::json!({}),
        )
    }

    #[test]
    fn test_aligned_balance_check() {
        let checker = HeuristicAlignmentChecker::new(false);
        let action = make_action("What is my account balance?", ActionType::GetBalance);

        let result = checker.check_alignment(&action);
        assert_eq!(result, AlignmentOutcome::Aligned);
    }

    #[test]
    fn test_misaligned_balance_to_transfer() {
        let checker = HeuristicAlignmentChecker::new(false);
        let action = make_action("Check my balance", ActionType::TransferFunds);

        let result = checker.check_alignment(&action);
        assert!(result.is_misaligned());
        assert!(result.reasons()[0].contains("read-only"));
    }

    #[test]
    fn test_aligned_transfer() {
        let checker = HeuristicAlignmentChecker::new(false);
        let action = make_action("Transfer $500 to my savings account", ActionType::TransferFunds);

        let result = checker.check_alignment(&action);
        assert_eq!(result, AlignmentOutcome::Aligned);
    }

    #[test]
    fn test_unknown_intent() {
        let checker = HeuristicAlignmentChecker::new(false);
        let action = make_action("Do something with my account", ActionType::GetBalance);

        let result = checker.check_alignment(&action);
        assert_eq!(result, AlignmentOutcome::Unknown);
    }

    #[test]
    fn test_strict_mode_unknown_write() {
        let checker = HeuristicAlignmentChecker::new(true);
        let action = make_action("Do something with my account", ActionType::TransferFunds);

        let result = checker.check_alignment(&action);
        assert!(result.is_misaligned());
    }
}

