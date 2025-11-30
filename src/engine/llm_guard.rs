//! LLM-based content safety using Meta Llama Guard via OpenRouter.
//!
//! This module provides neural detection capabilities using Llama Guard 4
//! for prompt injection, jailbreak, and other content safety classifications.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::domain::AgentAction;
use crate::engine::firewall::{FirewallOutcome, InputFirewall};

/// OpenRouter API configuration.
#[derive(Debug, Clone)]
pub struct OpenRouterConfig {
    /// API key for OpenRouter.
    pub api_key: String,
    /// Model to use (default: meta-llama/llama-guard-4-12b).
    pub model: String,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
    /// Whether the guard is enabled.
    pub enabled: bool,
}

impl Default for OpenRouterConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            model: "meta-llama/llama-guard-4-12b".to_string(),
            timeout_secs: 10,
            enabled: false,
        }
    }
}

/// Request to OpenRouter API.
#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

/// Response from OpenRouter API.
#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Debug, Deserialize)]
struct ResponseMessage {
    content: String,
}

/// Llama Guard safety categories (MLCommons hazard taxonomy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyCategory {
    /// S1: Violent Crimes
    ViolentCrimes,
    /// S2: Non-Violent Crimes
    NonViolentCrimes,
    /// S3: Sex-Related Crimes
    SexCrimes,
    /// S4: Child Sexual Exploitation
    ChildExploitation,
    /// S5: Defamation
    Defamation,
    /// S6: Specialized Advice
    SpecializedAdvice,
    /// S7: Privacy
    Privacy,
    /// S8: Intellectual Property
    IntellectualProperty,
    /// S9: Indiscriminate Weapons
    IndiscriminateWeapons,
    /// S10: Hate
    Hate,
    /// S11: Suicide & Self-Harm
    SelfHarm,
    /// S12: Sexual Content
    SexualContent,
    /// S13: Elections
    Elections,
    /// S14: Code Interpreter Abuse
    CodeInterpreterAbuse,
    /// Unknown category
    Unknown(String),
}

impl SafetyCategory {
    fn from_code(code: &str) -> Self {
        match code.trim().to_uppercase().as_str() {
            "S1" => SafetyCategory::ViolentCrimes,
            "S2" => SafetyCategory::NonViolentCrimes,
            "S3" => SafetyCategory::SexCrimes,
            "S4" => SafetyCategory::ChildExploitation,
            "S5" => SafetyCategory::Defamation,
            "S6" => SafetyCategory::SpecializedAdvice,
            "S7" => SafetyCategory::Privacy,
            "S8" => SafetyCategory::IntellectualProperty,
            "S9" => SafetyCategory::IndiscriminateWeapons,
            "S10" => SafetyCategory::Hate,
            "S11" => SafetyCategory::SelfHarm,
            "S12" => SafetyCategory::SexualContent,
            "S13" => SafetyCategory::Elections,
            "S14" => SafetyCategory::CodeInterpreterAbuse,
            other => SafetyCategory::Unknown(other.to_string()),
        }
    }

    fn description(&self) -> &str {
        match self {
            SafetyCategory::ViolentCrimes => "Violent crimes",
            SafetyCategory::NonViolentCrimes => "Non-violent crimes (fraud, theft)",
            SafetyCategory::SexCrimes => "Sex-related crimes",
            SafetyCategory::ChildExploitation => "Child sexual exploitation",
            SafetyCategory::Defamation => "Defamation",
            SafetyCategory::SpecializedAdvice => "Specialized advice (medical, legal, financial)",
            SafetyCategory::Privacy => "Privacy violation",
            SafetyCategory::IntellectualProperty => "Intellectual property violation",
            SafetyCategory::IndiscriminateWeapons => "Indiscriminate weapons (CBRN)",
            SafetyCategory::Hate => "Hate speech",
            SafetyCategory::SelfHarm => "Suicide & self-harm",
            SafetyCategory::SexualContent => "Sexual content",
            SafetyCategory::Elections => "Election misinformation",
            SafetyCategory::CodeInterpreterAbuse => "Code interpreter abuse",
            SafetyCategory::Unknown(s) => s.as_str(),
        }
    }
}

/// Result of Llama Guard classification.
#[derive(Debug, Clone)]
pub struct GuardResult {
    /// Whether the content is safe.
    pub is_safe: bool,
    /// Categories violated (if unsafe).
    pub violated_categories: Vec<SafetyCategory>,
    /// Raw response from the model.
    pub raw_response: String,
}

impl GuardResult {
    /// Parse Llama Guard response format.
    ///
    /// Llama Guard outputs:
    /// - "safe" if content is safe
    /// - "unsafe\nS1,S2,..." if content violates categories
    fn parse(response: &str) -> Self {
        let response = response.trim().to_lowercase();

        if response == "safe" || response.starts_with("safe") {
            return GuardResult {
                is_safe: true,
                violated_categories: Vec::new(),
                raw_response: response,
            };
        }

        // Parse unsafe response
        let mut categories = Vec::new();
        let lines: Vec<&str> = response.lines().collect();

        for line in lines.iter().skip(1) {
            // Parse comma-separated category codes
            for code in line.split(',') {
                let code = code.trim();
                if !code.is_empty() {
                    categories.push(SafetyCategory::from_code(code));
                }
            }
        }

        // Also check for inline categories like "unsafe S1, S2"
        if categories.is_empty() && lines.len() == 1 {
            let parts: Vec<&str> = response.split_whitespace().collect();
            for part in parts.iter().skip(1) {
                let code = part.trim_matches(|c| c == ',' || c == '.');
                if code.starts_with('s') && code.len() <= 3 {
                    categories.push(SafetyCategory::from_code(code));
                }
            }
        }

        GuardResult {
            is_safe: false,
            violated_categories: categories,
            raw_response: response,
        }
    }
}

/// Neural firewall using Llama Guard via OpenRouter.
pub struct LlamaGuardFirewall {
    config: OpenRouterConfig,
    client: Client,
}

impl LlamaGuardFirewall {
    /// Create a new Llama Guard firewall.
    pub fn new(config: OpenRouterConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    /// Classify content using Llama Guard.
    pub async fn classify(&self, content: &str) -> Result<GuardResult, String> {
        if !self.config.enabled || self.config.api_key.is_empty() {
            return Ok(GuardResult {
                is_safe: true,
                violated_categories: Vec::new(),
                raw_response: "Guard disabled".to_string(),
            });
        }

        // Format prompt for Llama Guard
        // The model expects a specific format for classification
        let prompt = format!(
            r#"<|begin_of_text|><|start_header_id|>user<|end_header_id|>

Task: Check if there is unsafe content in 'User' messages in conversations according to our safety policy.

<BEGIN CONVERSATION>

User: {}

<END CONVERSATION>

Provide your safety assessment for the User message.
- First line must read 'safe' or 'unsafe'.
- If unsafe, a second line must include a comma-separated list of violated categories.<|eot_id|><|start_header_id|>assistant<|end_header_id|>"#,
            content
        );

        let request = ChatRequest {
            model: self.config.model.clone(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: prompt,
            }],
            max_tokens: Some(100),
        };

        let response = self
            .client
            .post("https://openrouter.ai/api/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .header("HTTP-Referer", "https://shield.lat")
            .header("X-Title", "Shield Core")
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("API error {}: {}", status, body));
        }

        let chat_response: ChatResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        let content = chat_response
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        Ok(GuardResult::parse(&content))
    }

    /// Build text content from an action for classification.
    fn build_content(&self, action: &AgentAction) -> String {
        let mut content = String::new();

        content.push_str("User intent: ");
        content.push_str(&action.original_intent);
        content.push('\n');

        content.push_str("Action type: ");
        content.push_str(&action.action_type.to_string());
        content.push('\n');

        if let Some(cot) = &action.cot_trace {
            content.push_str("Chain of thought: ");
            content.push_str(cot);
            content.push('\n');
        }

        // Include relevant payload fields
        if let Some(obj) = action.payload.as_object() {
            for (key, value) in obj {
                if let Some(s) = value.as_str() {
                    content.push_str(&format!("{}: {}\n", key, s));
                }
            }
        }

        content
    }
}

/// Synchronous wrapper for the async firewall.
/// Uses a tokio runtime handle for blocking operations.
pub struct SyncLlamaGuardFirewall {
    inner: LlamaGuardFirewall,
}

impl SyncLlamaGuardFirewall {
    pub fn new(config: OpenRouterConfig) -> Self {
        Self {
            inner: LlamaGuardFirewall::new(config),
        }
    }
}

impl InputFirewall for SyncLlamaGuardFirewall {
    fn evaluate(&self, action: &AgentAction) -> FirewallOutcome {
        tracing::debug!(
            trace_id = %action.trace_id,
            enabled = self.inner.config.enabled,
            "Llama Guard firewall evaluating action"
        );

        if !self.inner.config.enabled {
            tracing::debug!("Llama Guard is disabled, skipping");
            return FirewallOutcome::Clean;
        }

        let content = self.inner.build_content(action);
        tracing::debug!(content_len = content.len(), "Sending to Llama Guard API");

        // Use tokio's current runtime to block on the async operation
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.inner.classify(&content))
        });

        match result {
            Ok(guard_result) => {
                tracing::debug!(
                    is_safe = guard_result.is_safe,
                    categories = ?guard_result.violated_categories,
                    "Llama Guard API response received"
                );
                if guard_result.is_safe {
                    FirewallOutcome::Clean
                } else {
                    let reasons: Vec<String> = guard_result
                        .violated_categories
                        .iter()
                        .map(|c| format!("Llama Guard: {}", c.description()))
                        .collect();

                    // Critical categories should block
                    let critical = guard_result.violated_categories.iter().any(|c| {
                        matches!(
                            c,
                            SafetyCategory::ChildExploitation
                                | SafetyCategory::IndiscriminateWeapons
                                | SafetyCategory::ViolentCrimes
                        )
                    });

                    if critical {
                        FirewallOutcome::Blocked { reasons }
                    } else {
                        FirewallOutcome::Suspicious { reasons }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Llama Guard classification failed, allowing action");
                // Fail open - if the guard fails, continue with other checks
                FirewallOutcome::Clean
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_safe_response() {
        let result = GuardResult::parse("safe");
        assert!(result.is_safe);
        assert!(result.violated_categories.is_empty());
    }

    #[test]
    fn test_parse_unsafe_response() {
        let result = GuardResult::parse("unsafe\nS1, S2");
        assert!(!result.is_safe);
        assert_eq!(result.violated_categories.len(), 2);
        assert!(matches!(
            result.violated_categories[0],
            SafetyCategory::ViolentCrimes
        ));
        assert!(matches!(
            result.violated_categories[1],
            SafetyCategory::NonViolentCrimes
        ));
    }

    #[test]
    fn test_parse_unsafe_inline() {
        let result = GuardResult::parse("unsafe S6");
        assert!(!result.is_safe);
        assert_eq!(result.violated_categories.len(), 1);
        assert!(matches!(
            result.violated_categories[0],
            SafetyCategory::SpecializedAdvice
        ));
    }

    #[test]
    fn test_category_description() {
        assert_eq!(
            SafetyCategory::NonViolentCrimes.description(),
            "Non-violent crimes (fraud, theft)"
        );
    }
}
