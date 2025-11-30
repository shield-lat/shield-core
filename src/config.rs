//! Configuration module for Shield Core.
//!
//! Loads configuration from YAML files and environment variables.

use config::{Config as ConfigLoader, ConfigError, Environment, File};
use serde::Deserialize;

/// Root configuration structure.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub safety: SafetyConfig,
}

/// Server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

/// Database configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

/// Safety policy configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct SafetyConfig {
    /// Maximum amount that can be auto-approved without HITL.
    pub max_auto_amount: f64,
    /// Threshold above which HITL is required.
    pub hitl_threshold: f64,
    /// Maximum transfers per hour per user (for future rate limiting).
    #[allow(dead_code)]
    pub max_transfers_per_hour: u32,
    /// Keywords that trigger firewall suspicion.
    #[serde(default)]
    pub suspicious_keywords: Vec<String>,
}

impl Config {
    /// Load configuration from files and environment.
    ///
    /// Priority (highest to lowest):
    /// 1. Environment variables (SHIELD_*)
    /// 2. config/local.yaml (if exists)
    /// 3. config/default.yaml
    pub fn load() -> Result<Self, ConfigError> {
        let config = ConfigLoader::builder()
            // Start with default config
            .add_source(File::with_name("config/default").required(false))
            // Layer on local overrides
            .add_source(File::with_name("config/local").required(false))
            // Layer on environment variables with SHIELD_ prefix
            .add_source(
                Environment::with_prefix("SHIELD")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        config.try_deserialize()
    }
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            max_auto_amount: 100.0,
            hitl_threshold: 1000.0,
            max_transfers_per_hour: 3,
            suspicious_keywords: vec![
                "ignore previous instructions".to_string(),
                "bypass".to_string(),
                "transfer all funds".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_safety_config() {
        let config = SafetyConfig::default();
        assert_eq!(config.max_auto_amount, 100.0);
        assert_eq!(config.hitl_threshold, 1000.0);
        assert_eq!(config.max_transfers_per_hour, 3);
        assert!(!config.suspicious_keywords.is_empty());
    }
}

