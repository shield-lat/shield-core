//! API Key authentication for agent/LLM clients.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Represents an API key with its metadata.
#[derive(Debug, Clone)]
pub struct ApiKeyInfo {
    /// Unique identifier for this key.
    pub key_id: String,
    /// Human-readable name/description (for future use in logging/auditing).
    #[allow(dead_code)]
    pub name: String,
    /// Associated client/agent identifier (for future use in auditing).
    #[allow(dead_code)]
    pub client_id: String,
    /// Whether this key is active.
    pub active: bool,
    /// Optional rate limit (for future rate limiting).
    #[allow(dead_code)]
    pub rate_limit: Option<u32>,
}

/// API Key validator and store.
#[derive(Clone)]
pub struct ApiKeyValidator {
    /// Map of hashed keys to their info.
    keys: Arc<RwLock<HashMap<String, ApiKeyInfo>>>,
}

impl ApiKeyValidator {
    /// Create a new validator with initial keys from config.
    pub fn new(configured_keys: Vec<ConfiguredApiKey>) -> Self {
        let mut keys = HashMap::new();

        for key in configured_keys {
            let hashed = Self::hash_key(&key.key);
            keys.insert(
                hashed,
                ApiKeyInfo {
                    key_id: key.id.clone(),
                    name: key.name,
                    client_id: key.client_id,
                    active: true,
                    rate_limit: key.rate_limit,
                },
            );
        }

        Self {
            keys: Arc::new(RwLock::new(keys)),
        }
    }

    /// Hash an API key for secure storage/comparison.
    pub fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Validate an API key and return its info if valid.
    pub async fn validate(&self, key: &str) -> Option<ApiKeyInfo> {
        let hashed = Self::hash_key(key);
        let keys = self.keys.read().await;

        keys.get(&hashed).filter(|info| info.active).cloned()
    }

    /// Add a new API key (for runtime management).
    #[allow(dead_code)]
    pub async fn add_key(&self, key: &str, info: ApiKeyInfo) {
        let hashed = Self::hash_key(key);
        let mut keys = self.keys.write().await;
        keys.insert(hashed, info);
    }

    /// Revoke an API key by its ID.
    #[allow(dead_code)]
    pub async fn revoke_key(&self, key_id: &str) {
        let mut keys = self.keys.write().await;
        for info in keys.values_mut() {
            if info.key_id == key_id {
                info.active = false;
            }
        }
    }
}

/// API key configuration from config file.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ConfiguredApiKey {
    /// Unique ID for the key.
    pub id: String,
    /// The actual API key value.
    pub key: String,
    /// Human-readable name.
    pub name: String,
    /// Associated client/agent ID.
    pub client_id: String,
    /// Optional rate limit.
    #[serde(default)]
    pub rate_limit: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_api_key_validation() {
        let keys = vec![ConfiguredApiKey {
            id: "key-1".to_string(),
            key: "sk-test-key-12345".to_string(),
            name: "Test Agent".to_string(),
            client_id: "agent-001".to_string(),
            rate_limit: Some(100),
        }];

        let validator = ApiKeyValidator::new(keys);

        // Valid key
        let result = validator.validate("sk-test-key-12345").await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().client_id, "agent-001");

        // Invalid key
        let result = validator.validate("wrong-key").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_key_revocation() {
        let keys = vec![ConfiguredApiKey {
            id: "key-1".to_string(),
            key: "sk-test-key".to_string(),
            name: "Test".to_string(),
            client_id: "agent".to_string(),
            rate_limit: None,
        }];

        let validator = ApiKeyValidator::new(keys);

        // Initially valid
        assert!(validator.validate("sk-test-key").await.is_some());

        // Revoke
        validator.revoke_key("key-1").await;

        // Now invalid
        assert!(validator.validate("sk-test-key").await.is_none());
    }
}

