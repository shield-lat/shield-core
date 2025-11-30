//! JWT authentication for admin console users.

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};

use crate::error::{ShieldError, ShieldResult};

/// JWT claims for authenticated users.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID).
    pub sub: String,
    /// User email.
    pub email: String,
    /// User role.
    pub role: UserRole,
    /// Expiration time (Unix timestamp).
    pub exp: i64,
    /// Issued at time (Unix timestamp).
    pub iat: i64,
    /// Issuer.
    pub iss: String,
}

/// User roles for authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    /// Can view HITL tasks but not decide.
    Viewer,
    /// Can approve/reject HITL tasks.
    Reviewer,
    /// Full access including configuration.
    Admin,
}

impl UserRole {
    /// Check if this role can review HITL tasks.
    #[allow(dead_code)]
    pub fn can_review(&self) -> bool {
        matches!(self, UserRole::Reviewer | UserRole::Admin)
    }

    /// Check if this role has admin privileges.
    #[allow(dead_code)]
    pub fn is_admin(&self) -> bool {
        matches!(self, UserRole::Admin)
    }
}

/// JWT token manager.
#[derive(Clone)]
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
    /// Token validity duration in hours.
    token_duration_hours: i64,
}

impl JwtManager {
    /// Create a new JWT manager with the given secret.
    pub fn new(secret: &str, issuer: String, token_duration_hours: i64) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            issuer,
            token_duration_hours,
        }
    }

    /// Get token duration in hours.
    pub fn token_duration_hours(&self) -> i64 {
        self.token_duration_hours
    }

    /// Generate a JWT token for a user.
    pub fn generate_token(
        &self,
        user_id: &str,
        email: &str,
        role: UserRole,
    ) -> ShieldResult<String> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.token_duration_hours);

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role,
            exp: exp.timestamp(),
            iat: now.timestamp(),
            iss: self.issuer.clone(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| ShieldError::Internal(format!("Failed to generate token: {}", e)))
    }

    /// Validate and decode a JWT token.
    pub fn validate_token(&self, token: &str) -> ShieldResult<Claims> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.issuer]);

        let token_data: TokenData<Claims> =
            decode(token, &self.decoding_key, &validation).map_err(|e| {
                tracing::debug!(error = %e, "JWT validation failed");
                ShieldError::BadRequest(format!("Invalid token: {}", e))
            })?;

        Ok(token_data.claims)
    }
}

/// Configured admin user from config file.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ConfiguredUser {
    /// User ID.
    pub id: String,
    /// User email.
    pub email: String,
    /// Password hash (SHA256 hex).
    pub password_hash: String,
    /// User role.
    pub role: UserRole,
}

impl ConfiguredUser {
    /// Verify a password against the stored hash.
    pub fn verify_password(&self, password: &str) -> bool {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let hash = hex::encode(hasher.finalize());
        hash == self.password_hash
    }
}

/// Simple in-memory user store (for MVP, can be replaced with DB).
#[derive(Clone)]
pub struct UserStore {
    users: std::collections::HashMap<String, ConfiguredUser>,
}

impl UserStore {
    /// Create a new user store from configured users.
    pub fn new(users: Vec<ConfiguredUser>) -> Self {
        let users = users
            .into_iter()
            .map(|u| (u.email.clone(), u))
            .collect();
        Self { users }
    }

    /// Find a user by email.
    pub fn find_by_email(&self, email: &str) -> Option<&ConfiguredUser> {
        self.users.get(email)
    }

    /// Authenticate a user with email and password.
    pub fn authenticate(&self, email: &str, password: &str) -> Option<&ConfiguredUser> {
        self.find_by_email(email)
            .filter(|user| user.verify_password(password))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_roundtrip() {
        let manager = JwtManager::new("test-secret-key-12345", "shield-core".to_string(), 24);

        let token = manager
            .generate_token("user-1", "admin@example.com", UserRole::Admin)
            .unwrap();

        let claims = manager.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.email, "admin@example.com");
        assert_eq!(claims.role, UserRole::Admin);
    }

    #[test]
    fn test_user_authentication() {
        use sha2::{Digest, Sha256};

        // Hash "password123"
        let mut hasher = Sha256::new();
        hasher.update(b"password123");
        let hash = hex::encode(hasher.finalize());

        let users = vec![ConfiguredUser {
            id: "user-1".to_string(),
            email: "admin@example.com".to_string(),
            password_hash: hash,
            role: UserRole::Admin,
        }];

        let store = UserStore::new(users);

        // Valid credentials
        assert!(store.authenticate("admin@example.com", "password123").is_some());

        // Wrong password
        assert!(store.authenticate("admin@example.com", "wrong").is_none());

        // Unknown user
        assert!(store.authenticate("unknown@example.com", "password123").is_none());
    }

    #[test]
    fn test_role_permissions() {
        assert!(!UserRole::Viewer.can_review());
        assert!(UserRole::Reviewer.can_review());
        assert!(UserRole::Admin.can_review());
        assert!(UserRole::Admin.is_admin());
        assert!(!UserRole::Reviewer.is_admin());
    }
}

