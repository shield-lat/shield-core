//! User domain types.
//!
//! Represents users in the Shield system, supporting both password and OAuth authentication.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// User role in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    /// Regular user/member.
    Member,
    /// Administrator.
    Admin,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::Member => write!(f, "member"),
            UserRole::Admin => write!(f, "admin"),
        }
    }
}

impl std::str::FromStr for UserRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "member" => Ok(UserRole::Member),
            "admin" => Ok(UserRole::Admin),
            _ => Err(format!("Unknown role: {}", s)),
        }
    }
}

impl Default for UserRole {
    fn default() -> Self {
        UserRole::Member
    }
}

/// A user in the Shield system.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct User {
    /// Unique identifier.
    pub id: Uuid,
    /// User's email address.
    pub email: String,
    /// User's display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Avatar image URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// User's role in the system.
    pub role: UserRole,
    /// Whether email is verified.
    pub email_verified: bool,
    /// Password hash (None for OAuth-only users).
    #[serde(skip)]
    pub password_hash: Option<String>,
    /// When the user was created.
    pub created_at: DateTime<Utc>,
    /// When the user was last updated.
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Create a new user with password.
    pub fn new_with_password(email: String, password_hash: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            email,
            name: None,
            image: None,
            role: UserRole::Member,
            email_verified: false,
            password_hash: Some(password_hash),
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a new user from OAuth provider.
    pub fn new_from_oauth(
        email: String,
        name: Option<String>,
        image: Option<String>,
        email_verified: bool,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            email,
            name,
            image,
            role: UserRole::Member,
            email_verified,
            password_hash: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Verify password (returns false for OAuth-only users).
    pub fn verify_password(&self, password: &str) -> bool {
        use sha2::{Digest, Sha256};

        match &self.password_hash {
            Some(hash) => {
                let mut hasher = Sha256::new();
                hasher.update(password.as_bytes());
                let computed = hex::encode(hasher.finalize());
                computed == *hash
            }
            None => false,
        }
    }
}

/// OAuth provider types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OAuthProvider {
    Google,
    GitHub,
}

impl std::fmt::Display for OAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuthProvider::Google => write!(f, "google"),
            OAuthProvider::GitHub => write!(f, "github"),
        }
    }
}

impl std::str::FromStr for OAuthProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "google" => Ok(OAuthProvider::Google),
            "github" => Ok(OAuthProvider::GitHub),
            _ => Err(format!("Unknown provider: {}", s)),
        }
    }
}

/// An OAuth account linked to a user.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OAuthAccount {
    /// Unique identifier.
    pub id: Uuid,
    /// User this account belongs to.
    pub user_id: Uuid,
    /// OAuth provider.
    pub provider: OAuthProvider,
    /// Provider's account ID.
    pub provider_account_id: String,
    /// When this link was created.
    pub created_at: DateTime<Utc>,
}

impl OAuthAccount {
    /// Create a new OAuth account link.
    pub fn new(user_id: Uuid, provider: OAuthProvider, provider_account_id: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            provider,
            provider_account_id,
            created_at: Utc::now(),
        }
    }
}

/// User's membership in a company (for API responses).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserCompanyMembership {
    /// Company ID.
    pub id: Uuid,
    /// Company name.
    pub name: String,
    /// Company slug.
    pub slug: String,
    /// User's role in the company.
    pub role: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_role_display() {
        assert_eq!(UserRole::Member.to_string(), "member");
        assert_eq!(UserRole::Admin.to_string(), "admin");
    }

    #[test]
    fn test_oauth_provider_parse() {
        assert_eq!("google".parse::<OAuthProvider>().unwrap(), OAuthProvider::Google);
        assert_eq!("github".parse::<OAuthProvider>().unwrap(), OAuthProvider::GitHub);
    }

    #[test]
    fn test_password_verification() {
        use sha2::{Digest, Sha256};
        
        let password = "test123";
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let hash = hex::encode(hasher.finalize());

        let user = User::new_with_password("test@example.com".to_string(), hash);
        assert!(user.verify_password("test123"));
        assert!(!user.verify_password("wrong"));
    }
}

