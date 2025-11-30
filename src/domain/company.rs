//! Company domain models.
//!
//! Companies are organizational units that group users and apps together.
//! A user can belong to multiple companies, and each company can have multiple apps.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// A company/organization that owns apps.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Company {
    /// Unique identifier.
    pub id: Uuid,
    /// Company name.
    pub name: String,
    /// URL-friendly slug.
    pub slug: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// When the company was created.
    pub created_at: DateTime<Utc>,
    /// When the company was last updated.
    pub updated_at: DateTime<Utc>,
}

impl Company {
    /// Create a new company.
    pub fn new(name: String, slug: String, description: Option<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            slug,
            description,
            created_at: now,
            updated_at: now,
        }
    }

    /// Generate a slug from a name.
    pub fn slugify(name: &str) -> String {
        name.to_lowercase()
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '-' })
            .collect::<String>()
            .split('-')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("-")
    }
}

/// Role within a company.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompanyRole {
    /// Full access to company settings and members.
    Owner,
    /// Can manage apps and view data.
    Admin,
    /// Can view data and manage HITL tasks.
    Member,
    /// Read-only access.
    Viewer,
}

impl std::fmt::Display for CompanyRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompanyRole::Owner => write!(f, "owner"),
            CompanyRole::Admin => write!(f, "admin"),
            CompanyRole::Member => write!(f, "member"),
            CompanyRole::Viewer => write!(f, "viewer"),
        }
    }
}

impl std::str::FromStr for CompanyRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "owner" => Ok(CompanyRole::Owner),
            "admin" => Ok(CompanyRole::Admin),
            "member" => Ok(CompanyRole::Member),
            "viewer" => Ok(CompanyRole::Viewer),
            _ => Err(format!("Unknown role: {}", s)),
        }
    }
}

/// A user's membership in a company.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CompanyMember {
    /// Unique identifier.
    pub id: Uuid,
    /// Company ID.
    pub company_id: Uuid,
    /// User ID.
    pub user_id: String,
    /// User's email (for display).
    pub email: String,
    /// Role in the company.
    pub role: CompanyRole,
    /// When the membership was created.
    pub created_at: DateTime<Utc>,
}

impl CompanyMember {
    /// Create a new company member.
    pub fn new(company_id: Uuid, user_id: String, email: String, role: CompanyRole) -> Self {
        Self {
            id: Uuid::new_v4(),
            company_id,
            user_id,
            email,
            role,
            created_at: Utc::now(),
        }
    }
}

/// Status of an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AppStatus {
    /// App is active and can make requests.
    Active,
    /// App is paused and cannot make requests.
    Paused,
    /// App has been revoked.
    Revoked,
}

impl std::fmt::Display for AppStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppStatus::Active => write!(f, "active"),
            AppStatus::Paused => write!(f, "paused"),
            AppStatus::Revoked => write!(f, "revoked"),
        }
    }
}

impl std::str::FromStr for AppStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(AppStatus::Active),
            "paused" => Ok(AppStatus::Paused),
            "revoked" => Ok(AppStatus::Revoked),
            _ => Err(format!("Unknown status: {}", s)),
        }
    }
}

/// An app/agent that belongs to a company.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct App {
    /// Unique identifier.
    pub id: Uuid,
    /// Company this app belongs to.
    pub company_id: Uuid,
    /// App name.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// API key (only shown once on creation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// API key prefix for identification.
    pub api_key_prefix: String,
    /// Current status.
    pub status: AppStatus,
    /// Rate limit (requests per minute).
    pub rate_limit: u32,
    /// When the app was created.
    pub created_at: DateTime<Utc>,
    /// When the app was last updated.
    pub updated_at: DateTime<Utc>,
    /// Last time the app made a request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
}

impl App {
    /// Create a new app with a generated API key.
    pub fn new(
        company_id: Uuid,
        name: String,
        description: Option<String>,
        rate_limit: u32,
    ) -> Self {
        let api_key = Self::generate_api_key();
        let api_key_prefix = api_key[..12].to_string();
        let now = Utc::now();

        Self {
            id: Uuid::new_v4(),
            company_id,
            name,
            description,
            api_key: Some(api_key),
            api_key_prefix,
            status: AppStatus::Active,
            rate_limit,
            created_at: now,
            updated_at: now,
            last_used_at: None,
        }
    }

    /// Generate a secure API key.
    fn generate_api_key() -> String {
        use sha2::{Digest, Sha256};

        let random_bytes: [u8; 32] = rand_bytes();
        let mut hasher = Sha256::new();
        hasher.update(random_bytes);
        hasher.update(Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        let hash = hasher.finalize();

        format!("sk_shield_{}", hex::encode(&hash[..24]))
    }

    /// Hash an API key for storage.
    pub fn hash_api_key(key: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Generate random bytes (simple implementation).
fn rand_bytes<const N: usize>() -> [u8; N] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut bytes = [0u8; N];
    let state = RandomState::new();
    for chunk in bytes.chunks_mut(8) {
        let mut hasher = state.build_hasher();
        hasher.write_usize(chunk.as_ptr() as usize);
        let random = hasher.finish().to_le_bytes();
        for (i, b) in chunk.iter_mut().enumerate() {
            *b = random[i % 8];
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slugify() {
        assert_eq!(Company::slugify("My Company"), "my-company");
        assert_eq!(Company::slugify("Test  Company  123"), "test-company-123");
        assert_eq!(
            Company::slugify("Special!@#Characters"),
            "special-characters"
        );
    }

    #[test]
    fn test_company_role_display() {
        assert_eq!(CompanyRole::Owner.to_string(), "owner");
        assert_eq!(CompanyRole::Admin.to_string(), "admin");
    }

    #[test]
    fn test_app_api_key_generation() {
        let app = App::new(Uuid::new_v4(), "Test App".to_string(), None, 100);
        assert!(app.api_key.as_ref().unwrap().starts_with("sk_shield_"));
        assert_eq!(app.api_key_prefix.len(), 12);
    }
}
