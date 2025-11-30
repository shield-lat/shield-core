//! Authentication middleware for axum.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::auth::{ApiKeyValidator, Claims, JwtManager};

/// Error response for authentication failures.
#[derive(Debug, Serialize)]
pub struct AuthError {
    pub error: String,
    pub code: String,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, Json(self)).into_response()
    }
}

/// Extract and validate API key from request.
///
/// Looks for `X-API-Key` header or `Authorization: Bearer <key>` header.
pub async fn require_api_key(
    State(validator): State<ApiKeyValidator>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, AuthError> {
    // Try X-API-Key header first
    let api_key = request
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Fall back to Authorization: Bearer
    let api_key = api_key.or_else(|| {
        request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(String::from)
    });

    let api_key = api_key.ok_or_else(|| AuthError {
        error: "Missing API key".to_string(),
        code: "MISSING_API_KEY".to_string(),
    })?;

    let key_info = validator.validate(&api_key).await.ok_or_else(|| {
        tracing::warn!(key_prefix = %&api_key[..8.min(api_key.len())], "Invalid API key attempted");
        AuthError {
            error: "Invalid API key".to_string(),
            code: "INVALID_API_KEY".to_string(),
        }
    })?;

    // Add key info to request extensions for handlers to access
    request.extensions_mut().insert(key_info);

    Ok(next.run(request).await)
}

/// Extract and validate JWT token from request.
///
/// Expects `Authorization: Bearer <token>` header.
pub async fn require_jwt(
    State(jwt_manager): State<JwtManager>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, AuthError> {
    let token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| AuthError {
            error: "Missing authorization token".to_string(),
            code: "MISSING_TOKEN".to_string(),
        })?;

    let claims = jwt_manager.validate_token(token).map_err(|e| {
        tracing::debug!(error = %e, "JWT validation failed");
        AuthError {
            error: "Invalid or expired token".to_string(),
            code: "INVALID_TOKEN".to_string(),
        }
    })?;

    // Add claims to request extensions for handlers to access
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

/// Optional JWT validation - populates claims if token is valid, but doesn't fail if missing.
///
/// Used in development mode when auth is disabled but handlers still need claims.
pub async fn optional_jwt(
    State(jwt_manager): State<JwtManager>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Try to extract and validate token
    if let Some(token) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        if let Ok(claims) = jwt_manager.validate_token(token) {
            request.extensions_mut().insert(claims);
        }
    }

    next.run(request).await
}

/// Middleware that requires reviewer role or higher.
#[allow(dead_code)]
pub async fn require_reviewer(request: Request<Body>, next: Next) -> Result<Response, AuthError> {
    let claims = request
        .extensions()
        .get::<Claims>()
        .ok_or_else(|| AuthError {
            error: "Authentication required".to_string(),
            code: "UNAUTHENTICATED".to_string(),
        })?;

    if !claims.role.can_review() {
        return Err(AuthError {
            error: "Insufficient permissions".to_string(),
            code: "FORBIDDEN".to_string(),
        });
    }

    Ok(next.run(request).await)
}

/// Extension trait to extract auth info from request extensions.
#[allow(dead_code)]
pub trait AuthExtensions {
    fn api_key_info(&self) -> Option<&crate::auth::ApiKeyInfo>;
    fn jwt_claims(&self) -> Option<&Claims>;
}

impl<B> AuthExtensions for Request<B> {
    fn api_key_info(&self) -> Option<&crate::auth::ApiKeyInfo> {
        self.extensions().get()
    }

    fn jwt_claims(&self) -> Option<&Claims> {
        self.extensions().get()
    }
}
