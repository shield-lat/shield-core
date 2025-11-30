//! Route definitions for the API.

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

use crate::api::handlers::{self, AuthState};
use crate::auth::{require_api_key, require_jwt, ApiKeyValidator, JwtManager};
use crate::AppState;

/// Security scheme modifier for OpenAPI.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
            components.add_security_scheme(
                "api_key",
                SecurityScheme::ApiKey(utoipa::openapi::security::ApiKey::Header(
                    utoipa::openapi::security::ApiKeyValue::new("X-API-Key"),
                )),
            );
        }
    }
}

/// OpenAPI documentation.
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::evaluate_action,
        handlers::list_hitl_tasks,
        handlers::get_hitl_task,
        handlers::submit_hitl_decision,
        handlers::health_check,
        handlers::login,
        handlers::get_current_user,
    ),
    components(schemas(
        crate::api::types::EvaluateActionRequest,
        crate::api::types::EvaluateActionResponse,
        crate::api::types::ListHitlTasksQuery,
        crate::api::types::ListHitlTasksResponse,
        crate::api::types::GetHitlTaskResponse,
        crate::api::types::HitlDecisionRequest,
        crate::api::types::HitlDecisionResponse,
        crate::api::types::HealthResponse,
        crate::api::types::LoginRequest,
        crate::api::types::LoginResponse,
        crate::api::types::UserInfo,
        crate::domain::AgentAction,
        crate::domain::ActionType,
        crate::domain::EvaluationResult,
        crate::domain::DecisionStatus,
        crate::domain::RiskTier,
        crate::domain::HitlTask,
        crate::domain::HitlStatus,
        crate::domain::HitlTaskDetails,
        crate::domain::HitlTaskSummary,
        crate::domain::TransferFundsPayload,
        crate::domain::GetBalancePayload,
        crate::domain::PayBillPayload,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "actions", description = "Action evaluation endpoints"),
        (name = "hitl", description = "Human-in-the-loop task management"),
        (name = "auth", description = "Authentication endpoints"),
        (name = "health", description = "Health and status endpoints")
    ),
    info(
        title = "Shield Core API",
        version = "0.1.0",
        description = "AI Safety Gateway for Fintech - Evaluates LLM agent actions before execution",
        license(name = "MIT")
    )
)]
pub struct ApiDoc;

/// Build the API router with optional authentication.
pub fn build_router(
    state: AppState,
    auth_enabled: bool,
    api_key_validator: ApiKeyValidator,
    jwt_manager: JwtManager,
    auth_state: AuthState,
) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    if auth_enabled {
        build_authenticated_router(state, api_key_validator, jwt_manager, auth_state, cors)
    } else {
        build_unauthenticated_router(state, auth_state, cors)
    }
}

/// Build router with authentication middleware.
fn build_authenticated_router(
    state: AppState,
    api_key_validator: ApiKeyValidator,
    jwt_manager: JwtManager,
    auth_state: AuthState,
    cors: CorsLayer,
) -> Router {
    // Routes requiring API key (for agents)
    let agent_routes = Router::new()
        .route("/v1/actions/evaluate", post(handlers::evaluate_action))
        .layer(middleware::from_fn_with_state(
            api_key_validator.clone(),
            require_api_key,
        ))
        .with_state(state.clone());

    // Routes requiring JWT (for admin console)
    let admin_routes = Router::new()
        .route("/v1/hitl/tasks", get(handlers::list_hitl_tasks))
        .route("/v1/hitl/tasks/{id}", get(handlers::get_hitl_task))
        .route(
            "/v1/hitl/tasks/{id}/decision",
            post(handlers::submit_hitl_decision),
        )
        .route("/v1/auth/me", get(handlers::get_current_user))
        .layer(middleware::from_fn_with_state(
            jwt_manager.clone(),
            require_jwt,
        ))
        .with_state(state.clone());

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/v1/health", get(handlers::health_check))
        .with_state(state.clone())
        .route("/v1/auth/login", post(handlers::login))
        .with_state(auth_state);

    Router::new()
        .merge(agent_routes)
        .merge(admin_routes)
        .merge(public_routes)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
}

/// Build router without authentication (for development).
fn build_unauthenticated_router(state: AppState, auth_state: AuthState, cors: CorsLayer) -> Router {
    Router::new()
        // Action evaluation
        .route("/v1/actions/evaluate", post(handlers::evaluate_action))
        // HITL management
        .route("/v1/hitl/tasks", get(handlers::list_hitl_tasks))
        .route("/v1/hitl/tasks/{id}", get(handlers::get_hitl_task))
        .route(
            "/v1/hitl/tasks/{id}/decision",
            post(handlers::submit_hitl_decision),
        )
        // Health
        .route("/v1/health", get(handlers::health_check))
        .with_state(state)
        // Auth (still available for testing)
        .route("/v1/auth/login", post(handlers::login))
        .with_state(auth_state)
        // OpenAPI docs
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(cors)
}
