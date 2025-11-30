//! Route definitions for the API.

use axum::{
    middleware,
    routing::{get, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

use crate::api::handlers;
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
        handlers::oauth_sync,
        handlers::refresh_token,
        handlers::get_current_user,
        // Company endpoints
        handlers::create_company,
        handlers::list_companies,
        handlers::get_company,
        handlers::update_company,
        handlers::delete_company,
        handlers::list_company_members,
        handlers::add_company_member,
        handlers::update_member_role,
        handlers::remove_company_member,
        // App endpoints
        handlers::list_company_apps,
        handlers::create_app,
        handlers::get_app,
        handlers::update_app,
        handlers::delete_app,
        // Metrics endpoints
        handlers::get_metrics_overview,
        handlers::get_time_series,
        handlers::get_risk_distribution,
        // Actions list
        handlers::list_company_actions,
        // Attacks
        handlers::list_attacks,
        // Settings
        handlers::get_company_settings,
        handlers::update_company_settings,
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
        crate::api::types::UserInfoResponse,
        crate::api::types::OAuthSyncRequest,
        crate::api::types::OAuthSyncResponse,
        crate::api::types::TokenRefreshResponse,
        crate::api::types::CurrentUserResponse,
        crate::domain::User,
        crate::domain::UserRole,
        crate::domain::OAuthProvider,
        crate::domain::UserCompanyMembership,
        // Company types
        crate::api::types::CreateCompanyRequest,
        crate::api::types::UpdateCompanyRequest,
        crate::api::types::CompanyResponse,
        crate::api::types::ListCompaniesResponse,
        crate::api::types::AddMemberRequest,
        crate::api::types::UpdateMemberRoleRequest,
        crate::api::types::MemberResponse,
        crate::api::types::ListMembersResponse,
        crate::api::types::CreateAppRequest,
        crate::api::types::UpdateAppRequest,
        crate::api::types::CreateAppResponse,
        crate::api::types::AppResponse,
        crate::api::types::ListAppsResponse,
        // Metrics types
        crate::api::types::MetricsQuery,
        crate::api::types::MetricsOverviewResponse,
        crate::api::types::TimeSeriesResponse,
        crate::api::types::RiskDistributionResponse,
        // Actions list types
        crate::api::types::ListActionsQuery,
        crate::api::types::ActionListItem,
        crate::api::types::ListActionsResponse,
        // Attacks types
        crate::api::types::ListAttacksQuery,
        crate::api::types::ListAttacksResponse,
        // Settings types
        crate::api::types::SettingsResponse,
        crate::api::types::UpdateSettingsRequest,
        // Domain types
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
        crate::domain::Company,
        crate::domain::CompanyMember,
        crate::domain::CompanyRole,
        crate::domain::App,
        crate::domain::AppStatus,
        crate::domain::AttackEvent,
        crate::domain::AttackType,
        crate::domain::AttackOutcome,
        crate::domain::MetricsOverview,
        crate::domain::Trends,
        crate::domain::TimeSeriesData,
        crate::domain::TimeSeriesPoint,
        crate::domain::RiskDistribution,
        crate::domain::RiskDistributionPoint,
        crate::domain::CompanySettings,
        crate::domain::PolicyThresholds,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "actions", description = "Action evaluation and listing"),
        (name = "hitl", description = "Human-in-the-loop task management"),
        (name = "metrics", description = "Analytics and metrics"),
        (name = "attacks", description = "Security attack events"),
        (name = "settings", description = "Company settings and policies"),
        (name = "auth", description = "Authentication endpoints"),
        (name = "companies", description = "Company management"),
        (name = "apps", description = "App/API key management"),
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
) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    if auth_enabled {
        build_authenticated_router(state, api_key_validator, jwt_manager, cors)
    } else {
        build_unauthenticated_router(state, cors)
    }
}

/// Build router with authentication middleware.
fn build_authenticated_router(
    state: AppState,
    api_key_validator: ApiKeyValidator,
    jwt_manager: JwtManager,
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
        // HITL routes
        .route("/v1/hitl/tasks", get(handlers::list_hitl_tasks))
        .route("/v1/hitl/tasks/{id}", get(handlers::get_hitl_task))
        .route(
            "/v1/hitl/tasks/{id}/decision",
            post(handlers::submit_hitl_decision),
        )
        // Auth routes
        .route("/v1/auth/me", get(handlers::get_current_user))
        // Company routes
        .route(
            "/v1/companies",
            get(handlers::list_companies).post(handlers::create_company),
        )
        .route(
            "/v1/companies/{id}",
            get(handlers::get_company)
                .put(handlers::update_company)
                .delete(handlers::delete_company),
        )
        .route(
            "/v1/companies/{id}/members",
            get(handlers::list_company_members).post(handlers::add_company_member),
        )
        .route(
            "/v1/companies/{company_id}/members/{user_id}",
            put(handlers::update_member_role).delete(handlers::remove_company_member),
        )
        // App routes
        .route(
            "/v1/companies/{id}/apps",
            get(handlers::list_company_apps).post(handlers::create_app),
        )
        .route(
            "/v1/companies/{company_id}/apps/{app_id}",
            get(handlers::get_app)
                .put(handlers::update_app)
                .delete(handlers::delete_app),
        )
        // Metrics routes
        .route(
            "/v1/companies/{id}/metrics/overview",
            get(handlers::get_metrics_overview),
        )
        .route(
            "/v1/companies/{id}/metrics/time-series",
            get(handlers::get_time_series),
        )
        .route(
            "/v1/companies/{id}/metrics/risk-distribution",
            get(handlers::get_risk_distribution),
        )
        // Actions list
        .route(
            "/v1/companies/{id}/actions",
            get(handlers::list_company_actions),
        )
        // Attacks
        .route("/v1/companies/{id}/attacks", get(handlers::list_attacks))
        // Settings
        .route(
            "/v1/companies/{id}/settings",
            get(handlers::get_company_settings).put(handlers::update_company_settings),
        )
        .layer(middleware::from_fn_with_state(
            jwt_manager.clone(),
            require_jwt,
        ))
        .with_state(state.clone());

    // Token refresh route (requires JWT)
    let token_refresh_routes = Router::new()
        .route("/v1/auth/token/refresh", post(handlers::refresh_token))
        .layer(middleware::from_fn_with_state(
            jwt_manager.clone(),
            require_jwt,
        ))
        .with_state(state.clone());

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/v1/health", get(handlers::health_check))
        .route("/v1/auth/login", post(handlers::login))
        .route("/v1/auth/oauth/sync", post(handlers::oauth_sync))
        .with_state(state.clone());

    Router::new()
        .merge(agent_routes)
        .merge(admin_routes)
        .merge(token_refresh_routes)
        .merge(public_routes)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
}

/// Build router without authentication (for development).
fn build_unauthenticated_router(state: AppState, cors: CorsLayer) -> Router {
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
        // Company routes
        .route(
            "/v1/companies",
            get(handlers::list_companies).post(handlers::create_company),
        )
        .route(
            "/v1/companies/{id}",
            get(handlers::get_company)
                .put(handlers::update_company)
                .delete(handlers::delete_company),
        )
        .route(
            "/v1/companies/{id}/members",
            get(handlers::list_company_members).post(handlers::add_company_member),
        )
        .route(
            "/v1/companies/{company_id}/members/{user_id}",
            put(handlers::update_member_role).delete(handlers::remove_company_member),
        )
        // App routes
        .route(
            "/v1/companies/{id}/apps",
            get(handlers::list_company_apps).post(handlers::create_app),
        )
        .route(
            "/v1/companies/{company_id}/apps/{app_id}",
            get(handlers::get_app)
                .put(handlers::update_app)
                .delete(handlers::delete_app),
        )
        // Metrics routes
        .route(
            "/v1/companies/{id}/metrics/overview",
            get(handlers::get_metrics_overview),
        )
        .route(
            "/v1/companies/{id}/metrics/time-series",
            get(handlers::get_time_series),
        )
        .route(
            "/v1/companies/{id}/metrics/risk-distribution",
            get(handlers::get_risk_distribution),
        )
        // Actions list
        .route(
            "/v1/companies/{id}/actions",
            get(handlers::list_company_actions),
        )
        // Attacks
        .route("/v1/companies/{id}/attacks", get(handlers::list_attacks))
        // Settings
        .route(
            "/v1/companies/{id}/settings",
            get(handlers::get_company_settings).put(handlers::update_company_settings),
        )
        // Health
        .route("/v1/health", get(handlers::health_check))
        // Auth endpoints
        .route("/v1/auth/me", get(handlers::get_current_user))
        .route("/v1/auth/token/refresh", post(handlers::refresh_token))
        .route("/v1/auth/login", post(handlers::login))
        .route("/v1/auth/oauth/sync", post(handlers::oauth_sync))
        .with_state(state)
        // OpenAPI docs
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(cors)
}
