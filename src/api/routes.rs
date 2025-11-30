//! Route definitions for the API.

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::api::handlers;
use crate::AppState;

/// OpenAPI documentation.
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::evaluate_action,
        handlers::list_hitl_tasks,
        handlers::get_hitl_task,
        handlers::submit_hitl_decision,
        handlers::health_check,
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
    tags(
        (name = "actions", description = "Action evaluation endpoints"),
        (name = "hitl", description = "Human-in-the-loop task management"),
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

/// Build the API router.
pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

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
        // OpenAPI docs
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

