//! HTTP request handlers.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use uuid::Uuid;

use crate::api::types::*;
use crate::domain::HitlStatus;
use crate::error::{ShieldError, ShieldResult};
use crate::AppState;

/// Evaluate an agent action through the safety pipeline.
///
/// POST /v1/actions/evaluate
#[utoipa::path(
    post,
    path = "/v1/actions/evaluate",
    request_body = EvaluateActionRequest,
    responses(
        (status = 200, description = "Evaluation complete", body = EvaluateActionResponse),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal error")
    ),
    tag = "actions"
)]
pub async fn evaluate_action(
    State(state): State<AppState>,
    Json(request): Json<EvaluateActionRequest>,
) -> ShieldResult<Json<EvaluateActionResponse>> {
    let action = request.action;

    tracing::info!(
        trace_id = %action.trace_id,
        user_id = %action.user_id,
        action_type = %action.action_type,
        "Evaluating action"
    );

    // Run the evaluation pipeline
    let result = state.coordinator.evaluate(&action);

    // Persist action and evaluation
    state.repository.save_action(&action).await?;
    state.repository.save_evaluation(&result.evaluation).await?;

    // Create HITL task if needed
    let hitl_task_id = if let Some(ref task) = result.hitl_task {
        state.repository.save_hitl_task(task).await?;
        Some(task.id)
    } else {
        None
    };

    tracing::info!(
        trace_id = %action.trace_id,
        decision = %result.evaluation.decision,
        risk_tier = %result.evaluation.risk_tier,
        hitl_task_id = ?hitl_task_id,
        "Evaluation complete"
    );

    Ok(Json(EvaluateActionResponse {
        evaluation: result.evaluation,
        hitl_task_id,
    }))
}

/// List HITL tasks with optional filtering.
///
/// GET /v1/hitl/tasks
#[utoipa::path(
    get,
    path = "/v1/hitl/tasks",
    params(
        ("status" = Option<String>, Query, description = "Filter by status: pending, approved, rejected"),
        ("limit" = Option<i64>, Query, description = "Maximum results (default 20)"),
        ("offset" = Option<i64>, Query, description = "Pagination offset")
    ),
    responses(
        (status = 200, description = "List of HITL tasks", body = ListHitlTasksResponse),
        (status = 500, description = "Internal error")
    ),
    tag = "hitl"
)]
pub async fn list_hitl_tasks(
    State(state): State<AppState>,
    Query(query): Query<ListHitlTasksQuery>,
) -> ShieldResult<Json<ListHitlTasksResponse>> {
    let status = query
        .status
        .as_ref()
        .map(|s| s.parse::<HitlStatus>().map_err(ShieldError::BadRequest))
        .transpose()?;

    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);

    let tasks = state
        .repository
        .list_hitl_tasks(status, limit, offset)
        .await?;

    Ok(Json(ListHitlTasksResponse {
        total: tasks.len(),
        tasks,
        limit,
        offset,
    }))
}

/// Get details of a specific HITL task.
///
/// GET /v1/hitl/tasks/{id}
#[utoipa::path(
    get,
    path = "/v1/hitl/tasks/{id}",
    params(
        ("id" = Uuid, Path, description = "Task ID")
    ),
    responses(
        (status = 200, description = "Task details", body = GetHitlTaskResponse),
        (status = 404, description = "Task not found"),
        (status = 500, description = "Internal error")
    ),
    tag = "hitl"
)]
pub async fn get_hitl_task(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ShieldResult<Json<GetHitlTaskResponse>> {
    let details = state.repository.get_hitl_task_details(id).await?;

    Ok(Json(GetHitlTaskResponse { details }))
}

/// Submit a decision for a HITL task.
///
/// POST /v1/hitl/tasks/{id}/decision
#[utoipa::path(
    post,
    path = "/v1/hitl/tasks/{id}/decision",
    params(
        ("id" = Uuid, Path, description = "Task ID")
    ),
    request_body = HitlDecisionRequest,
    responses(
        (status = 200, description = "Decision recorded", body = HitlDecisionResponse),
        (status = 400, description = "Invalid decision"),
        (status = 404, description = "Task not found"),
        (status = 500, description = "Internal error")
    ),
    tag = "hitl"
)]
pub async fn submit_hitl_decision(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<HitlDecisionRequest>,
) -> ShieldResult<Json<HitlDecisionResponse>> {
    // Validate decision
    let status = match request.decision.to_lowercase().as_str() {
        "approve" | "approved" => HitlStatus::Approved,
        "reject" | "rejected" => HitlStatus::Rejected,
        _ => {
            return Err(ShieldError::BadRequest(format!(
                "Invalid decision '{}'. Must be 'approve' or 'reject'",
                request.decision
            )))
        }
    };

    // Verify task exists and is pending
    let existing = state.repository.get_hitl_task(id).await?;
    if existing.status != HitlStatus::Pending {
        return Err(ShieldError::BadRequest(format!(
            "Task {} is already {}",
            id, existing.status
        )));
    }

    // Update the task
    let updated = state
        .repository
        .update_hitl_task(id, status, &request.reviewer_id, request.notes.as_deref())
        .await?;

    tracing::info!(
        task_id = %id,
        decision = %status,
        reviewer_id = %request.reviewer_id,
        "HITL decision recorded"
    );

    Ok(Json(HitlDecisionResponse {
        task_id: id,
        status: updated.status,
        message: format!("Task {} has been {}", id, status),
    }))
}

/// Health check endpoint.
///
/// GET /v1/health
#[utoipa::path(
    get,
    path = "/v1/health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse)
    ),
    tag = "health"
)]
pub async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    // Check database connectivity
    let db_status = match sqlx::query("SELECT 1")
        .fetch_one(state.repository.pool())
        .await
    {
        Ok(_) => "connected".to_string(),
        Err(e) => format!("error: {}", e),
    };

    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        database: db_status,
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}
