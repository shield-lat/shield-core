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

// ==================== Authentication Endpoints ====================

use crate::domain::{OAuthAccount, OAuthProvider, User, UserRole as DomainUserRole};

/// Login to obtain a JWT token.
///
/// POST /v1/auth/login
#[utoipa::path(
    post,
    path = "/v1/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 401, description = "Invalid credentials")
    ),
    tag = "auth"
)]
pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> ShieldResult<Json<LoginResponse>> {
    // Try database first
    if let Some(db_user) = state.repository.get_user_by_email(&request.email).await? {
        if db_user.verify_password(&request.password) {
            let token = state.jwt_manager.generate_token(
                &db_user.id.to_string(),
                &db_user.email,
                match db_user.role {
                    DomainUserRole::Admin => crate::auth::UserRole::Admin,
                    DomainUserRole::Member => crate::auth::UserRole::Reviewer,
                },
            )?;

            let companies = state
                .repository
                .get_user_companies(&db_user.id.to_string())
                .await?;

            tracing::info!(
                user_id = %db_user.id,
                email = %db_user.email,
                role = ?db_user.role,
                "User logged in (database)"
            );

            return Ok(Json(LoginResponse {
                user: db_user.into(),
                token,
                expires_in: state.jwt_manager.token_duration_hours() * 3600,
                companies,
            }));
        }
    }

    // Fall back to config-based users
    let user = state
        .user_store
        .authenticate(&request.email, &request.password)
        .ok_or_else(|| {
            tracing::warn!(email = %request.email, "Failed login attempt");
            ShieldError::Unauthorized("Invalid email or password".to_string())
        })?;

    let token = state
        .jwt_manager
        .generate_token(&user.id, &user.email, user.role)?;

    tracing::info!(
        user_id = %user.id,
        email = %user.email,
        role = ?user.role,
        "User logged in (config)"
    );

    Ok(Json(LoginResponse {
        user: UserInfoResponse {
            id: Uuid::parse_str(&user.id).unwrap_or_else(|_| Uuid::new_v4()),
            email: user.email.clone(),
            name: None,
            image: None,
            role: match user.role {
                crate::auth::UserRole::Admin => crate::domain::UserRole::Admin,
                _ => crate::domain::UserRole::Member,
            },
            email_verified: true,
            created_at: chrono::Utc::now(),
        },
        token,
        expires_in: state.jwt_manager.token_duration_hours() * 3600,
        companies: vec![],
    }))
}

/// OAuth user sync/provision endpoint.
///
/// When a user signs in via OAuth (Google/GitHub), the frontend calls this
/// to register/sync them with Shield Core.
///
/// POST /v1/auth/oauth/sync
#[utoipa::path(
    post,
    path = "/v1/auth/oauth/sync",
    request_body = OAuthSyncRequest,
    responses(
        (status = 200, description = "User synced/created", body = OAuthSyncResponse),
        (status = 400, description = "Invalid request")
    ),
    tag = "auth"
)]
pub async fn oauth_sync(
    State(state): State<AppState>,
    Json(request): Json<OAuthSyncRequest>,
) -> ShieldResult<Json<OAuthSyncResponse>> {
    let provider: OAuthProvider = request
        .provider
        .parse()
        .map_err(|_| ShieldError::BadRequest(format!("Invalid provider: {}", request.provider)))?;

    tracing::info!(
        provider = %request.provider,
        provider_id = %request.provider_id,
        email = %request.email,
        "OAuth sync request"
    );

    // 1. Look up user by provider + provider_id
    if let Some(user) = state
        .repository
        .find_user_by_oauth(provider, &request.provider_id)
        .await?
    {
        // User exists - generate JWT and return
        let token = state.jwt_manager.generate_token(
            &user.id.to_string(),
            &user.email,
            match user.role {
                DomainUserRole::Admin => crate::auth::UserRole::Admin,
                DomainUserRole::Member => crate::auth::UserRole::Reviewer,
            },
        )?;

        let companies = state
            .repository
            .get_user_companies(&user.id.to_string())
            .await?;

        tracing::info!(
            user_id = %user.id,
            email = %user.email,
            "OAuth sync: existing user"
        );

        return Ok(Json(OAuthSyncResponse {
            user: user.into(),
            token,
            expires_in: state.jwt_manager.token_duration_hours() * 3600,
            is_new_user: false,
            companies,
        }));
    }

    // 2. Check if email is already registered
    if let Some(existing) = state.repository.get_user_by_email(&request.email).await? {
        // Link OAuth to existing account
        let oauth_account = OAuthAccount::new(existing.id, provider, request.provider_id.clone());
        state
            .repository
            .create_oauth_account(&oauth_account)
            .await?;

        let token = state.jwt_manager.generate_token(
            &existing.id.to_string(),
            &existing.email,
            match existing.role {
                DomainUserRole::Admin => crate::auth::UserRole::Admin,
                DomainUserRole::Member => crate::auth::UserRole::Reviewer,
            },
        )?;

        let companies = state
            .repository
            .get_user_companies(&existing.id.to_string())
            .await?;

        tracing::info!(
            user_id = %existing.id,
            email = %existing.email,
            provider = %request.provider,
            "OAuth sync: linked to existing account"
        );

        return Ok(Json(OAuthSyncResponse {
            user: existing.into(),
            token,
            expires_in: state.jwt_manager.token_duration_hours() * 3600,
            is_new_user: false,
            companies,
        }));
    }

    // 3. Create new user
    let new_user = User::new_from_oauth(
        request.email.clone(),
        request.name.clone(),
        request.image.clone(),
        request.email_verified,
    );

    state.repository.create_user(&new_user).await?;

    // Link OAuth account
    let oauth_account = OAuthAccount::new(new_user.id, provider, request.provider_id.clone());
    state
        .repository
        .create_oauth_account(&oauth_account)
        .await?;

    let token = state.jwt_manager.generate_token(
        &new_user.id.to_string(),
        &new_user.email,
        match new_user.role {
            DomainUserRole::Admin => crate::auth::UserRole::Admin,
            DomainUserRole::Member => crate::auth::UserRole::Reviewer,
        },
    )?;

    tracing::info!(
        user_id = %new_user.id,
        email = %new_user.email,
        provider = %request.provider,
        "OAuth sync: created new user"
    );

    Ok(Json(OAuthSyncResponse {
        user: new_user.into(),
        token,
        expires_in: state.jwt_manager.token_duration_hours() * 3600,
        is_new_user: true,
        companies: vec![],
    }))
}

/// Refresh an expiring token.
///
/// POST /v1/auth/token/refresh
#[utoipa::path(
    post,
    path = "/v1/auth/token/refresh",
    responses(
        (status = 200, description = "Token refreshed", body = TokenRefreshResponse),
        (status = 401, description = "Invalid or expired token")
    ),
    security(("bearer_auth" = [])),
    tag = "auth"
)]
pub async fn refresh_token(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
) -> ShieldResult<Json<TokenRefreshResponse>> {
    let token = state
        .jwt_manager
        .generate_token(&claims.sub, &claims.email, claims.role)?;

    tracing::info!(
        user_id = %claims.sub,
        email = %claims.email,
        "Token refreshed"
    );

    Ok(Json(TokenRefreshResponse {
        token,
        expires_in: state.jwt_manager.token_duration_hours() * 3600,
    }))
}

/// Get current user info from JWT token.
///
/// GET /v1/auth/me
#[utoipa::path(
    get,
    path = "/v1/auth/me",
    responses(
        (status = 200, description = "Current user info", body = CurrentUserResponse),
        (status = 401, description = "Not authenticated")
    ),
    security(("bearer_auth" = [])),
    tag = "auth"
)]
pub async fn get_current_user(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
) -> ShieldResult<Json<CurrentUserResponse>> {
    // Try to get user from database
    if let Ok(user_id) = Uuid::parse_str(&claims.sub) {
        if let Ok(user) = state.repository.get_user(user_id).await {
            let companies = state.repository.get_user_companies(&claims.sub).await?;
            return Ok(Json(CurrentUserResponse {
                user: user.into(),
                companies,
            }));
        }
    }

    // Fall back to claims-based response (for config-based users)
    let companies = state
        .repository
        .get_user_companies(&claims.sub)
        .await
        .unwrap_or_default();

    Ok(Json(CurrentUserResponse {
        user: UserInfoResponse {
            id: Uuid::parse_str(&claims.sub).unwrap_or_else(|_| Uuid::new_v4()),
            email: claims.email.clone(),
            name: None,
            image: None,
            role: match claims.role {
                crate::auth::UserRole::Admin => crate::domain::UserRole::Admin,
                _ => crate::domain::UserRole::Member,
            },
            email_verified: true,
            created_at: chrono::Utc::now(),
        },
        companies,
    }))
}

// ==================== Company Endpoints ====================

use crate::domain::{App, Company, CompanyMember, CompanyRole};

/// Create a new company.
///
/// POST /v1/companies
#[utoipa::path(
    post,
    path = "/v1/companies",
    request_body = CreateCompanyRequest,
    responses(
        (status = 201, description = "Company created", body = CompanyResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated")
    ),
    security(("bearer_auth" = [])),
    tag = "companies"
)]
pub async fn create_company(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Json(request): Json<CreateCompanyRequest>,
) -> ShieldResult<(axum::http::StatusCode, Json<CompanyResponse>)> {
    if request.name.trim().is_empty() {
        return Err(ShieldError::BadRequest(
            "Company name is required".to_string(),
        ));
    }

    let slug = Company::slugify(&request.name);

    // Check if slug is already taken
    if state.repository.get_company_by_slug(&slug).await.is_ok() {
        return Err(ShieldError::BadRequest(format!(
            "A company with slug '{}' already exists",
            slug
        )));
    }

    let company = Company::new(request.name, slug, request.description);
    state.repository.create_company(&company).await?;

    // Add the creator as owner
    let member = CompanyMember::new(
        company.id,
        claims.sub.clone(),
        claims.email.clone(),
        CompanyRole::Owner,
    );
    state.repository.add_company_member(&member).await?;

    tracing::info!(
        company_id = %company.id,
        company_name = %company.name,
        owner_id = %claims.sub,
        "Company created"
    );

    Ok((
        axum::http::StatusCode::CREATED,
        Json(CompanyResponse { company }),
    ))
}

/// List companies for the current user.
///
/// GET /v1/companies
#[utoipa::path(
    get,
    path = "/v1/companies",
    responses(
        (status = 200, description = "List of companies", body = ListCompaniesResponse),
        (status = 401, description = "Not authenticated")
    ),
    security(("bearer_auth" = [])),
    tag = "companies"
)]
pub async fn list_companies(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
) -> ShieldResult<Json<ListCompaniesResponse>> {
    let companies = state.repository.list_user_companies(&claims.sub).await?;

    Ok(Json(ListCompaniesResponse { companies }))
}

/// Get a company by ID.
///
/// GET /v1/companies/{id}
#[utoipa::path(
    get,
    path = "/v1/companies/{id}",
    params(("id" = Uuid, Path, description = "Company ID")),
    responses(
        (status = 200, description = "Company details", body = CompanyResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not a member of this company"),
        (status = 404, description = "Company not found")
    ),
    security(("bearer_auth" = [])),
    tag = "companies"
)]
pub async fn get_company(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path(id): Path<Uuid>,
) -> ShieldResult<Json<CompanyResponse>> {
    // Verify user is a member
    let _ = state
        .repository
        .get_company_member(id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    let company = state.repository.get_company(id).await?;

    Ok(Json(CompanyResponse { company }))
}

/// Update a company.
///
/// PUT /v1/companies/{id}
#[utoipa::path(
    put,
    path = "/v1/companies/{id}",
    params(("id" = Uuid, Path, description = "Company ID")),
    request_body = UpdateCompanyRequest,
    responses(
        (status = 200, description = "Company updated", body = CompanyResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "Company not found")
    ),
    security(("bearer_auth" = [])),
    tag = "companies"
)]
pub async fn update_company(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateCompanyRequest>,
) -> ShieldResult<Json<CompanyResponse>> {
    // Verify user has admin/owner role
    let member = state
        .repository
        .get_company_member(id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    if !matches!(member.role, CompanyRole::Owner | CompanyRole::Admin) {
        return Err(ShieldError::Forbidden(
            "Only owners and admins can update company".to_string(),
        ));
    }

    let company = state
        .repository
        .update_company(id, request.name.as_deref(), request.description.as_deref())
        .await?;

    tracing::info!(
        company_id = %id,
        updated_by = %claims.sub,
        "Company updated"
    );

    Ok(Json(CompanyResponse { company }))
}

/// Delete a company.
///
/// DELETE /v1/companies/{id}
#[utoipa::path(
    delete,
    path = "/v1/companies/{id}",
    params(("id" = Uuid, Path, description = "Company ID")),
    responses(
        (status = 204, description = "Company deleted"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "Company not found")
    ),
    security(("bearer_auth" = [])),
    tag = "companies"
)]
pub async fn delete_company(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path(id): Path<Uuid>,
) -> ShieldResult<axum::http::StatusCode> {
    // Only owners can delete
    let member = state
        .repository
        .get_company_member(id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    if member.role != CompanyRole::Owner {
        return Err(ShieldError::Forbidden(
            "Only owners can delete a company".to_string(),
        ));
    }

    state.repository.delete_company(id).await?;

    tracing::info!(
        company_id = %id,
        deleted_by = %claims.sub,
        "Company deleted"
    );

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ==================== Company Member Endpoints ====================

/// List members of a company.
///
/// GET /v1/companies/{id}/members
#[utoipa::path(
    get,
    path = "/v1/companies/{id}/members",
    params(("id" = Uuid, Path, description = "Company ID")),
    responses(
        (status = 200, description = "List of members", body = ListMembersResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not a member of this company"),
        (status = 404, description = "Company not found")
    ),
    security(("bearer_auth" = [])),
    tag = "companies"
)]
pub async fn list_company_members(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path(id): Path<Uuid>,
) -> ShieldResult<Json<ListMembersResponse>> {
    // Verify user is a member
    let _ = state
        .repository
        .get_company_member(id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    let members = state.repository.list_company_members(id).await?;

    Ok(Json(ListMembersResponse { members }))
}

/// Add a member to a company.
///
/// POST /v1/companies/{id}/members
#[utoipa::path(
    post,
    path = "/v1/companies/{id}/members",
    params(("id" = Uuid, Path, description = "Company ID")),
    request_body = AddMemberRequest,
    responses(
        (status = 201, description = "Member added", body = MemberResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "Company not found")
    ),
    security(("bearer_auth" = [])),
    tag = "companies"
)]
pub async fn add_company_member(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path(id): Path<Uuid>,
    Json(request): Json<AddMemberRequest>,
) -> ShieldResult<(axum::http::StatusCode, Json<MemberResponse>)> {
    // Verify user has admin/owner role
    let member = state
        .repository
        .get_company_member(id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    if !matches!(member.role, CompanyRole::Owner | CompanyRole::Admin) {
        return Err(ShieldError::Forbidden(
            "Only owners and admins can add members".to_string(),
        ));
    }

    // Cannot add owner role unless current user is owner
    if request.role == CompanyRole::Owner && member.role != CompanyRole::Owner {
        return Err(ShieldError::Forbidden(
            "Only owners can add other owners".to_string(),
        ));
    }

    let new_member = CompanyMember::new(id, request.user_id, request.email, request.role);
    state.repository.add_company_member(&new_member).await?;

    tracing::info!(
        company_id = %id,
        new_member_id = %new_member.user_id,
        role = %new_member.role,
        added_by = %claims.sub,
        "Member added to company"
    );

    Ok((
        axum::http::StatusCode::CREATED,
        Json(MemberResponse { member: new_member }),
    ))
}

/// Update a member's role.
///
/// PUT /v1/companies/{company_id}/members/{user_id}
#[utoipa::path(
    put,
    path = "/v1/companies/{company_id}/members/{user_id}",
    params(
        ("company_id" = Uuid, Path, description = "Company ID"),
        ("user_id" = String, Path, description = "User ID to update")
    ),
    request_body = UpdateMemberRoleRequest,
    responses(
        (status = 200, description = "Member role updated"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "Member not found")
    ),
    security(("bearer_auth" = [])),
    tag = "companies"
)]
pub async fn update_member_role(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path((company_id, user_id)): Path<(Uuid, String)>,
    Json(request): Json<UpdateMemberRoleRequest>,
) -> ShieldResult<Json<MemberResponse>> {
    // Verify user has owner role (only owners can change roles)
    let member = state
        .repository
        .get_company_member(company_id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    if member.role != CompanyRole::Owner {
        return Err(ShieldError::Forbidden(
            "Only owners can change member roles".to_string(),
        ));
    }

    // Cannot demote yourself as the last owner
    if user_id == claims.sub && request.role != CompanyRole::Owner {
        let members = state.repository.list_company_members(company_id).await?;
        let owner_count = members
            .iter()
            .filter(|m| m.role == CompanyRole::Owner)
            .count();
        if owner_count <= 1 {
            return Err(ShieldError::BadRequest(
                "Cannot demote the last owner. Assign another owner first.".to_string(),
            ));
        }
    }

    state
        .repository
        .update_member_role(company_id, &user_id, request.role)
        .await?;
    let updated_member = state
        .repository
        .get_company_member(company_id, &user_id)
        .await?;

    tracing::info!(
        company_id = %company_id,
        target_user_id = %user_id,
        new_role = %request.role,
        updated_by = %claims.sub,
        "Member role updated"
    );

    Ok(Json(MemberResponse {
        member: updated_member,
    }))
}

/// Remove a member from a company.
///
/// DELETE /v1/companies/{company_id}/members/{user_id}
#[utoipa::path(
    delete,
    path = "/v1/companies/{company_id}/members/{user_id}",
    params(
        ("company_id" = Uuid, Path, description = "Company ID"),
        ("user_id" = String, Path, description = "User ID to remove")
    ),
    responses(
        (status = 204, description = "Member removed"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "Member not found")
    ),
    security(("bearer_auth" = [])),
    tag = "companies"
)]
pub async fn remove_company_member(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path((company_id, user_id)): Path<(Uuid, String)>,
) -> ShieldResult<axum::http::StatusCode> {
    // Verify user has admin/owner role
    let member = state
        .repository
        .get_company_member(company_id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    if !matches!(member.role, CompanyRole::Owner | CompanyRole::Admin) {
        return Err(ShieldError::Forbidden(
            "Only owners and admins can remove members".to_string(),
        ));
    }

    // Get target member to check their role
    let target = state
        .repository
        .get_company_member(company_id, &user_id)
        .await?;

    // Admins cannot remove owners
    if target.role == CompanyRole::Owner && member.role != CompanyRole::Owner {
        return Err(ShieldError::Forbidden(
            "Admins cannot remove owners".to_string(),
        ));
    }

    // Cannot remove yourself if you're the last owner
    if user_id == claims.sub && target.role == CompanyRole::Owner {
        let members = state.repository.list_company_members(company_id).await?;
        let owner_count = members
            .iter()
            .filter(|m| m.role == CompanyRole::Owner)
            .count();
        if owner_count <= 1 {
            return Err(ShieldError::BadRequest(
                "Cannot remove the last owner. Assign another owner first or delete the company."
                    .to_string(),
            ));
        }
    }

    state
        .repository
        .remove_company_member(company_id, &user_id)
        .await?;

    tracing::info!(
        company_id = %company_id,
        removed_user_id = %user_id,
        removed_by = %claims.sub,
        "Member removed from company"
    );

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ==================== App Endpoints ====================

/// List apps for a company.
///
/// GET /v1/companies/{id}/apps
#[utoipa::path(
    get,
    path = "/v1/companies/{id}/apps",
    params(("id" = Uuid, Path, description = "Company ID")),
    responses(
        (status = 200, description = "List of apps", body = ListAppsResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not a member of this company"),
        (status = 404, description = "Company not found")
    ),
    security(("bearer_auth" = [])),
    tag = "apps"
)]
pub async fn list_company_apps(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path(id): Path<Uuid>,
) -> ShieldResult<Json<ListAppsResponse>> {
    // Verify user is a member
    let _ = state
        .repository
        .get_company_member(id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    let apps = state.repository.list_company_apps(id).await?;

    Ok(Json(ListAppsResponse { apps }))
}

/// Create a new app for a company.
///
/// POST /v1/companies/{id}/apps
#[utoipa::path(
    post,
    path = "/v1/companies/{id}/apps",
    params(("id" = Uuid, Path, description = "Company ID")),
    request_body = CreateAppRequest,
    responses(
        (status = 201, description = "App created", body = CreateAppResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "Company not found")
    ),
    security(("bearer_auth" = [])),
    tag = "apps"
)]
pub async fn create_app(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path(id): Path<Uuid>,
    Json(request): Json<CreateAppRequest>,
) -> ShieldResult<(axum::http::StatusCode, Json<CreateAppResponse>)> {
    // Verify user has admin/owner role
    let member = state
        .repository
        .get_company_member(id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    if !matches!(member.role, CompanyRole::Owner | CompanyRole::Admin) {
        return Err(ShieldError::Forbidden(
            "Only owners and admins can create apps".to_string(),
        ));
    }

    if request.name.trim().is_empty() {
        return Err(ShieldError::BadRequest("App name is required".to_string()));
    }

    let app = App::new(id, request.name, request.description, request.rate_limit);
    let api_key = app.api_key.clone().expect("New app should have API key");
    let api_key_hash = App::hash_api_key(&api_key);

    state.repository.create_app(&app, &api_key_hash).await?;

    tracing::info!(
        app_id = %app.id,
        company_id = %id,
        app_name = %app.name,
        created_by = %claims.sub,
        "App created"
    );

    Ok((
        axum::http::StatusCode::CREATED,
        Json(CreateAppResponse {
            app,
            api_key,
            warning: "Save this API key now. It won't be shown again!".to_string(),
        }),
    ))
}

/// Get an app by ID.
///
/// GET /v1/companies/{company_id}/apps/{app_id}
#[utoipa::path(
    get,
    path = "/v1/companies/{company_id}/apps/{app_id}",
    params(
        ("company_id" = Uuid, Path, description = "Company ID"),
        ("app_id" = Uuid, Path, description = "App ID")
    ),
    responses(
        (status = 200, description = "App details", body = AppResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not a member of this company"),
        (status = 404, description = "App not found")
    ),
    security(("bearer_auth" = [])),
    tag = "apps"
)]
pub async fn get_app(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path((company_id, app_id)): Path<(Uuid, Uuid)>,
) -> ShieldResult<Json<AppResponse>> {
    // Verify user is a member
    let _ = state
        .repository
        .get_company_member(company_id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    let app = state.repository.get_app(app_id).await?;

    // Verify app belongs to this company
    if app.company_id != company_id {
        return Err(ShieldError::NotFound(format!(
            "App {} not found in company",
            app_id
        )));
    }

    Ok(Json(AppResponse { app }))
}

/// Update an app.
///
/// PUT /v1/companies/{company_id}/apps/{app_id}
#[utoipa::path(
    put,
    path = "/v1/companies/{company_id}/apps/{app_id}",
    params(
        ("company_id" = Uuid, Path, description = "Company ID"),
        ("app_id" = Uuid, Path, description = "App ID")
    ),
    request_body = UpdateAppRequest,
    responses(
        (status = 200, description = "App updated", body = AppResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "App not found")
    ),
    security(("bearer_auth" = [])),
    tag = "apps"
)]
pub async fn update_app(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path((company_id, app_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateAppRequest>,
) -> ShieldResult<Json<AppResponse>> {
    // Verify user has admin/owner role
    let member = state
        .repository
        .get_company_member(company_id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    if !matches!(member.role, CompanyRole::Owner | CompanyRole::Admin) {
        return Err(ShieldError::Forbidden(
            "Only owners and admins can update apps".to_string(),
        ));
    }

    // Verify app belongs to this company
    let existing = state.repository.get_app(app_id).await?;
    if existing.company_id != company_id {
        return Err(ShieldError::NotFound(format!(
            "App {} not found in company",
            app_id
        )));
    }

    let app = state
        .repository
        .update_app(
            app_id,
            request.name.as_deref(),
            request.description.as_deref(),
            request.status,
            request.rate_limit,
        )
        .await?;

    tracing::info!(
        app_id = %app_id,
        company_id = %company_id,
        updated_by = %claims.sub,
        "App updated"
    );

    Ok(Json(AppResponse { app }))
}

/// Delete an app.
///
/// DELETE /v1/companies/{company_id}/apps/{app_id}
#[utoipa::path(
    delete,
    path = "/v1/companies/{company_id}/apps/{app_id}",
    params(
        ("company_id" = Uuid, Path, description = "Company ID"),
        ("app_id" = Uuid, Path, description = "App ID")
    ),
    responses(
        (status = 204, description = "App deleted"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "App not found")
    ),
    security(("bearer_auth" = [])),
    tag = "apps"
)]
pub async fn delete_app(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path((company_id, app_id)): Path<(Uuid, Uuid)>,
) -> ShieldResult<axum::http::StatusCode> {
    // Verify user has admin/owner role
    let member = state
        .repository
        .get_company_member(company_id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    if !matches!(member.role, CompanyRole::Owner | CompanyRole::Admin) {
        return Err(ShieldError::Forbidden(
            "Only owners and admins can delete apps".to_string(),
        ));
    }

    // Verify app belongs to this company
    let existing = state.repository.get_app(app_id).await?;
    if existing.company_id != company_id {
        return Err(ShieldError::NotFound(format!(
            "App {} not found in company",
            app_id
        )));
    }

    state.repository.delete_app(app_id).await?;

    tracing::info!(
        app_id = %app_id,
        company_id = %company_id,
        deleted_by = %claims.sub,
        "App deleted"
    );

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ==================== Metrics Endpoints ====================

use crate::domain::{AttackOutcome, AttackType, DecisionStatus, Granularity, RiskTier, TimeRange};

/// Get metrics overview for a company.
///
/// GET /v1/companies/{id}/metrics/overview
#[utoipa::path(
    get,
    path = "/v1/companies/{id}/metrics/overview",
    params(
        ("id" = Uuid, Path, description = "Company ID"),
        ("time_range" = Option<String>, Query, description = "Time range: 24h, 7d, 30d, 90d"),
        ("app_id" = Option<Uuid>, Query, description = "Filter by app")
    ),
    responses(
        (status = 200, description = "Metrics overview", body = MetricsOverviewResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not a member"),
        (status = 404, description = "Company not found")
    ),
    security(("bearer_auth" = [])),
    tag = "metrics"
)]
pub async fn get_metrics_overview(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path(id): Path<Uuid>,
    Query(query): Query<MetricsQuery>,
) -> ShieldResult<Json<MetricsOverviewResponse>> {
    // Verify user is a member
    let _ = state
        .repository
        .get_company_member(id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    let time_range = query
        .time_range
        .parse::<TimeRange>()
        .unwrap_or(TimeRange::Last7d);

    let metrics = state
        .repository
        .get_metrics_overview(id, time_range, query.app_id)
        .await?;

    Ok(Json(MetricsOverviewResponse { metrics }))
}

/// Get time series data for a company.
///
/// GET /v1/companies/{id}/metrics/time-series
#[utoipa::path(
    get,
    path = "/v1/companies/{id}/metrics/time-series",
    params(
        ("id" = Uuid, Path, description = "Company ID"),
        ("time_range" = Option<String>, Query, description = "Time range: 24h, 7d, 30d, 90d"),
        ("app_id" = Option<Uuid>, Query, description = "Filter by app"),
        ("granularity" = Option<String>, Query, description = "Granularity: hour, day")
    ),
    responses(
        (status = 200, description = "Time series data", body = TimeSeriesResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not a member")
    ),
    security(("bearer_auth" = [])),
    tag = "metrics"
)]
pub async fn get_time_series(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path(id): Path<Uuid>,
    Query(query): Query<MetricsQuery>,
) -> ShieldResult<Json<TimeSeriesResponse>> {
    let _ = state
        .repository
        .get_company_member(id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    let time_range = query
        .time_range
        .parse::<TimeRange>()
        .unwrap_or(TimeRange::Last7d);

    let data = state
        .repository
        .get_time_series(id, time_range, Granularity::Day, query.app_id)
        .await?;

    Ok(Json(TimeSeriesResponse { data }))
}

/// Get risk distribution for a company.
///
/// GET /v1/companies/{id}/metrics/risk-distribution
#[utoipa::path(
    get,
    path = "/v1/companies/{id}/metrics/risk-distribution",
    params(
        ("id" = Uuid, Path, description = "Company ID"),
        ("time_range" = Option<String>, Query, description = "Time range: 24h, 7d, 30d, 90d"),
        ("app_id" = Option<Uuid>, Query, description = "Filter by app")
    ),
    responses(
        (status = 200, description = "Risk distribution", body = RiskDistributionResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not a member")
    ),
    security(("bearer_auth" = [])),
    tag = "metrics"
)]
pub async fn get_risk_distribution(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path(id): Path<Uuid>,
    Query(query): Query<MetricsQuery>,
) -> ShieldResult<Json<RiskDistributionResponse>> {
    let _ = state
        .repository
        .get_company_member(id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    let time_range = query
        .time_range
        .parse::<TimeRange>()
        .unwrap_or(TimeRange::Last7d);

    let data = state
        .repository
        .get_risk_distribution(id, time_range, query.app_id)
        .await?;

    Ok(Json(RiskDistributionResponse { data }))
}

// ==================== Actions List Endpoints ====================

/// List actions for a company.
///
/// GET /v1/companies/{id}/actions
#[utoipa::path(
    get,
    path = "/v1/companies/{id}/actions",
    params(
        ("id" = Uuid, Path, description = "Company ID"),
        ("app_id" = Option<Uuid>, Query, description = "Filter by app"),
        ("decision" = Option<String>, Query, description = "Filter: allow, require_hitl, block"),
        ("risk_tier" = Option<String>, Query, description = "Filter: low, medium, high, critical"),
        ("user_id" = Option<String>, Query, description = "Filter by user ID"),
        ("search" = Option<String>, Query, description = "Search string"),
        ("time_range" = Option<String>, Query, description = "Time range: 24h, 7d, 30d, 90d"),
        ("limit" = Option<i64>, Query, description = "Max results (default 20)"),
        ("offset" = Option<i64>, Query, description = "Pagination offset")
    ),
    responses(
        (status = 200, description = "List of actions", body = ListActionsResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not a member")
    ),
    security(("bearer_auth" = [])),
    tag = "actions"
)]
pub async fn list_company_actions(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListActionsQuery>,
) -> ShieldResult<Json<ListActionsResponse>> {
    let _ = state
        .repository
        .get_company_member(id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    let decision = query
        .decision
        .as_ref()
        .map(|d| match d.to_lowercase().as_str() {
            "allow" => Ok(DecisionStatus::Allow),
            "require_hitl" => Ok(DecisionStatus::RequireHitl),
            "block" => Ok(DecisionStatus::Block),
            _ => Err(ShieldError::BadRequest(format!("Invalid decision: {}", d))),
        })
        .transpose()?;

    let risk_tier = query
        .risk_tier
        .as_ref()
        .map(|r| r.parse::<RiskTier>())
        .transpose()
        .map_err(|e| ShieldError::BadRequest(e))?;

    let time_range = query
        .time_range
        .as_ref()
        .map(|tr| tr.parse::<TimeRange>())
        .transpose()
        .map_err(|e| ShieldError::BadRequest(e))?;

    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);

    let (rows, total) = state
        .repository
        .list_company_actions(
            id,
            query.app_id,
            decision,
            risk_tier,
            query.user_id.as_deref(),
            query.search.as_deref(),
            time_range,
            limit,
            offset,
        )
        .await?;

    let actions = rows
        .into_iter()
        .map(|r| ActionListItem {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            trace_id: r.trace_id,
            app_id: r.app_id.and_then(|s| Uuid::parse_str(&s).ok()),
            app_name: None, // Could join with apps table
            user_id: r.user_id,
            action_type: r.action_type,
            amount: r.amount,
            currency: r.currency,
            original_intent: r.original_intent,
            decision: r.decision,
            risk_tier: r.risk_tier,
            reasons: serde_json::from_str(&r.reasons).unwrap_or_default(),
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(ListActionsResponse {
        actions,
        total,
        limit,
        offset,
    }))
}

// ==================== Attacks Endpoints ====================

/// List attack events for a company.
///
/// GET /v1/companies/{id}/attacks
#[utoipa::path(
    get,
    path = "/v1/companies/{id}/attacks",
    params(
        ("id" = Uuid, Path, description = "Company ID"),
        ("app_id" = Option<Uuid>, Query, description = "Filter by app"),
        ("attack_type" = Option<String>, Query, description = "Filter by attack type"),
        ("severity" = Option<String>, Query, description = "Filter by severity"),
        ("outcome" = Option<String>, Query, description = "Filter: blocked, escalated, allowed"),
        ("limit" = Option<i64>, Query, description = "Max results"),
        ("offset" = Option<i64>, Query, description = "Pagination offset")
    ),
    responses(
        (status = 200, description = "List of attacks", body = ListAttacksResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not a member")
    ),
    security(("bearer_auth" = [])),
    tag = "attacks"
)]
pub async fn list_attacks(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListAttacksQuery>,
) -> ShieldResult<Json<ListAttacksResponse>> {
    let _ = state
        .repository
        .get_company_member(id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    let attack_type = query
        .attack_type
        .as_ref()
        .map(|t| t.parse::<AttackType>())
        .transpose()
        .map_err(|e| ShieldError::BadRequest(e))?;

    let severity = query
        .severity
        .as_ref()
        .map(|s| s.parse::<RiskTier>())
        .transpose()
        .map_err(|e| ShieldError::BadRequest(e))?;

    let outcome = query
        .outcome
        .as_ref()
        .map(|o| o.parse::<AttackOutcome>())
        .transpose()
        .map_err(|e| ShieldError::BadRequest(e))?;

    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);

    let (attacks, total) = state
        .repository
        .list_attack_events(
            id,
            query.app_id,
            attack_type,
            severity,
            outcome,
            limit,
            offset,
        )
        .await?;

    Ok(Json(ListAttacksResponse { attacks, total }))
}

// ==================== Settings Endpoints ====================

/// Get company settings.
///
/// GET /v1/companies/{id}/settings
#[utoipa::path(
    get,
    path = "/v1/companies/{id}/settings",
    params(("id" = Uuid, Path, description = "Company ID")),
    responses(
        (status = 200, description = "Company settings", body = SettingsResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not a member")
    ),
    security(("bearer_auth" = [])),
    tag = "settings"
)]
pub async fn get_company_settings(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path(id): Path<Uuid>,
) -> ShieldResult<Json<SettingsResponse>> {
    let _ = state
        .repository
        .get_company_member(id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    let settings = state.repository.get_company_settings(id).await?;

    Ok(Json(SettingsResponse { settings }))
}

/// Update company settings.
///
/// PUT /v1/companies/{id}/settings
#[utoipa::path(
    put,
    path = "/v1/companies/{id}/settings",
    params(("id" = Uuid, Path, description = "Company ID")),
    request_body = UpdateSettingsRequest,
    responses(
        (status = 200, description = "Settings updated", body = SettingsResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized")
    ),
    security(("bearer_auth" = [])),
    tag = "settings"
)]
pub async fn update_company_settings(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateSettingsRequest>,
) -> ShieldResult<Json<SettingsResponse>> {
    let member = state
        .repository
        .get_company_member(id, &claims.sub)
        .await
        .map_err(|_| ShieldError::Forbidden("Not a member of this company".to_string()))?;

    if !matches!(member.role, CompanyRole::Owner | CompanyRole::Admin) {
        return Err(ShieldError::Forbidden(
            "Only owners and admins can update settings".to_string(),
        ));
    }

    let settings = state
        .repository
        .update_company_settings(
            id,
            request.logo.as_deref(),
            request.webhook_url.as_deref(),
            request.notification_email.as_deref(),
            request.policy_thresholds.as_ref(),
        )
        .await?;

    tracing::info!(
        company_id = %id,
        updated_by = %claims.sub,
        "Company settings updated"
    );

    Ok(Json(SettingsResponse { settings }))
}
