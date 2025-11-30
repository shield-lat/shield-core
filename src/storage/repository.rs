//! Repository layer for database operations.

use chrono::{DateTime, Utc};
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

use crate::domain::{
    AgentAction, App, AppStatus, AttackEvent, AttackOutcome, AttackType, Company, CompanyMember,
    CompanyRole, CompanySettings, DecisionStatus, EvaluationResult, Granularity, HitlStatus,
    HitlTask, HitlTaskDetails, HitlTaskSummary, MetricsOverview, OAuthAccount, OAuthProvider,
    PolicyThresholds, RiskDistribution, RiskDistributionPoint, RiskTier, TimeRange, TimeSeriesData,
    TimeSeriesPoint, Trends, User, UserCompanyMembership,
};
use crate::error::{ShieldError, ShieldResult};
use crate::storage::models::{
    ActionListRow, AgentActionRow, AppRow, AttackEventRow, CompanyMemberRow, CompanyRow,
    CompanySettingsRow, EvaluationRow, HitlTaskRow, HitlTaskSummaryRow, OAuthAccountRow, UserRow,
};

/// Repository for all Shield database operations.
#[derive(Clone)]
pub struct ShieldRepository {
    pool: SqlitePool,
}

impl ShieldRepository {
    /// Get a reference to the underlying pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

impl ShieldRepository {
    /// Create a new repository with the given connection pool.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Initialize the database schema.
    pub async fn init_schema(&self) -> ShieldResult<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS agent_actions (
                id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                app_id TEXT,
                company_id TEXT,
                user_id TEXT NOT NULL,
                channel TEXT NOT NULL,
                model_name TEXT NOT NULL,
                original_intent TEXT NOT NULL,
                action_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                cot_trace TEXT,
                metadata TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_agent_actions_user_id ON agent_actions(user_id);
            CREATE INDEX IF NOT EXISTS idx_agent_actions_trace_id ON agent_actions(trace_id);
            CREATE INDEX IF NOT EXISTS idx_agent_actions_app_id ON agent_actions(app_id);
            CREATE INDEX IF NOT EXISTS idx_agent_actions_company_id ON agent_actions(company_id);
            CREATE INDEX IF NOT EXISTS idx_agent_actions_created_at ON agent_actions(created_at);
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS evaluations (
                id TEXT PRIMARY KEY,
                agent_action_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_tier TEXT NOT NULL,
                reasons TEXT NOT NULL,
                rule_hits TEXT NOT NULL,
                neural_signals TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (agent_action_id) REFERENCES agent_actions(id)
            );

            CREATE INDEX IF NOT EXISTS idx_evaluations_action_id ON evaluations(agent_action_id);
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS hitl_tasks (
                id TEXT PRIMARY KEY,
                agent_action_id TEXT NOT NULL,
                evaluation_id TEXT NOT NULL,
                status TEXT NOT NULL,
                reviewer_id TEXT,
                reviewed_at TEXT,
                review_notes TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (agent_action_id) REFERENCES agent_actions(id),
                FOREIGN KEY (evaluation_id) REFERENCES evaluations(id)
            );

            CREATE INDEX IF NOT EXISTS idx_hitl_tasks_status ON hitl_tasks(status);
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Company tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS companies (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                slug TEXT NOT NULL UNIQUE,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_companies_slug ON companies(slug);
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS company_members (
                id TEXT PRIMARY KEY,
                company_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE,
                UNIQUE(company_id, user_id)
            );

            CREATE INDEX IF NOT EXISTS idx_company_members_company ON company_members(company_id);
            CREATE INDEX IF NOT EXISTS idx_company_members_user ON company_members(user_id);
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS apps (
                id TEXT PRIMARY KEY,
                company_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                api_key_hash TEXT NOT NULL UNIQUE,
                api_key_prefix TEXT NOT NULL,
                status TEXT NOT NULL,
                rate_limit INTEGER NOT NULL DEFAULT 100,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_used_at TEXT,
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_apps_company ON apps(company_id);
            CREATE INDEX IF NOT EXISTS idx_apps_api_key_hash ON apps(api_key_hash);
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Attack events table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS attack_events (
                id TEXT PRIMARY KEY,
                company_id TEXT NOT NULL,
                app_id TEXT,
                agent_action_id TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                blocked INTEGER NOT NULL DEFAULT 0,
                outcome TEXT NOT NULL,
                user_id TEXT NOT NULL,
                description TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE,
                FOREIGN KEY (agent_action_id) REFERENCES agent_actions(id)
            );

            CREATE INDEX IF NOT EXISTS idx_attack_events_company ON attack_events(company_id);
            CREATE INDEX IF NOT EXISTS idx_attack_events_app ON attack_events(app_id);
            CREATE INDEX IF NOT EXISTS idx_attack_events_created_at ON attack_events(created_at);
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Company settings table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS company_settings (
                company_id TEXT PRIMARY KEY,
                logo TEXT,
                webhook_url TEXT,
                notification_email TEXT,
                max_auto_approve_amount REAL NOT NULL DEFAULT 100.0,
                hitl_threshold_amount REAL NOT NULL DEFAULT 1000.0,
                velocity_limit_per_hour INTEGER NOT NULL DEFAULT 10,
                velocity_limit_per_day INTEGER NOT NULL DEFAULT 50,
                block_high_risk_actions INTEGER NOT NULL DEFAULT 1,
                require_hitl_for_new_beneficiaries INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Users table (for OAuth and password auth)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                name TEXT,
                image TEXT,
                role TEXT NOT NULL DEFAULT 'member',
                email_verified INTEGER NOT NULL DEFAULT 0,
                password_hash TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            "#,
        )
        .execute(&self.pool)
        .await?;

        // OAuth accounts table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS oauth_accounts (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                provider_account_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(provider, provider_account_id)
            );

            CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id ON oauth_accounts(user_id);
            CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider ON oauth_accounts(provider, provider_account_id);
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ==================== Agent Actions ====================

    /// Save an agent action to the database.
    pub async fn save_action(&self, action: &AgentAction) -> ShieldResult<()> {
        sqlx::query(
            r#"
            INSERT INTO agent_actions (
                id, trace_id, app_id, user_id, channel, model_name,
                original_intent, action_type, payload, cot_trace, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(action.id.to_string())
        .bind(&action.trace_id)
        .bind(action.app_id.map(|id| id.to_string()))
        .bind(&action.user_id)
        .bind(&action.channel)
        .bind(&action.model_name)
        .bind(&action.original_intent)
        .bind(action.action_type.to_string())
        .bind(serde_json::to_string(&action.payload)?)
        .bind(&action.cot_trace)
        .bind(
            action
                .metadata
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
        )
        .bind(action.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Save an agent action with company context.
    pub async fn save_action_with_company(
        &self,
        action: &AgentAction,
        company_id: Uuid,
    ) -> ShieldResult<()> {
        sqlx::query(
            r#"
            INSERT INTO agent_actions (
                id, trace_id, app_id, company_id, user_id, channel, model_name,
                original_intent, action_type, payload, cot_trace, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(action.id.to_string())
        .bind(&action.trace_id)
        .bind(action.app_id.map(|id| id.to_string()))
        .bind(company_id.to_string())
        .bind(&action.user_id)
        .bind(&action.channel)
        .bind(&action.model_name)
        .bind(&action.original_intent)
        .bind(action.action_type.to_string())
        .bind(serde_json::to_string(&action.payload)?)
        .bind(&action.cot_trace)
        .bind(
            action
                .metadata
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
        )
        .bind(action.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get an agent action by ID.
    pub async fn get_action(&self, id: Uuid) -> ShieldResult<AgentAction> {
        let row: AgentActionRow = sqlx::query_as("SELECT * FROM agent_actions WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| ShieldError::NotFound(format!("Action {} not found", id)))?;

        row.try_into()
    }

    // ==================== Evaluations ====================

    /// Save an evaluation result to the database.
    pub async fn save_evaluation(&self, eval: &EvaluationResult) -> ShieldResult<()> {
        sqlx::query(
            r#"
            INSERT INTO evaluations (
                id, agent_action_id, decision, risk_tier,
                reasons, rule_hits, neural_signals, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(eval.id.to_string())
        .bind(eval.agent_action_id.to_string())
        .bind(eval.decision.to_string())
        .bind(eval.risk_tier.to_string())
        .bind(serde_json::to_string(&eval.reasons)?)
        .bind(serde_json::to_string(&eval.rule_hits)?)
        .bind(serde_json::to_string(&eval.neural_signals)?)
        .bind(eval.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get an evaluation by ID.
    pub async fn get_evaluation(&self, id: Uuid) -> ShieldResult<EvaluationResult> {
        let row: EvaluationRow = sqlx::query_as("SELECT * FROM evaluations WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| ShieldError::NotFound(format!("Evaluation {} not found", id)))?;

        row.try_into()
    }

    // ==================== HITL Tasks ====================

    /// Save a HITL task to the database.
    pub async fn save_hitl_task(&self, task: &HitlTask) -> ShieldResult<()> {
        sqlx::query(
            r#"
            INSERT INTO hitl_tasks (
                id, agent_action_id, evaluation_id, status,
                reviewer_id, reviewed_at, review_notes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(task.id.to_string())
        .bind(task.agent_action_id.to_string())
        .bind(task.evaluation_id.to_string())
        .bind(task.status.to_string())
        .bind(&task.reviewer_id)
        .bind(task.reviewed_at.map(|dt| dt.to_rfc3339()))
        .bind(&task.review_notes)
        .bind(task.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get a HITL task by ID.
    pub async fn get_hitl_task(&self, id: Uuid) -> ShieldResult<HitlTask> {
        let row: HitlTaskRow = sqlx::query_as("SELECT * FROM hitl_tasks WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| ShieldError::NotFound(format!("HITL task {} not found", id)))?;

        row.try_into()
    }

    /// Get full HITL task details including action and evaluation.
    pub async fn get_hitl_task_details(&self, id: Uuid) -> ShieldResult<HitlTaskDetails> {
        let task = self.get_hitl_task(id).await?;
        let agent_action = self.get_action(task.agent_action_id).await?;
        let evaluation = self.get_evaluation(task.evaluation_id).await?;

        Ok(HitlTaskDetails {
            task,
            agent_action,
            evaluation,
        })
    }

    /// Update a HITL task's status and review info.
    pub async fn update_hitl_task(
        &self,
        id: Uuid,
        status: HitlStatus,
        reviewer_id: &str,
        notes: Option<&str>,
    ) -> ShieldResult<HitlTask> {
        let reviewed_at = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            UPDATE hitl_tasks
            SET status = ?, reviewer_id = ?, reviewed_at = ?, review_notes = ?
            WHERE id = ?
            "#,
        )
        .bind(status.to_string())
        .bind(reviewer_id)
        .bind(&reviewed_at)
        .bind(notes)
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;

        self.get_hitl_task(id).await
    }

    /// List HITL tasks with optional status filter and pagination.
    pub async fn list_hitl_tasks(
        &self,
        status: Option<HitlStatus>,
        limit: i64,
        offset: i64,
    ) -> ShieldResult<Vec<HitlTaskSummary>> {
        let query = if status.is_some() {
            r#"
            SELECT
                t.id,
                a.user_id,
                a.action_type,
                json_extract(a.payload, '$.amount') as amount,
                e.risk_tier,
                t.status,
                t.created_at
            FROM hitl_tasks t
            JOIN agent_actions a ON t.agent_action_id = a.id
            JOIN evaluations e ON t.evaluation_id = e.id
            WHERE t.status = ?
            ORDER BY t.created_at DESC
            LIMIT ? OFFSET ?
            "#
        } else {
            r#"
            SELECT
                t.id,
                a.user_id,
                a.action_type,
                json_extract(a.payload, '$.amount') as amount,
                e.risk_tier,
                t.status,
                t.created_at
            FROM hitl_tasks t
            JOIN agent_actions a ON t.agent_action_id = a.id
            JOIN evaluations e ON t.evaluation_id = e.id
            ORDER BY t.created_at DESC
            LIMIT ? OFFSET ?
            "#
        };

        let rows: Vec<HitlTaskSummaryRow> = if let Some(s) = status {
            sqlx::query_as(query)
                .bind(s.to_string())
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
        } else {
            sqlx::query_as(query)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
        };

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    // ==================== Companies ====================

    /// Create a new company.
    pub async fn create_company(&self, company: &Company) -> ShieldResult<()> {
        sqlx::query(
            r#"
            INSERT INTO companies (id, name, slug, description, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(company.id.to_string())
        .bind(&company.name)
        .bind(&company.slug)
        .bind(&company.description)
        .bind(company.created_at.to_rfc3339())
        .bind(company.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get a company by ID.
    pub async fn get_company(&self, id: Uuid) -> ShieldResult<Company> {
        let row: CompanyRow = sqlx::query_as("SELECT * FROM companies WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| ShieldError::NotFound(format!("Company {} not found", id)))?;

        row.try_into()
    }

    /// Get a company by slug.
    pub async fn get_company_by_slug(&self, slug: &str) -> ShieldResult<Company> {
        let row: CompanyRow = sqlx::query_as("SELECT * FROM companies WHERE slug = ?")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| ShieldError::NotFound(format!("Company '{}' not found", slug)))?;

        row.try_into()
    }

    /// Update a company.
    pub async fn update_company(
        &self,
        id: Uuid,
        name: Option<&str>,
        description: Option<&str>,
    ) -> ShieldResult<Company> {
        let updated_at = chrono::Utc::now().to_rfc3339();

        if let Some(name) = name {
            let slug = Company::slugify(name);
            sqlx::query("UPDATE companies SET name = ?, slug = ?, updated_at = ? WHERE id = ?")
                .bind(name)
                .bind(&slug)
                .bind(&updated_at)
                .bind(id.to_string())
                .execute(&self.pool)
                .await?;
        }

        if let Some(desc) = description {
            sqlx::query("UPDATE companies SET description = ?, updated_at = ? WHERE id = ?")
                .bind(desc)
                .bind(&updated_at)
                .bind(id.to_string())
                .execute(&self.pool)
                .await?;
        }

        self.get_company(id).await
    }

    /// Delete a company.
    pub async fn delete_company(&self, id: Uuid) -> ShieldResult<()> {
        let result = sqlx::query("DELETE FROM companies WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(ShieldError::NotFound(format!("Company {} not found", id)));
        }

        Ok(())
    }

    /// List companies for a user.
    pub async fn list_user_companies(&self, user_id: &str) -> ShieldResult<Vec<Company>> {
        let rows: Vec<CompanyRow> = sqlx::query_as(
            r#"
            SELECT c.* FROM companies c
            JOIN company_members m ON c.id = m.company_id
            WHERE m.user_id = ?
            ORDER BY c.name ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    // ==================== Company Members ====================

    /// Add a member to a company.
    pub async fn add_company_member(&self, member: &CompanyMember) -> ShieldResult<()> {
        sqlx::query(
            r#"
            INSERT INTO company_members (id, company_id, user_id, email, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(member.id.to_string())
        .bind(member.company_id.to_string())
        .bind(&member.user_id)
        .bind(&member.email)
        .bind(member.role.to_string())
        .bind(member.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get company members.
    pub async fn list_company_members(&self, company_id: Uuid) -> ShieldResult<Vec<CompanyMember>> {
        let rows: Vec<CompanyMemberRow> = sqlx::query_as(
            "SELECT * FROM company_members WHERE company_id = ? ORDER BY created_at ASC",
        )
        .bind(company_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    /// Get a user's membership in a company.
    pub async fn get_company_member(
        &self,
        company_id: Uuid,
        user_id: &str,
    ) -> ShieldResult<CompanyMember> {
        let row: CompanyMemberRow =
            sqlx::query_as("SELECT * FROM company_members WHERE company_id = ? AND user_id = ?")
                .bind(company_id.to_string())
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| ShieldError::NotFound("Member not found".to_string()))?;

        row.try_into()
    }

    /// Update a member's role.
    pub async fn update_member_role(
        &self,
        company_id: Uuid,
        user_id: &str,
        role: CompanyRole,
    ) -> ShieldResult<()> {
        let result =
            sqlx::query("UPDATE company_members SET role = ? WHERE company_id = ? AND user_id = ?")
                .bind(role.to_string())
                .bind(company_id.to_string())
                .bind(user_id)
                .execute(&self.pool)
                .await?;

        if result.rows_affected() == 0 {
            return Err(ShieldError::NotFound("Member not found".to_string()));
        }

        Ok(())
    }

    /// Remove a member from a company.
    pub async fn remove_company_member(&self, company_id: Uuid, user_id: &str) -> ShieldResult<()> {
        let result =
            sqlx::query("DELETE FROM company_members WHERE company_id = ? AND user_id = ?")
                .bind(company_id.to_string())
                .bind(user_id)
                .execute(&self.pool)
                .await?;

        if result.rows_affected() == 0 {
            return Err(ShieldError::NotFound("Member not found".to_string()));
        }

        Ok(())
    }

    // ==================== Apps ====================

    /// Create a new app.
    pub async fn create_app(&self, app: &App, api_key_hash: &str) -> ShieldResult<()> {
        sqlx::query(
            r#"
            INSERT INTO apps (
                id, company_id, name, description, api_key_hash, api_key_prefix,
                status, rate_limit, created_at, updated_at, last_used_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(app.id.to_string())
        .bind(app.company_id.to_string())
        .bind(&app.name)
        .bind(&app.description)
        .bind(api_key_hash)
        .bind(&app.api_key_prefix)
        .bind(app.status.to_string())
        .bind(app.rate_limit as i64)
        .bind(app.created_at.to_rfc3339())
        .bind(app.updated_at.to_rfc3339())
        .bind(app.last_used_at.map(|dt| dt.to_rfc3339()))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get an app by ID.
    pub async fn get_app(&self, id: Uuid) -> ShieldResult<App> {
        let row: AppRow = sqlx::query_as("SELECT * FROM apps WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| ShieldError::NotFound(format!("App {} not found", id)))?;

        row.try_into()
    }

    /// Get an app by API key hash.
    pub async fn get_app_by_api_key_hash(&self, api_key_hash: &str) -> ShieldResult<App> {
        let row: AppRow = sqlx::query_as("SELECT * FROM apps WHERE api_key_hash = ?")
            .bind(api_key_hash)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| ShieldError::NotFound("Invalid API key".to_string()))?;

        row.try_into()
    }

    /// List apps for a company.
    pub async fn list_company_apps(&self, company_id: Uuid) -> ShieldResult<Vec<App>> {
        let rows: Vec<AppRow> =
            sqlx::query_as("SELECT * FROM apps WHERE company_id = ? ORDER BY created_at DESC")
                .bind(company_id.to_string())
                .fetch_all(&self.pool)
                .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    /// Update an app.
    pub async fn update_app(
        &self,
        id: Uuid,
        name: Option<&str>,
        description: Option<&str>,
        status: Option<AppStatus>,
        rate_limit: Option<u32>,
    ) -> ShieldResult<App> {
        let updated_at = chrono::Utc::now().to_rfc3339();

        if let Some(name) = name {
            sqlx::query("UPDATE apps SET name = ?, updated_at = ? WHERE id = ?")
                .bind(name)
                .bind(&updated_at)
                .bind(id.to_string())
                .execute(&self.pool)
                .await?;
        }

        if let Some(desc) = description {
            sqlx::query("UPDATE apps SET description = ?, updated_at = ? WHERE id = ?")
                .bind(desc)
                .bind(&updated_at)
                .bind(id.to_string())
                .execute(&self.pool)
                .await?;
        }

        if let Some(status) = status {
            sqlx::query("UPDATE apps SET status = ?, updated_at = ? WHERE id = ?")
                .bind(status.to_string())
                .bind(&updated_at)
                .bind(id.to_string())
                .execute(&self.pool)
                .await?;
        }

        if let Some(rate_limit) = rate_limit {
            sqlx::query("UPDATE apps SET rate_limit = ?, updated_at = ? WHERE id = ?")
                .bind(rate_limit as i64)
                .bind(&updated_at)
                .bind(id.to_string())
                .execute(&self.pool)
                .await?;
        }

        self.get_app(id).await
    }

    /// Update app's last used timestamp.
    pub async fn update_app_last_used(&self, id: Uuid) -> ShieldResult<()> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("UPDATE apps SET last_used_at = ? WHERE id = ?")
            .bind(&now)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Delete an app.
    pub async fn delete_app(&self, id: Uuid) -> ShieldResult<()> {
        let result = sqlx::query("DELETE FROM apps WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(ShieldError::NotFound(format!("App {} not found", id)));
        }

        Ok(())
    }

    // ==================== Metrics ====================

    /// Get metrics overview for a company.
    pub async fn get_metrics_overview(
        &self,
        company_id: Uuid,
        time_range: TimeRange,
        app_id: Option<Uuid>,
    ) -> ShieldResult<MetricsOverview> {
        let start_time = time_range.start_time().to_rfc3339();
        let prev_start =
            (time_range.start_time() - chrono::Duration::hours(time_range.hours())).to_rfc3339();

        // Current period counts
        let (total, blocked, escalated): (i64, i64, i64) = if let Some(app_id) = app_id {
            sqlx::query_as(
                r#"
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN e.decision = 'block' THEN 1 ELSE 0 END) as blocked,
                    SUM(CASE WHEN e.decision = 'require_hitl' THEN 1 ELSE 0 END) as escalated
                FROM agent_actions a
                JOIN evaluations e ON a.id = e.agent_action_id
                WHERE a.company_id = ? AND a.app_id = ? AND a.created_at >= ?
                "#,
            )
            .bind(company_id.to_string())
            .bind(app_id.to_string())
            .bind(&start_time)
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                r#"
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN e.decision = 'block' THEN 1 ELSE 0 END) as blocked,
                    SUM(CASE WHEN e.decision = 'require_hitl' THEN 1 ELSE 0 END) as escalated
                FROM agent_actions a
                JOIN evaluations e ON a.id = e.agent_action_id
                WHERE a.company_id = ? AND a.created_at >= ?
                "#,
            )
            .bind(company_id.to_string())
            .bind(&start_time)
            .fetch_one(&self.pool)
            .await?
        };

        // Attack counts
        let attack_stats: (i64, i64) = if let Some(app_id) = app_id {
            sqlx::query_as(
                r#"
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN outcome = 'allowed' THEN 1 ELSE 0 END) as successful
                FROM attack_events
                WHERE company_id = ? AND app_id = ? AND created_at >= ?
                "#,
            )
            .bind(company_id.to_string())
            .bind(app_id.to_string())
            .bind(&start_time)
            .fetch_one(&self.pool)
            .await
            .unwrap_or((0, 0))
        } else {
            sqlx::query_as(
                r#"
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN outcome = 'allowed' THEN 1 ELSE 0 END) as successful
                FROM attack_events
                WHERE company_id = ? AND created_at >= ?
                "#,
            )
            .bind(company_id.to_string())
            .bind(&start_time)
            .fetch_one(&self.pool)
            .await
            .unwrap_or((0, 0))
        };

        // Unique users impacted
        let (users_impacted,): (i64,) = if let Some(app_id) = app_id {
            sqlx::query_as(
                r#"
                SELECT COUNT(DISTINCT user_id)
                FROM agent_actions
                WHERE company_id = ? AND app_id = ? AND created_at >= ?
                "#,
            )
            .bind(company_id.to_string())
            .bind(app_id.to_string())
            .bind(&start_time)
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                r#"
                SELECT COUNT(DISTINCT user_id)
                FROM agent_actions
                WHERE company_id = ? AND created_at >= ?
                "#,
            )
            .bind(company_id.to_string())
            .bind(&start_time)
            .fetch_one(&self.pool)
            .await?
        };

        // Previous period for trends
        let (prev_total, prev_blocked, prev_escalated): (i64, i64, i64) = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN e.decision = 'block' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN e.decision = 'require_hitl' THEN 1 ELSE 0 END) as escalated
            FROM agent_actions a
            JOIN evaluations e ON a.id = e.agent_action_id
            WHERE a.company_id = ? AND a.created_at >= ? AND a.created_at < ?
            "#,
        )
        .bind(company_id.to_string())
        .bind(&prev_start)
        .bind(&start_time)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0, 0, 0));

        let (prev_attacks,): (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM attack_events
            WHERE company_id = ? AND created_at >= ? AND created_at < ?
            "#,
        )
        .bind(company_id.to_string())
        .bind(&prev_start)
        .bind(&start_time)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        fn calc_trend(current: i64, previous: i64) -> f64 {
            if previous == 0 {
                if current > 0 {
                    100.0
                } else {
                    0.0
                }
            } else {
                ((current - previous) as f64 / previous as f64) * 100.0
            }
        }

        let attack_success_rate = if attack_stats.0 > 0 {
            (attack_stats.1 as f64 / attack_stats.0 as f64) * 100.0
        } else {
            0.0
        };

        Ok(MetricsOverview {
            total_actions: total,
            blocked_actions: blocked,
            escalated_actions: escalated,
            attack_attempts: attack_stats.0,
            attack_success_rate,
            users_impacted,
            trends: Trends {
                total_actions: calc_trend(total, prev_total),
                blocked_actions: calc_trend(blocked, prev_blocked),
                escalated_actions: calc_trend(escalated, prev_escalated),
                attack_attempts: calc_trend(attack_stats.0, prev_attacks),
            },
        })
    }

    /// Get time series data for a company.
    pub async fn get_time_series(
        &self,
        company_id: Uuid,
        time_range: TimeRange,
        _granularity: Granularity,
        app_id: Option<Uuid>,
    ) -> ShieldResult<TimeSeriesData> {
        let start_time = time_range.start_time().to_rfc3339();

        // For simplicity, group by date
        let rows: Vec<(String, i64, i64, i64)> = if let Some(app_id) = app_id {
            sqlx::query_as(
                r#"
                SELECT
                    DATE(a.created_at) as date,
                    SUM(CASE WHEN e.decision = 'allow' THEN 1 ELSE 0 END) as allowed,
                    SUM(CASE WHEN e.decision = 'require_hitl' THEN 1 ELSE 0 END) as hitl,
                    SUM(CASE WHEN e.decision = 'block' THEN 1 ELSE 0 END) as blocked
                FROM agent_actions a
                JOIN evaluations e ON a.id = e.agent_action_id
                WHERE a.company_id = ? AND a.app_id = ? AND a.created_at >= ?
                GROUP BY DATE(a.created_at)
                ORDER BY date ASC
                "#,
            )
            .bind(company_id.to_string())
            .bind(app_id.to_string())
            .bind(&start_time)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                r#"
                SELECT
                    DATE(a.created_at) as date,
                    SUM(CASE WHEN e.decision = 'allow' THEN 1 ELSE 0 END) as allowed,
                    SUM(CASE WHEN e.decision = 'require_hitl' THEN 1 ELSE 0 END) as hitl,
                    SUM(CASE WHEN e.decision = 'block' THEN 1 ELSE 0 END) as blocked
                FROM agent_actions a
                JOIN evaluations e ON a.id = e.agent_action_id
                WHERE a.company_id = ? AND a.created_at >= ?
                GROUP BY DATE(a.created_at)
                ORDER BY date ASC
                "#,
            )
            .bind(company_id.to_string())
            .bind(&start_time)
            .fetch_all(&self.pool)
            .await?
        };

        let data = rows
            .into_iter()
            .filter_map(|(date, allowed, hitl, blocked)| {
                DateTime::parse_from_rfc3339(&format!("{}T00:00:00Z", date))
                    .ok()
                    .map(|ts| TimeSeriesPoint {
                        timestamp: ts.with_timezone(&Utc),
                        allowed,
                        hitl,
                        blocked,
                    })
            })
            .collect();

        Ok(TimeSeriesData { data })
    }

    /// Get risk distribution for a company.
    pub async fn get_risk_distribution(
        &self,
        company_id: Uuid,
        time_range: TimeRange,
        app_id: Option<Uuid>,
    ) -> ShieldResult<RiskDistribution> {
        let start_time = time_range.start_time().to_rfc3339();

        let rows: Vec<(String, i64)> = if let Some(app_id) = app_id {
            sqlx::query_as(
                r#"
                SELECT e.risk_tier, COUNT(*) as count
                FROM evaluations e
                JOIN agent_actions a ON e.agent_action_id = a.id
                WHERE a.company_id = ? AND a.app_id = ? AND a.created_at >= ?
                GROUP BY e.risk_tier
                "#,
            )
            .bind(company_id.to_string())
            .bind(app_id.to_string())
            .bind(&start_time)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                r#"
                SELECT e.risk_tier, COUNT(*) as count
                FROM evaluations e
                JOIN agent_actions a ON e.agent_action_id = a.id
                WHERE a.company_id = ? AND a.created_at >= ?
                GROUP BY e.risk_tier
                "#,
            )
            .bind(company_id.to_string())
            .bind(&start_time)
            .fetch_all(&self.pool)
            .await?
        };

        let total: i64 = rows.iter().map(|(_, c)| c).sum();
        let data = rows
            .into_iter()
            .map(|(tier, count)| RiskDistributionPoint {
                tier,
                count,
                percentage: if total > 0 {
                    (count as f64 / total as f64) * 100.0
                } else {
                    0.0
                },
            })
            .collect();

        Ok(RiskDistribution { data })
    }

    // ==================== Actions List ====================

    /// List actions for a company with filtering.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_company_actions(
        &self,
        company_id: Uuid,
        app_id: Option<Uuid>,
        decision: Option<DecisionStatus>,
        risk_tier: Option<RiskTier>,
        user_id: Option<&str>,
        search: Option<&str>,
        time_range: Option<TimeRange>,
        limit: i64,
        offset: i64,
    ) -> ShieldResult<(Vec<ActionListRow>, i64)> {
        let mut conditions = vec!["a.company_id = ?".to_string()];
        let start_time = time_range.map(|tr| tr.start_time().to_rfc3339());

        if app_id.is_some() {
            conditions.push("a.app_id = ?".to_string());
        }
        if decision.is_some() {
            conditions.push("e.decision = ?".to_string());
        }
        if risk_tier.is_some() {
            conditions.push("e.risk_tier = ?".to_string());
        }
        if user_id.is_some() {
            conditions.push("a.user_id = ?".to_string());
        }
        if search.is_some() {
            conditions.push(
                "(a.user_id LIKE ? OR a.trace_id LIKE ? OR a.action_type LIKE ?)".to_string(),
            );
        }
        if start_time.is_some() {
            conditions.push("a.created_at >= ?".to_string());
        }

        let where_clause = conditions.join(" AND ");

        let query = format!(
            r#"
            SELECT
                a.id,
                a.trace_id,
                a.app_id,
                a.user_id,
                a.action_type,
                a.original_intent,
                json_extract(a.payload, '$.amount') as amount,
                json_extract(a.payload, '$.currency') as currency,
                e.decision,
                e.risk_tier,
                e.reasons,
                a.created_at
            FROM agent_actions a
            JOIN evaluations e ON a.id = e.agent_action_id
            WHERE {}
            ORDER BY a.created_at DESC
            LIMIT ? OFFSET ?
            "#,
            where_clause
        );

        let count_query = format!(
            r#"
            SELECT COUNT(*)
            FROM agent_actions a
            JOIN evaluations e ON a.id = e.agent_action_id
            WHERE {}
            "#,
            where_clause
        );

        // Build the query dynamically
        let mut query_builder = sqlx::query_as::<_, ActionListRow>(&query);
        let mut count_builder = sqlx::query_as::<_, (i64,)>(&count_query);

        query_builder = query_builder.bind(company_id.to_string());
        count_builder = count_builder.bind(company_id.to_string());

        if let Some(app) = app_id {
            query_builder = query_builder.bind(app.to_string());
            count_builder = count_builder.bind(app.to_string());
        }
        if let Some(d) = decision {
            query_builder = query_builder.bind(d.to_string());
            count_builder = count_builder.bind(d.to_string());
        }
        if let Some(r) = risk_tier {
            query_builder = query_builder.bind(r.to_string());
            count_builder = count_builder.bind(r.to_string());
        }
        if let Some(u) = user_id {
            query_builder = query_builder.bind(u);
            count_builder = count_builder.bind(u);
        }
        if let Some(s) = search {
            let pattern = format!("%{}%", s);
            query_builder = query_builder
                .bind(pattern.clone())
                .bind(pattern.clone())
                .bind(pattern.clone());
            count_builder = count_builder
                .bind(pattern.clone())
                .bind(pattern.clone())
                .bind(pattern);
        }
        if let Some(ref st) = start_time {
            query_builder = query_builder.bind(st);
            count_builder = count_builder.bind(st);
        }

        query_builder = query_builder.bind(limit).bind(offset);

        let rows = query_builder.fetch_all(&self.pool).await?;
        let (total,) = count_builder.fetch_one(&self.pool).await?;

        Ok((rows, total))
    }

    // ==================== Attack Events ====================

    /// Save an attack event.
    pub async fn save_attack_event(&self, event: &AttackEvent) -> ShieldResult<()> {
        sqlx::query(
            r#"
            INSERT INTO attack_events (
                id, company_id, app_id, agent_action_id, attack_type, severity,
                blocked, outcome, user_id, description, details, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(event.id.to_string())
        .bind(event.company_id.to_string())
        .bind(event.app_id.map(|id| id.to_string()))
        .bind(event.agent_action_id.to_string())
        .bind(event.attack_type.to_string())
        .bind(event.severity.to_string())
        .bind(if event.blocked { 1 } else { 0 })
        .bind(event.outcome.to_string())
        .bind(&event.user_id)
        .bind(&event.description)
        .bind(&event.details)
        .bind(event.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// List attack events for a company.
    pub async fn list_attack_events(
        &self,
        company_id: Uuid,
        app_id: Option<Uuid>,
        attack_type: Option<AttackType>,
        severity: Option<RiskTier>,
        outcome: Option<AttackOutcome>,
        limit: i64,
        offset: i64,
    ) -> ShieldResult<(Vec<AttackEvent>, i64)> {
        let mut conditions = vec!["ae.company_id = ?".to_string()];

        if app_id.is_some() {
            conditions.push("ae.app_id = ?".to_string());
        }
        if attack_type.is_some() {
            conditions.push("ae.attack_type = ?".to_string());
        }
        if severity.is_some() {
            conditions.push("ae.severity = ?".to_string());
        }
        if outcome.is_some() {
            conditions.push("ae.outcome = ?".to_string());
        }

        let where_clause = conditions.join(" AND ");

        let query = format!(
            r#"
            SELECT ae.*
            FROM attack_events ae
            WHERE {}
            ORDER BY ae.created_at DESC
            LIMIT ? OFFSET ?
            "#,
            where_clause
        );

        let count_query = format!(
            r#"SELECT COUNT(*) FROM attack_events ae WHERE {}"#,
            where_clause
        );

        let mut query_builder = sqlx::query_as::<_, AttackEventRow>(&query);
        let mut count_builder = sqlx::query_as::<_, (i64,)>(&count_query);

        query_builder = query_builder.bind(company_id.to_string());
        count_builder = count_builder.bind(company_id.to_string());

        if let Some(app) = app_id {
            query_builder = query_builder.bind(app.to_string());
            count_builder = count_builder.bind(app.to_string());
        }
        if let Some(at) = attack_type {
            query_builder = query_builder.bind(at.to_string());
            count_builder = count_builder.bind(at.to_string());
        }
        if let Some(s) = severity {
            query_builder = query_builder.bind(s.to_string());
            count_builder = count_builder.bind(s.to_string());
        }
        if let Some(o) = outcome {
            query_builder = query_builder.bind(o.to_string());
            count_builder = count_builder.bind(o.to_string());
        }

        query_builder = query_builder.bind(limit).bind(offset);

        let rows = query_builder.fetch_all(&self.pool).await?;
        let (total,) = count_builder.fetch_one(&self.pool).await?;

        let events = rows
            .into_iter()
            .map(|r| r.try_into())
            .collect::<ShieldResult<Vec<_>>>()?;

        Ok((events, total))
    }

    // ==================== Company Settings ====================

    /// Get or create company settings.
    pub async fn get_company_settings(&self, company_id: Uuid) -> ShieldResult<CompanySettings> {
        let company = self.get_company(company_id).await?;

        let row: Option<CompanySettingsRow> =
            sqlx::query_as("SELECT * FROM company_settings WHERE company_id = ?")
                .bind(company_id.to_string())
                .fetch_optional(&self.pool)
                .await?;

        if let Some(settings_row) = row {
            settings_row.into_settings(company_id, company.name)
        } else {
            // Return defaults
            Ok(CompanySettings::new(company_id, company.name))
        }
    }

    /// Update company settings.
    pub async fn update_company_settings(
        &self,
        company_id: Uuid,
        logo: Option<&str>,
        webhook_url: Option<&str>,
        notification_email: Option<&str>,
        thresholds: Option<&PolicyThresholds>,
    ) -> ShieldResult<CompanySettings> {
        // Ensure settings row exists
        let existing: Option<(String,)> =
            sqlx::query_as("SELECT company_id FROM company_settings WHERE company_id = ?")
                .bind(company_id.to_string())
                .fetch_optional(&self.pool)
                .await?;

        if existing.is_none() {
            sqlx::query("INSERT INTO company_settings (company_id) VALUES (?)")
                .bind(company_id.to_string())
                .execute(&self.pool)
                .await?;
        }

        if let Some(logo) = logo {
            sqlx::query("UPDATE company_settings SET logo = ? WHERE company_id = ?")
                .bind(logo)
                .bind(company_id.to_string())
                .execute(&self.pool)
                .await?;
        }

        if let Some(url) = webhook_url {
            sqlx::query("UPDATE company_settings SET webhook_url = ? WHERE company_id = ?")
                .bind(url)
                .bind(company_id.to_string())
                .execute(&self.pool)
                .await?;
        }

        if let Some(email) = notification_email {
            sqlx::query("UPDATE company_settings SET notification_email = ? WHERE company_id = ?")
                .bind(email)
                .bind(company_id.to_string())
                .execute(&self.pool)
                .await?;
        }

        if let Some(t) = thresholds {
            sqlx::query(
                r#"
                UPDATE company_settings SET
                    max_auto_approve_amount = ?,
                    hitl_threshold_amount = ?,
                    velocity_limit_per_hour = ?,
                    velocity_limit_per_day = ?,
                    block_high_risk_actions = ?,
                    require_hitl_for_new_beneficiaries = ?
                WHERE company_id = ?
                "#,
            )
            .bind(t.max_auto_approve_amount)
            .bind(t.hitl_threshold_amount)
            .bind(t.velocity_limit_per_hour)
            .bind(t.velocity_limit_per_day)
            .bind(if t.block_high_risk_actions { 1 } else { 0 })
            .bind(if t.require_hitl_for_new_beneficiaries {
                1
            } else {
                0
            })
            .bind(company_id.to_string())
            .execute(&self.pool)
            .await?;
        }

        self.get_company_settings(company_id).await
    }

    // ==================== Users ====================

    /// Create a new user.
    pub async fn create_user(&self, user: &User) -> ShieldResult<()> {
        sqlx::query(
            r#"
            INSERT INTO users (id, email, name, image, role, email_verified, password_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(user.id.to_string())
        .bind(&user.email)
        .bind(&user.name)
        .bind(&user.image)
        .bind(user.role.to_string())
        .bind(if user.email_verified { 1 } else { 0 })
        .bind(&user.password_hash)
        .bind(user.created_at.to_rfc3339())
        .bind(user.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get a user by ID.
    pub async fn get_user(&self, id: Uuid) -> ShieldResult<User> {
        let row: UserRow = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| ShieldError::NotFound(format!("User {} not found", id)))?;

        row.try_into()
    }

    /// Get a user by email.
    pub async fn get_user_by_email(&self, email: &str) -> ShieldResult<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as("SELECT * FROM users WHERE email = ?")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.try_into()).transpose()
    }

    /// Update a user.
    pub async fn update_user(
        &self,
        id: Uuid,
        name: Option<&str>,
        image: Option<&str>,
    ) -> ShieldResult<User> {
        let updated_at = chrono::Utc::now().to_rfc3339();

        if let Some(name) = name {
            sqlx::query("UPDATE users SET name = ?, updated_at = ? WHERE id = ?")
                .bind(name)
                .bind(&updated_at)
                .bind(id.to_string())
                .execute(&self.pool)
                .await?;
        }

        if let Some(image) = image {
            sqlx::query("UPDATE users SET image = ?, updated_at = ? WHERE id = ?")
                .bind(image)
                .bind(&updated_at)
                .bind(id.to_string())
                .execute(&self.pool)
                .await?;
        }

        self.get_user(id).await
    }

    // ==================== OAuth Accounts ====================

    /// Create an OAuth account link.
    pub async fn create_oauth_account(&self, account: &OAuthAccount) -> ShieldResult<()> {
        sqlx::query(
            r#"
            INSERT INTO oauth_accounts (id, user_id, provider, provider_account_id, created_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(account.id.to_string())
        .bind(account.user_id.to_string())
        .bind(account.provider.to_string())
        .bind(&account.provider_account_id)
        .bind(account.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Find a user by OAuth provider and account ID.
    pub async fn find_user_by_oauth(
        &self,
        provider: OAuthProvider,
        provider_account_id: &str,
    ) -> ShieldResult<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as(
            r#"
            SELECT u.* FROM users u
            JOIN oauth_accounts oa ON u.id = oa.user_id
            WHERE oa.provider = ? AND oa.provider_account_id = ?
            "#,
        )
        .bind(provider.to_string())
        .bind(provider_account_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into()).transpose()
    }

    /// Get all OAuth accounts for a user.
    pub async fn get_user_oauth_accounts(&self, user_id: Uuid) -> ShieldResult<Vec<OAuthAccount>> {
        let rows: Vec<OAuthAccountRow> =
            sqlx::query_as("SELECT * FROM oauth_accounts WHERE user_id = ?")
                .bind(user_id.to_string())
                .fetch_all(&self.pool)
                .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    /// Get companies for a user (with their role in each).
    pub async fn get_user_companies(
        &self,
        user_id: &str,
    ) -> ShieldResult<Vec<UserCompanyMembership>> {
        let rows: Vec<(String, String, String, String)> = sqlx::query_as(
            r#"
            SELECT c.id, c.name, c.slug, m.role
            FROM companies c
            JOIN company_members m ON c.id = m.company_id
            WHERE m.user_id = ?
            ORDER BY c.name ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|(id, name, slug, role)| {
                Uuid::parse_str(&id).ok().map(|id| UserCompanyMembership {
                    id,
                    name,
                    slug,
                    role,
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ActionType, DecisionStatus, RiskTier};

    async fn setup_test_db() -> ShieldRepository {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");
        let repo = ShieldRepository::new(pool);
        repo.init_schema().await.expect("Failed to init schema");
        repo
    }

    #[tokio::test]
    async fn test_save_and_get_action() {
        let repo = setup_test_db().await;

        let action = AgentAction::new(
            "user123",
            "chatbot",
            "gpt-4",
            "Check my balance",
            ActionType::GetBalance,
            serde_json::json!({"account_id": "checking"}),
        );

        repo.save_action(&action).await.unwrap();

        let retrieved = repo.get_action(action.id).await.unwrap();
        assert_eq!(retrieved.user_id, "user123");
        assert_eq!(retrieved.action_type, ActionType::GetBalance);
    }

    #[tokio::test]
    async fn test_save_and_get_evaluation() {
        let repo = setup_test_db().await;

        let action = AgentAction::new(
            "user123",
            "chatbot",
            "gpt-4",
            "Check my balance",
            ActionType::GetBalance,
            serde_json::json!({"account_id": "checking"}),
        );
        repo.save_action(&action).await.unwrap();

        let eval = EvaluationResult::new(
            action.id,
            DecisionStatus::Allow,
            RiskTier::Low,
            vec!["All checks passed".to_string()],
            vec![],
        );
        repo.save_evaluation(&eval).await.unwrap();

        let retrieved = repo.get_evaluation(eval.id).await.unwrap();
        assert_eq!(retrieved.decision, DecisionStatus::Allow);
    }

    #[tokio::test]
    async fn test_hitl_task_lifecycle() {
        let repo = setup_test_db().await;

        // Create action and evaluation
        let action = AgentAction::new(
            "user123",
            "chatbot",
            "gpt-4",
            "Transfer $500",
            ActionType::TransferFunds,
            serde_json::json!({
                "from_account_id": "checking",
                "to_account_id": "savings",
                "amount": 500.0
            }),
        );
        repo.save_action(&action).await.unwrap();

        let eval = EvaluationResult::require_hitl(
            action.id,
            vec!["Amount exceeds auto-approval limit".to_string()],
            vec!["AMOUNT_EXCEEDS_AUTO_LIMIT".to_string()],
        );
        repo.save_evaluation(&eval).await.unwrap();

        // Create HITL task
        let task = HitlTask::new(action.id, eval.id);
        repo.save_hitl_task(&task).await.unwrap();

        // List pending tasks
        let tasks = repo
            .list_hitl_tasks(Some(HitlStatus::Pending), 10, 0)
            .await
            .unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].status, HitlStatus::Pending);

        // Approve task
        let updated = repo
            .update_hitl_task(
                task.id,
                HitlStatus::Approved,
                "admin@example.com",
                Some("Looks good"),
            )
            .await
            .unwrap();
        assert_eq!(updated.status, HitlStatus::Approved);

        // Verify no more pending
        let pending = repo
            .list_hitl_tasks(Some(HitlStatus::Pending), 10, 0)
            .await
            .unwrap();
        assert!(pending.is_empty());
    }
}
