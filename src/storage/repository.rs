//! Repository layer for database operations.

use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

use crate::domain::{
    AgentAction, App, AppStatus, Company, CompanyMember, CompanyRole, EvaluationResult, HitlStatus,
    HitlTask, HitlTaskDetails, HitlTaskSummary,
};
use crate::error::{ShieldError, ShieldResult};
use crate::storage::models::{
    AgentActionRow, AppRow, CompanyMemberRow, CompanyRow, EvaluationRow, HitlTaskRow,
    HitlTaskSummaryRow,
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

        Ok(())
    }

    // ==================== Agent Actions ====================

    /// Save an agent action to the database.
    pub async fn save_action(&self, action: &AgentAction) -> ShieldResult<()> {
        sqlx::query(
            r#"
            INSERT INTO agent_actions (
                id, trace_id, user_id, channel, model_name,
                original_intent, action_type, payload, cot_trace, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(action.id.to_string())
        .bind(&action.trace_id)
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
