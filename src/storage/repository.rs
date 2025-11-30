//! Repository layer for database operations.

use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

use crate::domain::{
    AgentAction, EvaluationResult, HitlStatus, HitlTask, HitlTaskDetails, HitlTaskSummary,
};
use crate::error::{ShieldError, ShieldResult};
use crate::storage::models::{AgentActionRow, EvaluationRow, HitlTaskRow, HitlTaskSummaryRow};

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
