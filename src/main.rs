//! Shield Core - AI Safety Gateway for Fintech
//!
//! This service evaluates LLM agent actions before execution,
//! applying layered safety checks to protect financial operations.

use std::sync::Arc;

use sqlx::sqlite::SqlitePool;
use tokio::net::TcpListener;

mod api;
mod auth;
mod config;
mod domain;
mod engine;
mod error;
mod logging;
mod storage;

use crate::api::build_router;
use crate::auth::{ApiKeyValidator, JwtManager, UserStore};
use crate::config::Config;
use crate::engine::{
    CompositeFirewall, ConfigPolicyEngine, EvaluationCoordinator, HeuristicAlignmentChecker,
    KeywordFirewall,
};
use crate::storage::ShieldRepository;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    /// The evaluation coordinator.
    pub coordinator: Arc<EvaluationCoordinator>,
    /// Database repository.
    pub repository: ShieldRepository,
    /// JWT manager for token operations.
    pub jwt_manager: JwtManager,
    /// User store for config-based users (legacy).
    pub user_store: UserStore,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables from .env file (if present)
    // This is optional and won't fail if .env doesn't exist
    if let Err(e) = dotenvy::dotenv() {
        // Only log at debug level - missing .env is expected in production
        eprintln!("Note: No .env file loaded ({e})");
    }

    // Initialize logging
    logging::init();

    tracing::info!("Starting Shield Core v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = Config::load().map_err(|e| {
        tracing::error!(error = %e, "Failed to load configuration");
        anyhow::anyhow!("Configuration error: {}", e)
    })?;

    tracing::info!(
        host = %config.server.host,
        port = %config.server.port,
        database = %config.database.url,
        auth_enabled = %config.auth.enabled,
        "Configuration loaded"
    );

    // Connect to database
    let pool = SqlitePool::connect(&config.database.url)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to connect to database");
            anyhow::anyhow!("Database connection error: {}", e)
        })?;

    // Initialize repository and schema
    let repository = ShieldRepository::new(pool);
    repository.init_schema().await.map_err(|e| {
        tracing::error!(error = %e, "Failed to initialize database schema");
        anyhow::anyhow!("Schema initialization error: {}", e)
    })?;

    tracing::info!("Database connected and schema initialized");

    // Build the evaluation coordinator
    let mut firewalls: Vec<Box<dyn engine::InputFirewall>> = vec![Box::new(KeywordFirewall::new(
        config.safety.suspicious_keywords.clone(),
    ))];

    // Add Llama Guard if enabled
    if config.llm.enabled && !config.llm.openrouter_api_key.is_empty() {
        tracing::info!(
            model = %config.llm.guard_model,
            "Llama Guard neural firewall enabled"
        );
        let llm_config = engine::OpenRouterConfig {
            api_key: config.llm.openrouter_api_key.clone(),
            model: config.llm.guard_model.clone(),
            timeout_secs: config.llm.timeout_secs,
            enabled: true,
        };
        firewalls.push(Box::new(engine::SyncLlamaGuardFirewall::new(llm_config)));
    } else {
        tracing::info!("Llama Guard neural firewall disabled");
    }

    let firewall = CompositeFirewall::new(firewalls);
    let alignment_checker = HeuristicAlignmentChecker::new(false);
    let policy_engine = ConfigPolicyEngine::new(config.safety.clone());

    let coordinator = Arc::new(EvaluationCoordinator::new(
        Box::new(firewall),
        Box::new(alignment_checker),
        Box::new(policy_engine),
    ));

    // Build authentication components
    let api_key_validator = ApiKeyValidator::new(config.auth.api_keys.clone());
    let jwt_manager = JwtManager::new(
        &config.auth.jwt_secret,
        config.auth.jwt_issuer.clone(),
        config.auth.token_duration_hours,
    );
    let user_store = UserStore::new(config.auth.users.clone());

    // Build application state
    let state = AppState {
        coordinator,
        repository,
        jwt_manager: jwt_manager.clone(),
        user_store: user_store.clone(),
    };

    if config.auth.enabled {
        tracing::info!(
            api_keys = config.auth.api_keys.len(),
            users = config.auth.users.len(),
            "Authentication enabled"
        );
    } else {
        tracing::warn!("Authentication is DISABLED - enable for production");
    }

    // Build router
    let app = build_router(state, config.auth.enabled, api_key_validator, jwt_manager);

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&addr).await?;

    tracing::info!(address = %addr, "Server listening");
    tracing::info!("Swagger UI available at http://{}/swagger-ui/", addr);

    axum::serve(listener, app).await?;

    Ok(())
}
