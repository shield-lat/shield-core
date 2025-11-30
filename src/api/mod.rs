//! HTTP API layer for Shield Core.
//!
//! Provides REST endpoints for action evaluation and HITL management.

pub mod handlers;
mod routes;
mod types;

pub use routes::build_router;

