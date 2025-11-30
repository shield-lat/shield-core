//! Storage layer for Shield Core.
//!
//! Provides database access via SQLx with SQLite (MVP) or Postgres.

mod models;
mod repository;

pub use repository::ShieldRepository;

