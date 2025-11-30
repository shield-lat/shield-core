//! Authentication module for Shield Core.
//!
//! Provides two authentication mechanisms:
//! - API Key: For agent/LLM clients calling action evaluation
//! - JWT: For admin console accessing HITL endpoints

mod api_key;
mod jwt;
mod middleware;

pub use api_key::*;
pub use jwt::*;
pub use middleware::*;
