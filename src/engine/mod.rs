//! Evaluation engine for Shield Core.
//!
//! This module contains the layered safety pipeline:
//! - Input Firewall: Detects prompt injection and suspicious patterns
//! - LLM Guard: Neural content safety using Llama Guard
//! - Alignment Checker: Verifies intent matches action
//! - Policy Engine: Applies symbolic rules (thresholds, limits)
//! - Evaluation Coordinator: Orchestrates all layers

mod alignment;
mod coordinator;
mod firewall;
mod llm_guard;
mod policy;

pub use alignment::*;
pub use coordinator::*;
pub use firewall::*;
pub use llm_guard::*;
pub use policy::*;

