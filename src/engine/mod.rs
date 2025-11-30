//! Evaluation engine for Shield Core.
//!
//! This module contains the layered safety pipeline:
//! - Input Firewall: Detects prompt injection and suspicious patterns
//! - Alignment Checker: Verifies intent matches action
//! - Policy Engine: Applies symbolic rules (thresholds, limits)
//! - Evaluation Coordinator: Orchestrates all layers

mod alignment;
mod coordinator;
mod firewall;
mod policy;

pub use alignment::*;
pub use coordinator::*;
pub use firewall::*;
pub use policy::*;

