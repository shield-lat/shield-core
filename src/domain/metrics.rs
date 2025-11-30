//! Metrics domain types for analytics.
//!
//! Provides aggregated metrics and statistics for the dashboard.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Time range for metrics queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimeRange {
    /// Last 24 hours.
    Last24h,
    /// Last 7 days.
    Last7d,
    /// Last 30 days.
    Last30d,
    /// Last 90 days.
    Last90d,
}

impl TimeRange {
    /// Get the number of hours for this time range.
    pub fn hours(&self) -> i64 {
        match self {
            TimeRange::Last24h => 24,
            TimeRange::Last7d => 24 * 7,
            TimeRange::Last30d => 24 * 30,
            TimeRange::Last90d => 24 * 90,
        }
    }

    /// Get the start timestamp for this time range.
    pub fn start_time(&self) -> DateTime<Utc> {
        Utc::now() - chrono::Duration::hours(self.hours())
    }
}

impl std::str::FromStr for TimeRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "24h" | "last24h" => Ok(TimeRange::Last24h),
            "7d" | "last7d" => Ok(TimeRange::Last7d),
            "30d" | "last30d" => Ok(TimeRange::Last30d),
            "90d" | "last90d" => Ok(TimeRange::Last90d),
            _ => Err(format!("Invalid time range: {}. Use 24h, 7d, 30d, or 90d", s)),
        }
    }
}

impl Default for TimeRange {
    fn default() -> Self {
        TimeRange::Last7d
    }
}

/// Granularity for time-series data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Granularity {
    /// Hourly data points.
    Hour,
    /// Daily data points.
    Day,
}

impl Default for Granularity {
    fn default() -> Self {
        Granularity::Day
    }
}

impl std::str::FromStr for Granularity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hour" | "hourly" => Ok(Granularity::Hour),
            "day" | "daily" => Ok(Granularity::Day),
            _ => Err(format!("Invalid granularity: {}. Use hour or day", s)),
        }
    }
}

/// Trend information (percentage change from previous period).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Trends {
    /// Trend for total actions.
    pub total_actions: f64,
    /// Trend for blocked actions.
    pub blocked_actions: f64,
    /// Trend for escalated actions.
    pub escalated_actions: f64,
    /// Trend for attack attempts.
    pub attack_attempts: f64,
}

/// Overview metrics for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MetricsOverview {
    /// Total number of actions evaluated.
    pub total_actions: i64,
    /// Number of blocked actions.
    pub blocked_actions: i64,
    /// Number of actions escalated to HITL.
    pub escalated_actions: i64,
    /// Number of attack attempts detected.
    pub attack_attempts: i64,
    /// Attack success rate (percentage 0-100).
    pub attack_success_rate: f64,
    /// Number of unique users impacted.
    pub users_impacted: i64,
    /// Trend information.
    pub trends: Trends,
}

impl Default for MetricsOverview {
    fn default() -> Self {
        Self {
            total_actions: 0,
            blocked_actions: 0,
            escalated_actions: 0,
            attack_attempts: 0,
            attack_success_rate: 0.0,
            users_impacted: 0,
            trends: Trends {
                total_actions: 0.0,
                blocked_actions: 0.0,
                escalated_actions: 0.0,
                attack_attempts: 0.0,
            },
        }
    }
}

/// A single data point in a time series.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TimeSeriesPoint {
    /// Timestamp for this data point.
    pub timestamp: DateTime<Utc>,
    /// Number of allowed actions.
    pub allowed: i64,
    /// Number of HITL actions.
    pub hitl: i64,
    /// Number of blocked actions.
    pub blocked: i64,
}

/// Time series metrics data.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TimeSeriesData {
    /// The data points.
    pub data: Vec<TimeSeriesPoint>,
}

/// Risk distribution data point.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskDistributionPoint {
    /// Risk tier.
    pub tier: String,
    /// Count of actions in this tier.
    pub count: i64,
    /// Percentage of total.
    pub percentage: f64,
}

/// Risk distribution metrics.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskDistribution {
    /// Distribution data.
    pub data: Vec<RiskDistributionPoint>,
}

/// Attack statistics per app.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AppAttackStats {
    /// App ID.
    pub app_id: Uuid,
    /// App name.
    pub app_name: String,
    /// Number of attacks detected.
    pub attack_count: i64,
    /// Success rate of attacks (percentage 0-100).
    pub success_rate: f64,
}

/// Attacks by app metrics.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AttacksByApp {
    /// Attack data per app.
    pub data: Vec<AppAttackStats>,
}

/// Metrics summary for an app.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AppMetrics {
    /// Total actions processed.
    pub total_actions: i64,
    /// Blocked actions.
    pub blocked_actions: i64,
    /// HITL actions.
    pub hitl_actions: i64,
    /// Attacks detected.
    pub attacks_detected: i64,
    /// Attack success rate.
    pub attack_success_rate: f64,
    /// Users impacted.
    pub users_impacted: i64,
    /// Pending HITL tasks.
    pub pending_hitl_tasks: i64,
}

impl Default for AppMetrics {
    fn default() -> Self {
        Self {
            total_actions: 0,
            blocked_actions: 0,
            hitl_actions: 0,
            attacks_detected: 0,
            attack_success_rate: 0.0,
            users_impacted: 0,
            pending_hitl_tasks: 0,
        }
    }
}

