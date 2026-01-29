use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Log severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Critical,
    Success,
    Attack,
    Flag,
}

impl LogLevel {
    /// Get Discord color for this log level
    pub fn color(&self) -> u32 {
        match self {
            LogLevel::Debug => 0x95A5A6,      // Gray
            LogLevel::Info => 0x3498DB,       // Blue
            LogLevel::Warn => 0xF39C12,       // Orange
            LogLevel::Error => 0xE74C3C,      // Red
            LogLevel::Critical => 0x8E44AD,   // Purple
            LogLevel::Success => 0x2ECC71,    // Green
            LogLevel::Attack => 0xFF0000,     // Bright Red
            LogLevel::Flag => 0xFFD700,       // Gold
        }
    }

    /// Get emoji for this log level
    pub fn emoji(&self) -> &'static str {
        match self {
            LogLevel::Debug => "🔍",
            LogLevel::Info => "ℹ️",
            LogLevel::Warn => "⚠️",
            LogLevel::Error => "❌",
            LogLevel::Critical => "🚨",
            LogLevel::Success => "✅",
            LogLevel::Attack => "⚔️",
            LogLevel::Flag => "🏁",
        }
    }

    /// Get the display name
    pub fn name(&self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Critical => "CRITICAL",
            LogLevel::Success => "SUCCESS",
            LogLevel::Attack => "ATTACK",
            LogLevel::Flag => "FLAG",
        }
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

/// A log entry sent via HTTP API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Log message content
    pub message: String,
    /// Log severity level
    #[serde(default)]
    pub level: LogLevel,
    /// Optional title for embed
    #[serde(default)]
    pub title: Option<String>,
    /// Optional team identifier
    #[serde(default)]
    pub team: Option<String>,
    /// Optional service identifier
    #[serde(default)]
    pub service: Option<String>,
    /// Optional additional fields
    #[serde(default)]
    pub fields: HashMap<String, serde_json::Value>,
    /// Timestamp (auto-generated if not provided)
    #[serde(default = "default_timestamp")]
    pub timestamp: DateTime<Utc>,
    /// Source IP address
    #[serde(default)]
    pub source_ip: Option<String>,
    /// Optional tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Optional URL for viewing more details
    #[serde(default)]
    pub url: Option<String>,
    /// Optional thumbnail/image URL
    #[serde(default)]
    pub thumbnail: Option<String>,
    /// Whether to ping @everyone (for critical alerts)
    #[serde(default)]
    pub ping_everyone: bool,
    /// Whether to ping @here
    #[serde(default)]
    pub ping_here: bool,
}

fn default_timestamp() -> DateTime<Utc> {
    Utc::now()
}

/// Batch log request for sending multiple logs at once
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchLogRequest {
    pub entries: Vec<LogEntry>,
}

/// Statistics for a channel
#[derive(Debug, Clone, Serialize, Default)]
pub struct ChannelStats {
    pub total_logs: u64,
    pub logs_by_level: HashMap<String, u64>,
    pub unique_teams: u64,
    pub unique_services: u64,
}

/// Rate limit info for an IP
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub request_count: u32,
    pub window_start: DateTime<Utc>,
}
