use anyhow::{Context, Result};
use std::net::SocketAddr;

/// Application configuration loaded from environment variables
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Discord bot token
    pub discord_token: String,
    /// Discord application ID
    pub discord_application_id: u64,
    /// HTTP server host
    pub http_host: String,
    /// HTTP server port
    pub http_port: u16,
    /// Database URL
    pub database_url: String,
    /// Discord guild ID (server ID) for slash commands
    pub guild_id: Option<u64>,
    /// Category name for log channels
    pub log_category_name: String,
    /// Channel name for blacklist notifications
    pub blacklist_channel_name: String,
    /// Rate limit: max requests per minute per IP
    pub rate_limit_per_minute: u32,
    /// Maximum log message length
    pub max_message_length: usize,
    /// Whether to enable IP geolocation info
    pub enable_geoip: bool,
    /// Admin Discord user IDs (can manage whitelist)
    pub admin_user_ids: Vec<u64>,
}

impl AppConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        // Load .env file if it exists
        let _ = dotenvy::dotenv();

        let discord_token = std::env::var("DISCORD_TOKEN")
            .context("DISCORD_TOKEN environment variable is required")?;

        let discord_application_id = std::env::var("DISCORD_APPLICATION_ID")
            .context("DISCORD_APPLICATION_ID environment variable is required")?
            .parse()
            .context("DISCORD_APPLICATION_ID must be a valid u64")?;

        let http_host = std::env::var("HTTP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

        let http_port = std::env::var("HTTP_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .context("HTTP_PORT must be a valid u16")?;

        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite://awd_logger.db".to_string());

        let guild_id = std::env::var("GUILD_ID")
            .ok()
            .map(|s| s.parse().ok())
            .flatten();

        let log_category_name = std::env::var("LOG_CATEGORY_NAME")
            .unwrap_or_else(|_| "🔥 AWD Logs".to_string());

        let blacklist_channel_name = std::env::var("BLACKLIST_CHANNEL_NAME")
            .unwrap_or_else(|_| "🚫 blacklist".to_string());

        let rate_limit_per_minute = std::env::var("RATE_LIMIT_PER_MINUTE")
            .unwrap_or_else(|_| "60".to_string())
            .parse()
            .context("RATE_LIMIT_PER_MINUTE must be a valid u32")?;

        let max_message_length = std::env::var("MAX_MESSAGE_LENGTH")
            .unwrap_or_else(|_| "4000".to_string())
            .parse()
            .context("MAX_MESSAGE_LENGTH must be a valid usize")?;

        let enable_geoip = std::env::var("ENABLE_GEOIP")
            .unwrap_or_else(|_| "false".to_string())
            .eq_ignore_ascii_case("true");

        let admin_user_ids: Vec<u64> = std::env::var("ADMIN_USER_IDS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().parse())
            .filter_map(Result::ok)
            .collect();

        Ok(Self {
            discord_token,
            discord_application_id,
            http_host,
            http_port,
            database_url,
            guild_id,
            log_category_name,
            blacklist_channel_name,
            rate_limit_per_minute,
            max_message_length,
            enable_geoip,
            admin_user_ids,
        })
    }

    /// Get the socket address for the HTTP server
    pub fn socket_addr(&self) -> Result<SocketAddr> {
        let addr = format!("{}:{}", self.http_host, self.http_port)
            .parse()
            .context("Invalid HTTP server address")?;
        Ok(addr)
    }
}
