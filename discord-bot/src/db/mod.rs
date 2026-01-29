use crate::models::whitelist::WhitelistEntry;
use crate::models::log_entry::RateLimitInfo;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::collections::HashMap;

pub mod migrations;

pub struct Database {
    pool: Pool<Sqlite>,
    rate_limits: HashMap<String, RateLimitInfo>,
}

impl Database {
    /// Create a new database connection pool
    pub async fn new(database_url: &str) -> Result<Self> {
        // Ensure the database file directory exists for file-based URLs
        if database_url.starts_with("sqlite://") && !database_url.contains(":memory:") {
            let path = database_url.trim_start_matches("sqlite://");
            if let Some(parent) = std::path::Path::new(path).parent() {
                tokio::fs::create_dir_all(parent).await.ok();
            }
        }

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .context("Failed to create database pool")?;

        Ok(Self {
            pool,
            rate_limits: HashMap::new(),
        })
    }

    /// Run database migrations
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .context("Failed to run migrations")?;
        Ok(())
    }

    /// Get the database pool
    pub fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }

    // ==================== Whitelist Operations ====================

    /// Add an IP to the whitelist
    pub async fn add_whitelist(
        &self,
        ip_address: &str,
        description: Option<&str>,
        added_by: Option<&str>,
    ) -> Result<i64> {
        let result = sqlx::query!(
            r#"
            INSERT INTO whitelist (ip_address, description, added_by, created_at, is_active)
            VALUES (?, ?, ?, datetime('now'), TRUE)
            ON CONFLICT(ip_address) DO UPDATE SET
                description = COALESCE(excluded.description, whitelist.description),
                is_active = TRUE,
                added_by = COALESCE(excluded.added_by, whitelist.added_by)
            RETURNING id
            "#,
            ip_address,
            description,
            added_by
        )
        .fetch_one(&self.pool)
        .await
        .context("Failed to add whitelist entry")?;

        Ok(result.id)
    }

    /// Remove an IP from the whitelist
    pub async fn remove_whitelist(&self, ip_address: &str) -> Result<bool> {
        let rows_affected = sqlx::query!(
            r#"DELETE FROM whitelist WHERE ip_address = ?"#,
            ip_address
        )
        .execute(&self.pool)
        .await
        .context("Failed to remove whitelist entry")?
        .rows_affected();

        Ok(rows_affected > 0)
    }

    /// Check if an IP is whitelisted
    pub async fn is_whitelisted(&self, ip_address: &str) -> Result<bool> {
        let entries = self.get_all_whitelist().await?;
        
        for entry in entries {
            if entry.is_active && crate::models::whitelist::ip_matches(ip_address, &entry.ip_address) {
                // Update last used time
                let _ = sqlx::query!(
                    r#"UPDATE whitelist SET last_used_at = datetime('now'), request_count = request_count + 1 WHERE id = ?"#,
                    entry.id
                )
                .execute(&self.pool)
                .await;
                return Ok(true);
            }
        }
        
        Ok(false)
    }

    /// Get all whitelist entries
    pub async fn get_all_whitelist(&self) -> Result<Vec<WhitelistEntry>> {
        let entries = sqlx::query_as!(
            WhitelistEntry,
            r#"SELECT * FROM whitelist ORDER BY created_at DESC"#
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch whitelist entries")?;

        Ok(entries)
    }

    /// Get a specific whitelist entry
    pub async fn get_whitelist(&self, ip_address: &str) -> Result<Option<WhitelistEntry>> {
        let entry = sqlx::query_as!(
            WhitelistEntry,
            r#"SELECT * FROM whitelist WHERE ip_address = ?"#,
            ip_address
        )
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch whitelist entry")?;

        Ok(entry)
    }

    // ==================== Rate Limiting ====================

    /// Check if an IP is rate limited
    pub fn check_rate_limit(&mut self, ip: &str, max_requests: u32) -> bool {
        let now = Utc::now();
        let window_start = now - Duration::minutes(1);

        if let Some(info) = self.rate_limits.get_mut(ip) {
            if info.window_start < window_start {
                // Reset window
                info.window_start = now;
                info.request_count = 1;
                true
            } else if info.request_count < max_requests {
                info.request_count += 1;
                true
            } else {
                false // Rate limited
            }
        } else {
            // First request from this IP
            self.rate_limits.insert(
                ip.to_string(),
                RateLimitInfo {
                    request_count: 1,
                    window_start: now,
                },
            );
            true
        }
    }

    /// Clean up old rate limit entries
    pub fn cleanup_rate_limits(&mut self) {
        let now = Utc::now();
        let window_start = now - Duration::minutes(1);
        self.rate_limits.retain(|_, info| info.window_start >= window_start);
    }

    // ==================== Statistics ====================

    /// Log a request for statistics
    pub async fn log_request(&self, channel_name: &str, level: &str, source_ip: &str) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO request_logs (channel_name, level, source_ip, timestamp)
            VALUES (?, ?, ?, datetime('now'))
            "#,
            channel_name,
            level,
            source_ip
        )
        .execute(&self.pool)
        .await
        .context("Failed to log request")?;

        Ok(())
    }

    /// Get statistics for all channels
    pub async fn get_channel_stats(&self) -> Result<HashMap<String, crate::models::log_entry::ChannelStats>> {
        let logs = sqlx::query!(
            r#"
            SELECT channel_name, level, COUNT(*) as count
            FROM request_logs
            WHERE timestamp > datetime('now', '-1 day')
            GROUP BY channel_name, level
            "#
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch statistics")?;

        let mut stats: HashMap<String, crate::models::log_entry::ChannelStats> = HashMap::new();

        for log in logs {
            let entry = stats.entry(log.channel_name.clone()).or_default();
            entry.total_logs += log.count as u64;
            *entry.logs_by_level.entry(log.level).or_insert(0) += log.count as u64;
        }

        Ok(stats)
    }

    /// Get blacklist log count
    pub async fn get_blacklist_count(&self) -> Result<i64> {
        let count = sqlx::query_scalar!(
            r#"SELECT COUNT(*) FROM request_logs WHERE channel_name = 'blacklist'"#
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0);

        Ok(count)
    }
}
