use crate::models::whitelist::WhitelistEntry;
use crate::models::log_entry::RateLimitInfo;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite, Row};
use std::collections::HashMap;

#[derive(Debug)]
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
            let path = std::path::Path::new(path);
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)
                        .context("Failed to create database directory")?;
                }
            }
            // Also ensure the file exists
            if !path.exists() {
                std::fs::File::create(path).context("Failed to create database file")?;
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
        // Create tables if they don't exist
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                description TEXT,
                added_by TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME,
                request_count INTEGER DEFAULT 0,
                is_active BOOLEAN DEFAULT TRUE
            )
            "#
        )
        .execute(&self.pool)
        .await
        .context("Failed to create whitelist table")?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_name TEXT NOT NULL,
                level TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#
        )
        .execute(&self.pool)
        .await
        .context("Failed to create request_logs table")?;

        // Create indexes
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_whitelist_ip ON whitelist(ip_address)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_whitelist_active ON whitelist(is_active)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_request_logs_channel ON request_logs(channel_name)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp)")
            .execute(&self.pool)
            .await?;

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
        // Try to insert, update if exists
        let result = sqlx::query(
            r#"
            INSERT INTO whitelist (ip_address, description, added_by, created_at, is_active)
            VALUES (?, ?, ?, datetime('now'), TRUE)
            ON CONFLICT(ip_address) DO UPDATE SET
                description = COALESCE(excluded.description, whitelist.description),
                is_active = TRUE,
                added_by = COALESCE(excluded.added_by, whitelist.added_by)
            RETURNING id
            "#
        )
        .bind(ip_address)
        .bind(description)
        .bind(added_by)
        .fetch_one(&self.pool)
        .await
        .context("Failed to add whitelist entry")?;

        Ok(result.get::<i64, _>("id"))
    }

    /// Remove an IP from the whitelist
    pub async fn remove_whitelist(&self, ip_address: &str) -> Result<bool> {
        let rows_affected = sqlx::query(
            r#"DELETE FROM whitelist WHERE ip_address = ?"#
        )
        .bind(ip_address)
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
                let _ = sqlx::query(
                    r#"UPDATE whitelist SET last_used_at = datetime('now'), request_count = request_count + 1 WHERE id = ?"#
                )
                .bind(entry.id)
                .execute(&self.pool)
                .await;
                return Ok(true);
            }
        }
        
        Ok(false)
    }

    /// Get all whitelist entries
    pub async fn get_all_whitelist(&self) -> Result<Vec<WhitelistEntry>> {
        let rows = sqlx::query(
            r#"SELECT * FROM whitelist ORDER BY created_at DESC"#
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch whitelist entries")?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(WhitelistEntry {
                id: row.get("id"),
                ip_address: row.get("ip_address"),
                description: row.get("description"),
                added_by: row.get("added_by"),
                created_at: row.get("created_at"),
                last_used_at: row.get("last_used_at"),
                request_count: row.get("request_count"),
                is_active: row.get("is_active"),
            });
        }

        Ok(entries)
    }

    /// Get a specific whitelist entry
    pub async fn get_whitelist(&self, ip_address: &str) -> Result<Option<WhitelistEntry>> {
        let rows = sqlx::query(
            r#"SELECT * FROM whitelist WHERE ip_address = ?"#
        )
        .bind(ip_address)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch whitelist entry")?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = &rows[0];
        Ok(Some(WhitelistEntry {
            id: row.get("id"),
            ip_address: row.get("ip_address"),
            description: row.get("description"),
            added_by: row.get("added_by"),
            created_at: row.get("created_at"),
            last_used_at: row.get("last_used_at"),
            request_count: row.get("request_count"),
            is_active: row.get("is_active"),
        }))
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
        sqlx::query(
            r#"
            INSERT INTO request_logs (channel_name, level, source_ip, timestamp)
            VALUES (?, ?, ?, datetime('now'))
            "#
        )
        .bind(channel_name)
        .bind(level)
        .bind(source_ip)
        .execute(&self.pool)
        .await
        .context("Failed to log request")?;

        Ok(())
    }

    /// Get statistics for all channels
    pub async fn get_channel_stats(&self) -> Result<HashMap<String, crate::models::log_entry::ChannelStats>> {
        let rows = sqlx::query(
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

        for row in rows {
            let channel_name: String = row.get("channel_name");
            let level: String = row.get("level");
            let count: i64 = row.get("count");
            
            let entry = stats.entry(channel_name).or_default();
            entry.total_logs += count as u64;
            *entry.logs_by_level.entry(level).or_insert(0) += count as u64;
        }

        Ok(stats)
    }

    /// Get blacklist log count
    pub async fn get_blacklist_count(&self) -> Result<i64> {
        let row = sqlx::query(
            r#"SELECT COUNT(*) as count FROM request_logs WHERE channel_name = 'blacklist'"#
        )
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(r.get::<i64, _>("count")),
            None => Ok(0),
        }
    }
}
