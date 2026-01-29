use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

mod api;
mod bot;
mod config;
mod db;
mod models;
mod utils;

use crate::config::AppConfig;
use crate::db::Database;
use crate::models::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "awd_logger=info,tower_http=info".into()),
        )
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .init();

    info!("🚀 Starting AWD Logger System v1.0.0");

    // Load configuration
    let app_config = Arc::new(AppConfig::from_env()?);
    info!("✅ Configuration loaded");

    // Initialize database
    let db = Database::new(&app_config.database_url).await?;
    db.migrate().await?;
    let db = Arc::new(RwLock::new(db));
    info!("✅ Database initialized");

    // Create shared state
    let state = Arc::new(AppState {
        config: app_config.clone(),
        db: db.clone(),
    });

    // Start Discord bot in a separate task
    let bot_state = state.clone();
    let bot_handle = tokio::spawn(async move {
        if let Err(e) = bot::start_bot(bot_state).await {
            warn!("Discord bot error: {}", e);
        }
    });

    // Give the bot a moment to initialize
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Start HTTP API server
    let api_state = state.clone();
    let api_handle = tokio::spawn(async move {
        if let Err(e) = api::start_server(api_state).await {
            warn!("HTTP API error: {}", e);
        }
    });

    info!("🎯 AWD Logger is running!");
    info!("📊 HTTP API: http://{}:{}", app_config.http_host, app_config.http_port);
    info!("🤖 Discord Bot is starting...");

    // Wait for both services
    tokio::select! {
        _ = bot_handle => warn!("Discord bot stopped"),
        _ = api_handle => warn!("HTTP API stopped"),
    }

    Ok(())
}
