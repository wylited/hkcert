use crate::models::log_entry::{BatchLogRequest, LogEntry};
use crate::models::AppState;
use crate::utils::discord::{create_log_embed, find_or_create_category, find_or_create_channel};
use anyhow::{anyhow, Context, Result};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Json;
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};
use serenity::builder::CreateMessage;
use serenity::http::Http;
use serenity::model::id::GuildId;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn, debug};

/// Start the HTTP API server
pub async fn start_server(state: Arc<AppState>) -> Result<()> {
    let app = create_router(state.clone());
    let addr = state.config.socket_addr()?;

    info!("🌐 Starting HTTP server on http://{}", addr);

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

/// Create the API router
fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/:channel_name", post(handle_log))
        .route("/:channel_name/batch", post(handle_batch_log))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
                .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
                .into_inner(),
        )
        .with_state(state)
}

/// Handle a single log request
async fn handle_log(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(channel_name): Path<String>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<Value>) {
    let source_ip = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string());

    debug!("📨 Log request to '{}' from {}", channel_name, source_ip);

    let is_whitelisted = match state.db.read().await.is_whitelisted(&source_ip).await {
        Ok(w) => w,
        Err(e) => {
            warn!("Database error checking whitelist: {}", e);
            false
        }
    };

    if !is_whitelisted {
        warn!("🚫 Non-whitelisted IP attempted to log: {}", source_ip);
        if let Err(e) = send_blacklist_notification(&state, &source_ip, &channel_name, &body).await {
            warn!("Failed to send blacklist notification: {}", e);
        }
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "success": false,
                "error": "IP address not whitelisted",
                "ip": source_ip
            })),
        );
    }

    {
        let mut db = state.db.write().await;
        if !db.check_rate_limit(&source_ip, state.config.rate_limit_per_minute) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "success": false,
                    "error": "Rate limit exceeded",
                    "retry_after": 60
                })),
            );
        }
        db.cleanup_rate_limits();
    }

    let mut log_entry = match parse_log_entry(&body) {
        Ok(entry) => entry,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": format!("Invalid log format: {}", e)
                })),
            );
        }
    };

    log_entry.source_ip = Some(source_ip.clone());

    if log_entry.message.len() > state.config.max_message_length {
        log_entry.message = format!(
            "{}... (truncated)",
            &log_entry.message[..state.config.max_message_length - 20]
        );
    }

    let _ = state
        .db
        .read()
        .await
        .log_request(&channel_name, log_entry.level.name(), &source_ip)
        .await;

    match send_log_to_discord(&state, &channel_name, &log_entry).await {
        Ok(_) => {
            debug!("✅ Log sent to Discord channel '{}'", channel_name);
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "channel": channel_name,
                    "level": log_entry.level.name()
                })),
            )
        }
        Err(e) => {
            warn!("Failed to send log to Discord: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Discord error: {}", e)
                })),
            )
        }
    }
}

async fn handle_batch_log(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(channel_name): Path<String>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<Value>) {
    let source_ip = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string());

    let is_whitelisted = match state.db.read().await.is_whitelisted(&source_ip).await {
        Ok(w) => w,
        Err(e) => {
            warn!("Database error checking whitelist: {}", e);
            false
        }
    };

    if !is_whitelisted {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "success": false,
                "error": "IP address not whitelisted",
                "ip": source_ip
            })),
        );
    }

    let batch: BatchLogRequest = match serde_json::from_str(&body) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": format!("Invalid batch format: {}", e)
                })),
            );
        }
    };

    let mut success_count = 0;
    let mut errors = Vec::new();

    for mut entry in batch.entries {
        entry.source_ip = Some(source_ip.clone());
        match send_log_to_discord(&state, &channel_name, &entry).await {
            Ok(_) => success_count += 1,
            Err(e) => errors.push(format!("Failed to send log: {}", e)),
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "sent": success_count,
            "total": success_count + errors.len(),
            "errors": errors
        })),
    )
}

fn parse_log_entry(body: &str) -> Result<LogEntry, serde_json::Error> {
    if body.trim().starts_with('{') {
        serde_json::from_str(body)
    } else {
        Ok(LogEntry {
            message: body.to_string(),
            ..Default::default()
        })
    }
}

async fn send_log_to_discord(
    state: &AppState,
    channel_name: &str,
    entry: &LogEntry,
) -> Result<()> {
    let http = Http::new(&state.config.discord_token);

    let guild_id = state.config.guild_id.ok_or_else(|| anyhow!("No guild ID configured"))?;
    let guild_id = GuildId::new(guild_id);

    let category_id = find_or_create_category(&http, guild_id, &state.config.log_category_name)
        .await
        .map_err(|e| anyhow!("Failed to find/create category: {}", e))?;

    let channel_id = find_or_create_channel(
        &http,
        guild_id,
        category_id,
        channel_name,
    )
    .await
    .map_err(|e| anyhow!("Failed to find/create channel: {}", e))?;

    let embed = create_log_embed(entry);
    let mut message = CreateMessage::default();
    message = message.add_embed(embed);
    
    if entry.ping_everyone {
        message = message.content("@everyone");
    } else if entry.ping_here {
        message = message.content("@here");
    }

    channel_id.send_message(&http, message).await?;
    Ok(())
}

async fn send_blacklist_notification(
    state: &AppState,
    ip: &str,
    attempted_channel: &str,
    body: &str,
) -> Result<()> {
    let http = Http::new(&state.config.discord_token);

    let guild_id = state.config.guild_id.ok_or_else(|| anyhow!("No guild ID configured"))?;
    let guild_id = GuildId::new(guild_id);

    let category_id = find_or_create_category(&http, guild_id, &state.config.log_category_name)
        .await
        .map_err(|e| anyhow!("Category error: {}", e))?;

    let channel_name = state.config.blacklist_channel_name
        .replace("🚫 ", "")
        .replace(" ", "-");
    
    let channel_id = find_or_create_channel(
        &http,
        guild_id,
        category_id,
        &channel_name,
    )
    .await
    .map_err(|e| anyhow!("Channel error: {}", e))?;

    let embed = serenity::builder::CreateEmbed::default()
        .title("🚫 Blacklisted IP Attempt")
        .description(format!(
            "IP address `{}` attempted to send a log but is not whitelisted.",
            ip
        ))
        .color(0xE74C3C)
        .field("Target Channel", attempted_channel, true)
        .field("IP Address", format!("`{}`", ip), true)
        .field("Request Body", format!("```\n{}\n```", &body[..body.len().min(1000)]), false)
        .timestamp(chrono::Utc::now());

    let message = CreateMessage::default().add_embed(embed);
    channel_id.send_message(&http, message).await?;

    let _ = state
        .db
        .read()
        .await
        .log_request("blacklist", "block", ip)
        .await;

    Ok(())
}
