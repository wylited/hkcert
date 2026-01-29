use crate::models::log_entry::LogEntry;
use serenity::builder::{CreateEmbed, CreateEmbedFooter, CreateChannel};
use serenity::http::Http;
use serenity::model::prelude::*;

/// Create a Discord embed from a log entry
pub fn create_log_embed(entry: &LogEntry) -> CreateEmbed {
    let mut embed = CreateEmbed::default();

    // Set color based on level
    embed = embed.color(entry.level.color());

    // Title
    let title = entry
        .title
        .as_ref()
        .map(|t| format!("{} {}", entry.level.emoji(), t))
        .unwrap_or_else(|| format!("{} Log Entry", entry.level.emoji()));
    embed = embed.title(title);

    // Description (main message)
    embed = embed.description(&entry.message);

    // Timestamp
    embed = embed.timestamp(entry.timestamp);

    // Fields
    if let Some(team) = &entry.team {
        embed = embed.field("👥 Team", team, true);
    }
    if let Some(service) = &entry.service {
        embed = embed.field("🔧 Service", service, true);
    }

    // Additional custom fields
    for (key, value) in &entry.fields {
        let value_str = match value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        embed = embed.field(key, value_str, true);
    }

    // Tags
    if !entry.tags.is_empty() {
        let tags_str = entry.tags.iter().map(|t| format!("`{}`", t)).collect::<Vec<_>>().join(" ");
        embed = embed.field("🏷️ Tags", tags_str, false);
    }

    // Source IP
    if let Some(ip) = &entry.source_ip {
        embed = embed.field("🌐 Source IP", format!("`{}`", ip), true);
    }

    // URL
    if let Some(url) = &entry.url {
        embed = embed.url(url);
    }

    // Thumbnail
    if let Some(thumbnail) = &entry.thumbnail {
        embed = embed.thumbnail(thumbnail);
    }

    // Footer
    let mut footer_text = format!("Level: {}", entry.level.name());
    if entry.ping_everyone {
        footer_text.push_str(" | ALERT");
    }
    embed = embed.footer(CreateEmbedFooter::new(footer_text));

    embed
}

/// Find or create a channel by name under a category
pub async fn find_or_create_channel(
    http: &Http,
    guild_id: GuildId,
    category_id: ChannelId,
    channel_name: &str,
) -> Result<ChannelId, Box<dyn std::error::Error + Send + Sync>> {
    // First try to find existing channel
    let channels = guild_id.channels(http).await?;
    
    for (id, channel) in channels {
        if channel.name().to_lowercase() == channel_name.to_lowercase() {
            return Ok(id);
        }
    }

    // Create new channel
    let create_channel = CreateChannel::new(channel_name)
        .kind(ChannelType::Text)
        .category(category_id);
    
    let channel = guild_id
        .create_channel(http, create_channel)
        .await?;

    Ok(channel.id)
}

/// Find or create a category by name
pub async fn find_or_create_category(
    http: &Http,
    guild_id: GuildId,
    category_name: &str,
) -> Result<ChannelId, Box<dyn std::error::Error + Send + Sync>> {
    // First try to find existing category
    let channels = guild_id.channels(http).await?;
    
    for (id, channel) in channels {
        if channel.kind == ChannelType::Category && channel.name() == category_name {
            return Ok(id);
        }
    }

    // Create new category
    let create_channel = CreateChannel::new(category_name)
        .kind(ChannelType::Category);
    
    let channel = guild_id
        .create_channel(http, create_channel)
        .await?;

    Ok(channel.id)
}
