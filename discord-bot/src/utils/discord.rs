use crate::models::log_entry::LogEntry;
use serenity::builder::{CreateEmbed, CreateEmbedFooter, CreateMessage};
use serenity::model::prelude::*;
use serenity::prelude::*;

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

/// Create a message builder from a log entry
pub fn create_log_message(entry: &LogEntry) -> CreateMessage {
    let mut message = CreateMessage::default();

    // Add pings if needed
    let mut content = String::new();
    if entry.ping_everyone {
        content.push_str("@everyone ");
    }
    if entry.ping_here {
        content.push_str("@here ");
    }

    if !content.is_empty() {
        message = message.content(content);
    }

    message = message.add_embed(create_log_embed(entry));

    message
}

/// Find or create a channel by name under a category
pub async fn find_or_create_channel(
    ctx: &Context,
    guild_id: GuildId,
    category_id: ChannelId,
    channel_name: &str,
) -> Result<ChannelId, Box<dyn std::error::Error + Send + Sync>> {
    // First try to find existing channel
    let guild = guild_id.to_partial_guild(ctx).await?;
    
    for (id, channel) in guild.channels(ctx).await? {
        if channel.name().to_lowercase() == channel_name.to_lowercase() {
            return Ok(id);
        }
    }

    // Create new channel
    let channel = guild_id
        .create_channel(ctx, |c| {
            c.name(channel_name)
                .kind(ChannelType::Text)
                .category(category_id)
        })
        .await?;

    Ok(channel.id)
}

/// Find or create a category by name
pub async fn find_or_create_category(
    ctx: &Context,
    guild_id: GuildId,
    category_name: &str,
) -> Result<ChannelId, Box<dyn std::error::Error + Send + Sync>> {
    // First try to find existing category
    let guild = guild_id.to_partial_guild(ctx).await?;
    
    for (id, channel) in guild.channels(ctx).await? {
        if channel.kind == ChannelType::Category && channel.name() == category_name {
            return Ok(id);
        }
    }

    // Create new category
    let channel = guild_id
        .create_channel(ctx, |c| c.name(category_name).kind(ChannelType::Category))
        .await?;

    Ok(channel.id)
}

/// Get guild ID from context
pub async fn get_guild_id(ctx: &Context) -> Option<GuildId> {
    // Try to get from cache first
    for (guild_id, guild) in ctx.cache.guilds() {
        return Some(guild_id);
    }
    None
}
