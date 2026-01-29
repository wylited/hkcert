use crate::bot::{Context, Error};
use crate::utils::discord::*;
use crate::utils::format::*;
use serenity::builder::CreateEmbed;
use serenity::model::prelude::*;

/// Whitelist management commands
#[poise::command(
    slash_command,
    prefix_command,
    subcommands("whitelist_add", "whitelist_remove", "whitelist_list", "whitelist_clear"),
    subcommand_required
)]
pub async fn whitelist(_ctx: Context<'_>) -> Result<(), Error> {
    Ok(())
}

/// Add an IP address to the whitelist
#[poise::command(slash_command, prefix_command)]
pub async fn whitelist_add(
    ctx: Context<'_>,
    #[description = "IP address to whitelist (supports CIDR notation like 192.168.1.0/24)"]
    ip_address: String,
    #[description = "Description of this IP entry"] description: Option<String>,
) -> Result<(), Error> {
    ctx.defer_ephemeral().await?;

    // Validate IP format
    match crate::models::whitelist::validate_ip(&ip_address) {
        crate::models::whitelist::IpValidation::InvalidFormat => {
            ctx.say(format!("❌ Invalid IP address format: `{}`", ip_address))
                .await?;
            return Ok(());
        }
        _ => {}
    }

    let state = ctx.data();
    let db = state.db.read().await;

    let added_by = Some(format!("{} (ID: {})", ctx.author().name, ctx.author().id));
    
    match db
        .add_whitelist(&ip_address, description.as_deref(), added_by.as_deref())
        .await
    {
        Ok(id) => {
            let mut embed = CreateEmbed::default();
            embed = embed
                .title("✅ IP Added to Whitelist")
                .description(format!("`{}` has been whitelisted.", ip_address))
                .color(0x2ECC71)
                .field("ID", id.to_string(), true);
            
            if let Some(desc) = description {
                embed = embed.field("Description", desc, true);
            }

            let builder = poise::CreateReply::default().embed(embed).ephemeral(true);
            ctx.send(builder).await?;
        }
        Err(e) => {
            ctx.say(format!("❌ Failed to add IP: {}", e)).await?;
        }
    }

    Ok(())
}

/// Remove an IP address from the whitelist
#[poise::command(slash_command, prefix_command)]
pub async fn whitelist_remove(
    ctx: Context<'_>,
    #[description = "IP address to remove from whitelist"] ip_address: String,
) -> Result<(), Error> {
    ctx.defer_ephemeral().await?;

    let state = ctx.data();
    let db = state.db.read().await;

    match db.remove_whitelist(&ip_address).await {
        Ok(true) => {
            ctx.say(format!(
                "✅ IP address `{}` has been removed from the whitelist.",
                ip_address
            ))
            .await?;
        }
        Ok(false) => {
            ctx.say(format!(
                "⚠️ IP address `{}` was not found in the whitelist.",
                ip_address
            ))
            .await?;
        }
        Err(e) => {
            ctx.say(format!("❌ Failed to remove IP: {}", e)).await?;
        }
    }

    Ok(())
}

/// List all whitelisted IP addresses
#[poise::command(slash_command, prefix_command)]
pub async fn whitelist_list(ctx: Context<'_>) -> Result<(), Error> {
    ctx.defer_ephemeral().await?;

    let state = ctx.data();
    let db = state.db.read().await;

    match db.get_all_whitelist().await {
        Ok(entries) => {
            if entries.is_empty() {
                ctx.say("📋 The whitelist is empty.").await?;
            } else {
                let mut description = String::new();
                for entry in &entries {
                    let status = if entry.is_active { "🟢" } else { "🔴" };
                    let desc = entry.description.as_deref().unwrap_or("No description");
                    let last_used = entry
                        .last_used_at
                        .as_ref()
                        .map(|dt| format_timestamp(dt))
                        .unwrap_or_else(|| "Never".to_string());
                    
                    description.push_str(&format!(
                        "{} `{}` - {} (Requests: {}, Last used: {})\n",
                        status, entry.ip_address, desc, entry.request_count, last_used
                    ));
                }

                let mut embed = CreateEmbed::default();
                embed = embed
                    .title(format!("📋 Whitelist Entries ({})", entries.len()))
                    .description(description)
                    .color(0x3498DB);

                let builder = poise::CreateReply::default().embed(embed).ephemeral(true);
                ctx.send(builder).await?;
            }
        }
        Err(e) => {
            ctx.say(format!("❌ Failed to fetch whitelist: {}", e)).await?;
        }
    }

    Ok(())
}

/// Clear all whitelist entries (admin only)
#[poise::command(slash_command, prefix_command)]
pub async fn whitelist_clear(
    ctx: Context<'_>,
    #[description = "Confirm with 'yes' to clear all entries"] confirm: String,
) -> Result<(), Error> {
    ctx.defer_ephemeral().await?;

    if confirm != "yes" {
        ctx.say("⚠️ Please confirm with `yes` to clear all whitelist entries.").await?;
        return Ok(());
    }

    ctx.say("⚠️ This feature is not yet implemented. Please remove entries individually.").await?;
    Ok(())
}

/// Show statistics
#[poise::command(slash_command, prefix_command)]
pub async fn stats(ctx: Context<'_>) -> Result<(), Error> {
    ctx.defer().await?;

    let state = ctx.data();
    let db = state.db.read().await;

    let mut embed = CreateEmbed::default();
    embed = embed.title("📊 AWD Logger Statistics").color(0x9B59B6);

    // Channel stats
    match db.get_channel_stats().await {
        Ok(stats) => {
            if stats.is_empty() {
                embed = embed.field("📈 Channel Activity", "No recent activity", false);
            } else {
                let mut channel_text = String::new();
                for (channel, stat) in &stats {
                    channel_text.push_str(&format!(
                        "• **{}**: {} logs\n",
                        channel, stat.total_logs
                    ));
                }
                embed = embed.field("📈 Channel Activity (24h)", channel_text, false);
            }
        }
        Err(e) => {
            embed = embed.field("📈 Channel Activity", format!("Error: {}", e), false);
        }
    }

    // Blacklist count
    match db.get_blacklist_count().await {
        Ok(count) => {
            embed = embed.field("🚫 Blacklisted Attempts", count.to_string(), true);
        }
        Err(_) => {}
    }

    // Whitelist count
    match db.get_all_whitelist().await {
        Ok(entries) => {
            embed = embed.field("✅ Whitelisted IPs", entries.len().to_string(), true);
        }
        Err(_) => {}
    }

    let builder = poise::CreateReply::default().embed(embed);
    ctx.send(builder).await?;

    Ok(())
}

/// Channel management commands
#[poise::command(
    slash_command,
    prefix_command,
    subcommands("channel_list", "channel_create", "channel_delete"),
    subcommand_required
)]
pub async fn channel(_ctx: Context<'_>) -> Result<(), Error> {
    Ok(())
}

/// List all logging channels
#[poise::command(slash_command, prefix_command)]
pub async fn channel_list(ctx: Context<'_>) -> Result<(), Error> {
    ctx.defer().await?;

    let guild_id = ctx.guild_id().ok_or("This command must be used in a guild")?;
    
    // Get channels from HTTP API instead of cache to avoid Send issues
    let channels = guild_id.channels(ctx.http()).await?;
    let log_category = ctx.data().config.log_category_name.clone();

    let mut log_channels = Vec::new();
    for (id, channel) in &channels {
        if let Some(parent_id) = channel.parent_id {
            if let Ok(parent) = parent_id.to_channel(ctx).await {
                if let Some(category) = parent.guild() {
                    if category.name == log_category {
                        log_channels.push((channel.name.clone(), *id));
                    }
                }
            }
        }
    }

    let mut embed = CreateEmbed::default();
    embed = embed
        .title(format!("📁 Logging Channels in '{}'", log_category))
        .color(0x3498DB);

    if log_channels.is_empty() {
        embed = embed.description("No logging channels found. Use `/channel create` to create one.");
    } else {
        let description = log_channels
            .iter()
            .map(|(name, id)| format!("• <#{}> - `{}`", id, name))
            .collect::<Vec<_>>()
            .join("\n");
        embed = embed.description(description);
    }

    let builder = poise::CreateReply::default().embed(embed);
    ctx.send(builder).await?;

    Ok(())
}

/// Create a new logging channel
#[poise::command(slash_command, prefix_command)]
pub async fn channel_create(
    ctx: Context<'_>,
    #[description = "Name of the channel to create"] name: String,
) -> Result<(), Error> {
    ctx.defer().await?;

    let guild_id = ctx.guild_id().ok_or("This command must be used in a guild")?;
    let http = ctx.http();
    
    // Find or create the log category
    let category_id = find_or_create_category(http, guild_id, &ctx.data().config.log_category_name)
        .await?;

    // Create the channel
    let channel_id = find_or_create_channel(
        http,
        guild_id,
        category_id,
        &name.to_lowercase().replace(" ", "-"),
    )
    .await?;

    ctx.say(format!(
        "✅ Created logging channel <#{}>",
        channel_id
    ))
    .await?;

    Ok(())
}

/// Delete a logging channel
#[poise::command(slash_command, prefix_command)]
pub async fn channel_delete(
    ctx: Context<'_>,
    #[description = "Channel to delete"] channel: GuildChannel,
) -> Result<(), Error> {
    ctx.defer().await?;

    let channel_name = channel.name.clone();

    // Delete the channel
    channel.delete(ctx).await?;

    ctx.say(format!("🗑️ Deleted channel `{}`", channel_name)).await?;

    Ok(())
}
