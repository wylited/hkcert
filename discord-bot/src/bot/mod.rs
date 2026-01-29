use crate::models::AppState;
use anyhow::Result;
use poise::serenity_prelude as serenity;
use std::sync::Arc;
use tracing::{info, warn};

mod commands;
mod handlers;

pub use commands::*;

/// Bot error type
type Error = Box<dyn std::error::Error + Send + Sync>;
type Context<'a> = poise::Context<'a, Arc<AppState>, Error>;

/// Start the Discord bot
pub async fn start_bot(state: Arc<AppState>) -> Result<()> {
    let token = state.config.discord_token.clone();
    let guild_id = state.config.guild_id;
    
    let framework = poise::Framework::builder()
        .options(poise::FrameworkOptions {
            commands: vec![
                help(),
                whitelist(),
                stats(),
                channel(),
                ping(),
            ],
            prefix_options: poise::PrefixFrameworkOptions {
                prefix: Some("!".into()),
                case_insensitive_commands: true,
                ..Default::default()
            },
            on_error: |error| {
                Box::pin(async move {
                    match error {
                        poise::FrameworkError::Setup { error, .. } => {
                            warn!("Error in setup: {}", error);
                        }
                        poise::FrameworkError::Command { error, ctx, .. } => {
                            warn!("Error in command `{}`: {}", ctx.command().name, error);
                            let _ = ctx.say(format!("❌ An error occurred: {}", error)).await;
                        }
                        _ => {
                            warn!("Other framework error: {:?}", error);
                        }
                    }
                })
            },
            ..Default::default()
        })
        .setup(move |ctx, _ready, framework| {
            Box::pin(async move {
                info!("🤖 Discord bot is connected!");
                
                // Register slash commands
                poise::builtins::register_globally(ctx, &framework.options().commands).await?;
                
                // Register guild-specific commands if guild ID is provided
                if let Some(gid) = guild_id {
                    let guild_id = serenity::GuildId::new(gid);
                    poise::builtins::register_in_guild(ctx, &framework.options().commands, guild_id).await?;
                    info!("✅ Slash commands registered for guild {}", guild_id);
                }
                
                Ok(state)
            })
        })
        .build();

    let intents = serenity::GatewayIntents::non_privileged()
        | serenity::GatewayIntents::GUILD_MESSAGES
        | serenity::GatewayIntents::GUILDS;

    let mut client = serenity::Client::builder(&token, intents)
        .framework(framework)
        .await?;

    client.start().await?;
    Ok(())
}

/// Help command
#[poise::command(slash_command, prefix_command, track_edits)]
async fn help(
    ctx: Context<'_>,
    #[description = "Command to show help for"] command: Option<String>,
) -> Result<(), Error> {
    let config = poise::builtins::HelpConfiguration {
        extra_text_at_bottom: "AWD Logger - A comprehensive logging system for Attack With Defense competitions.",
        show_context_menu_commands: true,
        ..Default::default()
    };
    poise::builtins::help(ctx, command.as_deref(), config).await?;
    Ok(())
}

/// Ping command - check bot latency
#[poise::command(slash_command, prefix_command)]
async fn ping(ctx: Context<'_>) -> Result<(), Error> {
    let response = ctx.say("🏓 Pinging...").await?;
    
    let ping = ctx.ping().await.as_millis();
    
    let content = format!(
        "🏓 Pong! Latency: `{}ms`\n🤖 Bot is operational!",
        ping
    );
    
    response
        .edit(ctx, poise::CreateReply::default().content(content))
        .await?;
    
    Ok(())
}
