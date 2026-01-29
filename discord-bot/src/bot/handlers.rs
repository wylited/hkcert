use serenity::async_trait;
use serenity::model::prelude::*;
use serenity::prelude::*;
use tracing::{info, debug};

pub struct Handler;

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        info!("✅ Connected as {}", ready.user.name);
        
        // Set bot presence
        let activity = Activity::watching("AWD Competition Logs");
        ctx.set_presence(Some(activity), OnlineStatus::Online).await;
    }

    async fn guild_create(&self, _ctx: Context, guild: Guild, _is_new: Option<bool>) {
        debug!("📊 Guild available: {} ({})", guild.name, guild.id);
    }

    async fn message(&self, ctx: Context, msg: Message) {
        // Ignore bot messages
        if msg.author.bot {
            return;
        }

        debug!("💬 Message in #{}: {}", msg.channel_id, msg.content);
    }
}
