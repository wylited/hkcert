use serenity::async_trait;
use serenity::model::gateway::Ready;
use serenity::model::prelude::*;
use serenity::prelude::*;
use tracing::{info, debug};

pub struct Handler;

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, _ctx: Context, ready: Ready) {
        info!("✅ Connected as {}", ready.user.name);
    }

    async fn guild_create(&self, _ctx: Context, guild: Guild, _is_new: Option<bool>) {
        debug!("📊 Guild available: {} ({})", guild.name, guild.id);
    }

    async fn message(&self, _ctx: Context, msg: Message) {
        if msg.author.bot {
            return;
        }
        debug!("💬 Message in #{}: {}", msg.channel_id, msg.content);
    }
}
