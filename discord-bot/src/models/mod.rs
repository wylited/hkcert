use crate::config::AppConfig;
use crate::db::Database;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod log_entry;
pub mod whitelist;

/// Shared application state
#[derive(Debug)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: Arc<RwLock<Database>>,
}

impl AppState {
    /// Get a clone of the database handle
    pub fn db(&self) -> Arc<RwLock<Database>> {
        self.db.clone()
    }
}
