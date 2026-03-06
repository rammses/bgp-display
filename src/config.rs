use crate::{db::RouterDb, router::RouterConfig};
use anyhow::Result;

// ─── In-memory Application Config ────────────────────────────────────────────
//
// Persistence is handled by RouterDb (SQLite + AES-256-GCM).
// All mutations are auto-saved — no manual save step required.

#[derive(Debug, Clone, Default)]
pub struct AppConfig {
    pub routers: Vec<RouterConfig>,
}

impl AppConfig {
    /// Open the encrypted SQLite database and load all routers.
    /// On first run the DB is created and seeded with default routers.
    pub fn load_with_key(passphrase: &str) -> Result<(Self, RouterDb)> {
        let db = RouterDb::open(passphrase)?;
        let routers = db.load_all()?;
        Ok((Self { routers }, db))
    }
}
