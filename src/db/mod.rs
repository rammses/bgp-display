// SQLite-backed router config store with AES-256-GCM encrypted passwords.
//
// Schema:
//   routers(id TEXT PK, name, hostname, vendor, ssh_port, username,
//           password_enc TEXT nullable, local_as INTEGER nullable,
//           router_id TEXT nullable)
//
// password_enc is base64( nonce(12) || ciphertext ), encrypted under a
// 32-byte key derived from the user's passphrase via Argon2id.
//
// The salt used for key-derivation is stored in the DB itself (kv table) so
// the same passphrase always produces the same key for a given database.

mod config_history;
mod crypto;
mod neighbors;
mod projects;
mod routers;
mod templates;

pub use config_history::ConfigHistoryEntry;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use rusqlite::{params, Connection};
use std::path::PathBuf;

// No default routers — users add their own via the Router Editor tab.

pub struct RouterDb {
    pub(crate) conn: Connection,
    pub(crate) key: [u8; 32],
}

impl RouterDb {
    fn db_path() -> PathBuf {
        // On macOS this resolves to ~/Library/Application Support/bgp-link-manager/
        // On Linux this resolves to ~/.local/share/bgp-link-manager/
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("bgp-link-manager")
            .join("routers.db")
    }

    /// Open (or create) the database. `passphrase` is used to derive the
    /// AES key. On first run a random Argon2 salt is generated and stored.
    pub fn open(passphrase: &str) -> Result<Self> {
        let path = Self::db_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn =
            Connection::open(&path).with_context(|| format!("opening db at {}", path.display()))?;

        Self::initialize(conn, passphrase)
    }

    #[cfg(test)]
    pub(crate) fn in_memory() -> Result<Self> {
        Self::initialize(Connection::open_in_memory()?, "synthetic-test-passphrase")
    }

    fn initialize(conn: Connection, passphrase: &str) -> Result<Self> {
        // Create tables
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (
                 key   TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS routers (
                 id           TEXT PRIMARY KEY,
                 name         TEXT NOT NULL,
                 hostname     TEXT NOT NULL,
                 vendor       TEXT NOT NULL DEFAULT 'Cisco',
                 ssh_port     INTEGER NOT NULL DEFAULT 22,
                 username     TEXT NOT NULL DEFAULT 'admin',
                 password_enc TEXT,
                 local_as     INTEGER,
                 router_id    TEXT,
                 vdom         TEXT,
                 mikrotik_instance TEXT
             );",
        )?;

        ensure_router_columns(&conn)?;

        // Get or create salt
        let salt_b64: String = match conn.query_row(
            "SELECT value FROM kv WHERE key = 'argon2_salt'",
            [],
            |row| row.get(0),
        ) {
            Ok(s) => s,
            Err(_) => {
                // Generate fresh 16-byte random salt, store as standard base64
                let mut salt_bytes = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut salt_bytes);
                let s = B64.encode(salt_bytes);
                conn.execute(
                    "INSERT INTO kv(key, value) VALUES ('argon2_salt', ?1)",
                    params![s],
                )?;
                s
            }
        };

        let key = crypto::derive_key(passphrase, &salt_b64)?;
        let db = Self { conn, key };

        // Projects tables
        db.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS projects (
                 id   TEXT PRIMARY KEY,
                 name TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS project_routers (
                 project_id TEXT NOT NULL,
                 router_id  TEXT NOT NULL,
                 PRIMARY KEY (project_id, router_id)
             );",
        )?;

        // Neighbors table (desired-state tracking)
        db.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS neighbors (
                 id            TEXT PRIMARY KEY,
                 router_id     TEXT NOT NULL,
                 neighbor_ip   TEXT NOT NULL,
                 remote_as     INTEGER NOT NULL,
                 description   TEXT NOT NULL,
                 update_source TEXT,
                 next_hop_self INTEGER NOT NULL DEFAULT 0,
                 rr_client     INTEGER NOT NULL DEFAULT 0,
                 hold_time     INTEGER NOT NULL DEFAULT 180,
                 keepalive     INTEGER NOT NULL DEFAULT 60,
                 password_enc  TEXT,
                 bfd           INTEGER NOT NULL DEFAULT 0,
                 soft_reconfig INTEGER NOT NULL DEFAULT 1,
                 created_at    TEXT NOT NULL,
                 updated_at    TEXT NOT NULL,
                 UNIQUE(router_id, neighbor_ip)
             );",
        )?;

        // Config history table (rollback support)
        db.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS config_history (
                 id          TEXT PRIMARY KEY,
                 router_id   TEXT NOT NULL,
                 action      TEXT NOT NULL,
                 description TEXT NOT NULL,
                 commands    TEXT NOT NULL,
                 rollback    TEXT NOT NULL,
                 applied_at  TEXT NOT NULL
             );",
        )?;

        // Peer templates table
        db.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS peer_templates (
                 id                TEXT PRIMARY KEY,
                 name              TEXT NOT NULL UNIQUE,
                 remote_as         TEXT,
                 description_prefix TEXT,
                 update_source     TEXT,
                 next_hop_self     INTEGER NOT NULL DEFAULT 0,
                 rr_client         INTEGER NOT NULL DEFAULT 0,
                 hold_time         INTEGER NOT NULL DEFAULT 180,
                 keepalive         INTEGER NOT NULL DEFAULT 60,
                 bfd               INTEGER NOT NULL DEFAULT 0,
                 soft_reconfig     INTEGER NOT NULL DEFAULT 1
             );",
        )?;

        Ok(db)
    }
}

fn ensure_router_columns(conn: &Connection) -> Result<()> {
    let mut statement = conn
        .prepare("PRAGMA table_info(routers)")
        .context("inspect router schema")?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    anyhow::ensure!(!names.is_empty(), "router schema missing");
    for column in ["vdom", "mikrotik_instance"] {
        if !names.iter().any(|name| name == column) {
            conn.execute(&format!("ALTER TABLE routers ADD COLUMN {column} TEXT"), [])
                .with_context(|| format!("add routers.{column}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::{RouterConfig, RouterVendor};

    #[test]
    fn mikrotik_persistence_old_schema_preserves_ciphertext_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE routers (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, hostname TEXT NOT NULL,
            vendor TEXT NOT NULL DEFAULT 'Cisco', ssh_port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL DEFAULT 'admin', password_enc TEXT,
            local_as INTEGER, router_id TEXT);",
        )
        .unwrap();
        let key = [7; 32];
        let cipher = crypto::encrypt(&key, "synthetic-test-password").unwrap();
        conn.execute(
            "INSERT INTO routers(id,name,hostname,vendor,password_enc,local_as)
            VALUES (?1,'old','lab.invalid','citrix',?2,65000)",
            params![uuid::Uuid::nil().to_string(), cipher],
        )
        .unwrap();
        ensure_router_columns(&conn).unwrap();
        ensure_router_columns(&conn).unwrap();
        let db = RouterDb { conn, key };
        let rows = db.load_all().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].vendor, RouterVendor::CitrixVpx);
        assert_eq!(rows[0].password.as_deref(), Some("synthetic-test-password"));
        assert_eq!(rows[0].local_as, Some(65000));
        assert_eq!(rows[0].mikrotik_instance, None);
        assert_eq!(
            db.conn
                .query_row("SELECT password_enc FROM routers", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            cipher
        );
    }

    #[test]
    fn mikrotik_persistence_reports_migration_errors() {
        let conn = Connection::open_in_memory().unwrap();
        assert!(ensure_router_columns(&conn).is_err());
        conn.execute_batch("CREATE VIEW routers AS SELECT 1 AS id;")
            .unwrap();
        assert!(ensure_router_columns(&conn).is_err());
    }

    #[test]
    fn mikrotik_persistence_roundtrip_nullable_scope_and_vendor() {
        let db = RouterDb::in_memory().unwrap();
        let mut router = RouterConfig {
            vendor: RouterVendor::MikroTik,
            mikrotik_instance: Some("blue".into()),
            password: Some("synthetic-test-password".into()),
            ..RouterConfig::default()
        };
        db.upsert(&router).unwrap();
        let rows = db.load_all().unwrap();
        assert_eq!(rows[0].vendor, RouterVendor::MikroTik);
        assert_eq!(rows[0].mikrotik_instance.as_deref(), Some("blue"));
        assert_eq!(rows[0].password, router.password);
        assert_ne!(
            db.conn
                .query_row("SELECT password_enc FROM routers", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "synthetic-test-password"
        );
        router.mikrotik_instance = None;
        db.upsert(&router).unwrap();
        assert_eq!(db.load_all().unwrap()[0].mikrotik_instance, None);
    }
}
