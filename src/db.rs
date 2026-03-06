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

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{bail, Context, Result};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use rusqlite::{params, Connection};
use std::path::PathBuf;

use crate::router::{RouterConfig, RouterVendor};
use uuid::Uuid;

// ─── Default routers (seeded on first run) ───────────────────────────────────

fn default_routers() -> Vec<RouterConfig> {
    vec![
        RouterConfig { id: Uuid::new_v4(), name: "eqx-master".into(), hostname: "192.168.122.227".into(), vendor: RouterVendor::Cisco, ssh_port: 22, username: "admin".into(), password: None, local_as: None, router_id: None },
        RouterConfig { id: Uuid::new_v4(), name: "eqx-slave".into(),  hostname: "192.168.122.187".into(), vendor: RouterVendor::Cisco, ssh_port: 22, username: "admin".into(), password: None, local_as: None, router_id: None },
        RouterConfig { id: Uuid::new_v4(), name: "kkb-master".into(), hostname: "192.168.122.184".into(), vendor: RouterVendor::Cisco, ssh_port: 22, username: "admin".into(), password: None, local_as: None, router_id: None },
        RouterConfig { id: Uuid::new_v4(), name: "kkb-slave".into(),  hostname: "192.168.122.34".into(),  vendor: RouterVendor::Cisco, ssh_port: 22, username: "admin".into(), password: None, local_as: None, router_id: None },
    ]
}

// ─── Crypto ──────────────────────────────────────────────────────────────────

/// Derive a 32-byte AES key from `passphrase` + `salt_b64`.
fn derive_key(passphrase: &str, salt_b64: &str) -> Result<[u8; 32]> {
    let salt_bytes = B64.decode(salt_b64).context("invalid stored salt")?;
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &salt_bytes, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2 error: {e}"))?;
    Ok(key)
}

/// Encrypt plaintext → base64(nonce || ciphertext).
fn encrypt(key_bytes: &[u8; 32], plaintext: &str) -> Result<String> {
    let key    = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce      = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("encrypt error: {e}"))?;
    let mut blob = nonce_bytes.to_vec();
    blob.extend_from_slice(&ciphertext);
    Ok(B64.encode(blob))
}

/// Decrypt base64(nonce || ciphertext) → plaintext.
fn decrypt(key_bytes: &[u8; 32], b64: &str) -> Result<String> {
    let blob = B64.decode(b64).context("invalid base64 in db")?;
    if blob.len() < 12 {
        bail!("blob too short");
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let key    = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce  = Nonce::from_slice(nonce_bytes);
    let plain  = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong passphrase?"))?;
    String::from_utf8(plain).context("decrypted password not utf-8")
}

// ─── Database ─────────────────────────────────────────────────────────────────

pub struct RouterDb {
    conn:    Connection,
    key:     [u8; 32],
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
        let conn = Connection::open(&path)
            .with_context(|| format!("opening db at {}", path.display()))?;

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
                 router_id    TEXT
             );",
        )?;

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

        let key = derive_key(passphrase, &salt_b64)?;
        let db = Self { conn, key };

        // Seed default routers on first ever run (empty table)
        if db.load_all()?.is_empty() {
            for r in &default_routers() {
                db.upsert(r)?;
            }
        }

        Ok(db)
    }

    // ── CRUD ──────────────────────────────────────────────────────────────────

    pub fn load_all(&self) -> Result<Vec<RouterConfig>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, hostname, vendor, ssh_port, username,
                    password_enc, local_as, router_id
             FROM routers ORDER BY rowid",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,   // id
                row.get::<_, String>(1)?,   // name
                row.get::<_, String>(2)?,   // hostname
                row.get::<_, String>(3)?,   // vendor
                row.get::<_, u16>(4)?,      // ssh_port
                row.get::<_, String>(5)?,   // username
                row.get::<_, Option<String>>(6)?,  // password_enc
                row.get::<_, Option<u32>>(7)?,     // local_as
                row.get::<_, Option<String>>(8)?,  // router_id
            ))
        })?;

        let mut routers = Vec::new();
        for row in rows {
            let (id_s, name, hostname, vendor_s, ssh_port, username,
                 password_enc, local_as, router_id_s) = row?;

            let password = if let Some(enc) = password_enc {
                match decrypt(&self.key, &enc) {
                    Ok(p)  => Some(p),
                    Err(e) => {
                        eprintln!("warn: could not decrypt password for {name}: {e}");
                        None
                    }
                }
            } else {
                None
            };

            let id: uuid::Uuid = id_s.parse().unwrap_or_else(|_| uuid::Uuid::new_v4());
            let router_id = router_id_s.and_then(|s| s.parse().ok());
            let vendor = match vendor_s.to_lowercase().as_str() {
                "vyos" => RouterVendor::VyOs,
                _      => RouterVendor::Cisco,
            };

            routers.push(RouterConfig {
                id,
                name,
                hostname,
                vendor,
                ssh_port,
                username,
                password,
                local_as,
                router_id,
            });
        }
        Ok(routers)
    }

    pub fn upsert(&self, r: &RouterConfig) -> Result<()> {
        let password_enc = if let Some(pw) = &r.password {
            Some(encrypt(&self.key, pw)?)
        } else {
            None
        };
        let router_id_s = r.router_id.map(|ip| ip.to_string());
        self.conn.execute(
            "INSERT INTO routers
                 (id, name, hostname, vendor, ssh_port, username,
                  password_enc, local_as, router_id)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(id) DO UPDATE SET
                 name         = excluded.name,
                 hostname     = excluded.hostname,
                 vendor       = excluded.vendor,
                 ssh_port     = excluded.ssh_port,
                 username     = excluded.username,
                 password_enc = excluded.password_enc,
                 local_as     = excluded.local_as,
                 router_id    = excluded.router_id",
            params![
                r.id.to_string(),
                r.name,
                r.hostname,
                r.vendor.to_string(),
                r.ssh_port,
                r.username,
                password_enc,
                r.local_as,
                router_id_s,
            ],
        )?;
        Ok(())
    }

    pub fn delete(&self, id: uuid::Uuid) -> Result<()> {
        self.conn.execute(
            "DELETE FROM routers WHERE id = ?1",
            params![id.to_string()],
        )?;
        Ok(())
    }

    pub fn save_all(&self, routers: &[RouterConfig]) -> Result<()> {
        // Replace entire set with a transaction
        let tx = self.conn.unchecked_transaction()?;
        self.conn.execute("DELETE FROM routers", [])?;
        for r in routers {
            self.upsert(r)?;
        }
        tx.commit()?;
        Ok(())
    }
}
