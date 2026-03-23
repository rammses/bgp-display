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

use crate::bgp::{NeighborDraft, PeerTemplate};
use crate::router::{RouterConfig, RouterVendor};
use chrono::Utc;
use uuid::Uuid;

// No default routers — users add their own via the Router Editor tab.

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
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
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
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plain = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong passphrase?"))?;
    String::from_utf8(plain).context("decrypted password not utf-8")
}

// ─── Database ─────────────────────────────────────────────────────────────────

pub struct RouterDb {
    conn: Connection,
    key: [u8; 32],
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
                 vdom         TEXT
             );",
        )?;

        // Migrate: add vdom column to existing databases that predate this field.
        let _ = conn.execute("ALTER TABLE routers ADD COLUMN vdom TEXT", []);

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

    // ── CRUD ──────────────────────────────────────────────────────────────────

    pub fn load_all(&self) -> Result<Vec<RouterConfig>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, hostname, vendor, ssh_port, username,
                    password_enc, local_as, router_id, vdom
             FROM routers ORDER BY rowid",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,         // id
                row.get::<_, String>(1)?,         // name
                row.get::<_, String>(2)?,         // hostname
                row.get::<_, String>(3)?,         // vendor
                row.get::<_, u16>(4)?,            // ssh_port
                row.get::<_, String>(5)?,         // username
                row.get::<_, Option<String>>(6)?, // password_enc
                row.get::<_, Option<u32>>(7)?,    // local_as
                row.get::<_, Option<String>>(8)?, // router_id
                row.get::<_, Option<String>>(9)?, // vdom
            ))
        })?;

        let mut routers = Vec::new();
        for row in rows {
            let (
                id_s,
                name,
                hostname,
                vendor_s,
                ssh_port,
                username,
                password_enc,
                local_as,
                router_id_s,
                vdom,
            ) = row?;

            let password = if let Some(enc) = password_enc {
                match decrypt(&self.key, &enc) {
                    Ok(p) => Some(p),
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
                "citrixvpx" | "citrix" => RouterVendor::CitrixVpx,
                "pfsense" => RouterVendor::PfSense,
                "fortigate" => RouterVendor::FortiGate,
                _ => RouterVendor::Cisco,
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
                vdom,
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
                  password_enc, local_as, router_id, vdom)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(id) DO UPDATE SET
                 name         = excluded.name,
                 hostname     = excluded.hostname,
                 vendor       = excluded.vendor,
                 ssh_port     = excluded.ssh_port,
                 username     = excluded.username,
                 password_enc = excluded.password_enc,
                 local_as     = excluded.local_as,
                 router_id    = excluded.router_id,
                 vdom         = excluded.vdom",
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
                r.vdom,
            ],
        )?;
        Ok(())
    }

    pub fn delete(&self, id: uuid::Uuid) -> Result<()> {
        self.conn
            .execute("DELETE FROM routers WHERE id = ?1", params![id.to_string()])?;
        Ok(())
    }

    // ── Project CRUD ──────────────────────────────────────────────────────────

    pub fn load_projects(&self) -> Result<Vec<crate::router::Project>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name FROM projects ORDER BY rowid")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut projects = Vec::new();
        for row in rows {
            let (id_s, name) = row?;
            let id: uuid::Uuid = id_s.parse().unwrap_or_else(|_| uuid::Uuid::new_v4());

            let mut rstmt = self
                .conn
                .prepare("SELECT router_id FROM project_routers WHERE project_id = ?1")?;
            let rids: Vec<uuid::Uuid> = rstmt
                .query_map(params![id_s], |r| r.get::<_, String>(0))?
                .filter_map(|r| r.ok().and_then(|s| s.parse().ok()))
                .collect();

            projects.push(crate::router::Project {
                id,
                name,
                router_ids: rids,
            });
        }
        Ok(projects)
    }

    pub fn upsert_project(&self, p: &crate::router::Project) -> Result<()> {
        let id_s = p.id.to_string();
        self.conn.execute(
            "INSERT INTO projects (id, name) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name",
            params![id_s, p.name],
        )?;
        // Rebuild router membership
        self.conn.execute(
            "DELETE FROM project_routers WHERE project_id = ?1",
            params![id_s],
        )?;
        for rid in &p.router_ids {
            self.conn.execute(
                "INSERT INTO project_routers (project_id, router_id) VALUES (?1, ?2)",
                params![id_s, rid.to_string()],
            )?;
        }
        Ok(())
    }

    pub fn delete_project(&self, id: uuid::Uuid) -> Result<()> {
        let id_s = id.to_string();
        self.conn.execute(
            "DELETE FROM project_routers WHERE project_id = ?1",
            params![id_s],
        )?;
        self.conn
            .execute("DELETE FROM projects WHERE id = ?1", params![id_s])?;
        Ok(())
    }

    // ── Neighbor CRUD ─────────────────────────────────────────────────────────

    pub fn upsert_neighbor(&self, router_id: Uuid, draft: &NeighborDraft) -> Result<Uuid> {
        let id = draft.id.unwrap_or_else(Uuid::new_v4);
        let now = Utc::now().to_rfc3339();
        let created = draft
            .created_at
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| now.clone());
        let remote_as: u32 = draft.remote_as.trim().parse().unwrap_or(0);
        let password_enc = if draft.password.is_empty() {
            None
        } else {
            Some(encrypt(&self.key, &draft.password)?)
        };

        self.conn.execute(
            "INSERT INTO neighbors
                 (id, router_id, neighbor_ip, remote_as, description,
                  update_source, next_hop_self, rr_client, hold_time, keepalive,
                  password_enc, bfd, soft_reconfig, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
             ON CONFLICT(router_id, neighbor_ip) DO UPDATE SET
                 remote_as     = excluded.remote_as,
                 description   = excluded.description,
                 update_source = excluded.update_source,
                 next_hop_self = excluded.next_hop_self,
                 rr_client     = excluded.rr_client,
                 hold_time     = excluded.hold_time,
                 keepalive     = excluded.keepalive,
                 password_enc  = excluded.password_enc,
                 bfd           = excluded.bfd,
                 soft_reconfig = excluded.soft_reconfig,
                 updated_at    = excluded.updated_at",
            params![
                id.to_string(),
                router_id.to_string(),
                draft.neighbor_ip.trim(),
                remote_as,
                draft.description.trim(),
                if draft.update_source.is_empty() {
                    None
                } else {
                    Some(draft.update_source.trim().to_string())
                },
                draft.next_hop_self as i32,
                draft.route_reflector_client as i32,
                draft.hold_time.trim().parse::<u16>().unwrap_or(180) as i32,
                draft.keepalive.trim().parse::<u16>().unwrap_or(60) as i32,
                password_enc,
                draft.bfd as i32,
                draft.soft_reconfiguration_inbound as i32,
                created,
                now,
            ],
        )?;
        Ok(id)
    }

    pub fn delete_neighbor(&self, router_id: Uuid, neighbor_ip: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM neighbors WHERE router_id = ?1 AND neighbor_ip = ?2",
            params![router_id.to_string(), neighbor_ip.trim()],
        )?;
        Ok(())
    }

    pub fn load_neighbors(&self, router_id: Uuid) -> Result<Vec<NeighborDraft>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, neighbor_ip, remote_as, description, update_source,
                    next_hop_self, rr_client, hold_time, keepalive,
                    password_enc, bfd, soft_reconfig, created_at, updated_at
             FROM neighbors WHERE router_id = ?1 ORDER BY neighbor_ip",
        )?;

        let rows = stmt.query_map(params![router_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i32>(5)?,
                row.get::<_, i32>(6)?,
                row.get::<_, i32>(7)?,
                row.get::<_, i32>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, i32>(10)?,
                row.get::<_, i32>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, String>(13)?,
            ))
        })?;

        let mut drafts = Vec::new();
        for row in rows {
            let (
                id_s,
                neighbor_ip,
                remote_as,
                description,
                update_source,
                nhs,
                rrc,
                hold,
                keep,
                pw_enc,
                bfd,
                soft,
                created_s,
                updated_s,
            ) = row?;

            let password = if let Some(enc) = pw_enc {
                decrypt(&self.key, &enc).unwrap_or_default()
            } else {
                String::new()
            };

            let af = crate::bgp::AddressFamily::from_ip(&neighbor_ip);
            let mut draft = NeighborDraft::default();
            draft.id = id_s.parse().ok();
            draft.router_id = Some(router_id);
            draft.neighbor_ip = neighbor_ip;
            draft.remote_as = remote_as.to_string();
            draft.description = description;
            draft.update_source = update_source.unwrap_or_default();
            draft.next_hop_self = nhs != 0;
            draft.route_reflector_client = rrc != 0;
            draft.hold_time = hold.to_string();
            draft.keepalive = keep.to_string();
            draft.password = password;
            draft.bfd = bfd != 0;
            draft.soft_reconfiguration_inbound = soft != 0;
            draft.address_family = af;
            draft.created_at = chrono::DateTime::parse_from_rfc3339(&created_s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc));
            draft.updated_at = chrono::DateTime::parse_from_rfc3339(&updated_s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc));
            drafts.push(draft);
        }
        Ok(drafts)
    }

    pub fn load_all_neighbors(&self) -> Result<std::collections::HashMap<Uuid, Vec<NeighborDraft>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT router_id FROM neighbors")?;
        let rids: Vec<Uuid> = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok().and_then(|s| s.parse().ok()))
            .collect();

        let mut map = std::collections::HashMap::new();
        for rid in rids {
            map.insert(rid, self.load_neighbors(rid)?);
        }
        Ok(map)
    }

    // ── Peer Template CRUD ─────────────────────────────────────────────────────

    pub fn upsert_peer_template(&self, t: &PeerTemplate) -> Result<()> {
        self.conn.execute(
            "INSERT INTO peer_templates
                 (id, name, remote_as, description_prefix, update_source,
                  next_hop_self, rr_client, hold_time, keepalive, bfd, soft_reconfig)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
             ON CONFLICT(id) DO UPDATE SET
                 name              = excluded.name,
                 remote_as         = excluded.remote_as,
                 description_prefix = excluded.description_prefix,
                 update_source     = excluded.update_source,
                 next_hop_self     = excluded.next_hop_self,
                 rr_client         = excluded.rr_client,
                 hold_time         = excluded.hold_time,
                 keepalive         = excluded.keepalive,
                 bfd               = excluded.bfd,
                 soft_reconfig     = excluded.soft_reconfig",
            params![
                t.id.to_string(),
                t.name,
                t.remote_as,
                t.description_prefix,
                if t.update_source.is_empty() { None } else { Some(&t.update_source) },
                t.next_hop_self as i32,
                t.route_reflector_client as i32,
                t.hold_time.trim().parse::<u16>().unwrap_or(180) as i32,
                t.keepalive.trim().parse::<u16>().unwrap_or(60) as i32,
                t.bfd as i32,
                t.soft_reconfiguration_inbound as i32,
            ],
        )?;
        Ok(())
    }

    pub fn delete_peer_template(&self, id: Uuid) -> Result<()> {
        self.conn.execute(
            "DELETE FROM peer_templates WHERE id = ?1",
            params![id.to_string()],
        )?;
        Ok(())
    }

    pub fn load_peer_templates(&self) -> Result<Vec<PeerTemplate>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, remote_as, description_prefix, update_source,
                    next_hop_self, rr_client, hold_time, keepalive, bfd, soft_reconfig
             FROM peer_templates ORDER BY name",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i32>(5)?,
                row.get::<_, i32>(6)?,
                row.get::<_, i32>(7)?,
                row.get::<_, i32>(8)?,
                row.get::<_, i32>(9)?,
                row.get::<_, i32>(10)?,
            ))
        })?;

        let mut templates = Vec::new();
        for row in rows {
            let (id_s, name, remote_as, desc_prefix, update_src, nhs, rrc, hold, keep, bfd, soft) =
                row?;
            templates.push(PeerTemplate {
                id: id_s.parse().unwrap_or_else(|_| Uuid::new_v4()),
                name,
                remote_as,
                description_prefix: desc_prefix,
                update_source: update_src.unwrap_or_default(),
                next_hop_self: nhs != 0,
                route_reflector_client: rrc != 0,
                hold_time: hold.to_string(),
                keepalive: keep.to_string(),
                bfd: bfd != 0,
                soft_reconfiguration_inbound: soft != 0,
            });
        }
        Ok(templates)
    }

    // ── Config History ────────────────────────────────────────────────────────

    pub fn insert_config_history(
        &self,
        router_id: Uuid,
        action: &str,
        description: &str,
        commands: &[String],
        rollback: &[String],
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let now = Utc::now().to_rfc3339();
        let cmd_json =
            serde_json::to_string(commands).unwrap_or_else(|_| "[]".into());
        let rb_json =
            serde_json::to_string(rollback).unwrap_or_else(|_| "[]".into());

        self.conn.execute(
            "INSERT INTO config_history (id, router_id, action, description, commands, rollback, applied_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                id.to_string(),
                router_id.to_string(),
                action,
                description,
                cmd_json,
                rb_json,
                now,
            ],
        )?;
        Ok(id)
    }

    pub fn load_config_history(&self, router_id: Uuid) -> Result<Vec<ConfigHistoryEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, action, description, commands, rollback, applied_at
             FROM config_history WHERE router_id = ?1
             ORDER BY applied_at DESC LIMIT 50",
        )?;

        let rows = stmt.query_map(params![router_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;

        let mut entries = Vec::new();
        for row in rows {
            let (id_s, action, desc, cmd_json, rb_json, applied) = row?;
            entries.push(ConfigHistoryEntry {
                id: id_s.parse().unwrap_or_else(|_| Uuid::new_v4()),
                router_id,
                action,
                description: desc,
                commands: serde_json::from_str(&cmd_json).unwrap_or_default(),
                rollback: serde_json::from_str(&rb_json).unwrap_or_default(),
                applied_at: applied,
            });
        }
        Ok(entries)
    }

    pub fn get_config_entry(&self, id: Uuid) -> Result<Option<ConfigHistoryEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT router_id, action, description, commands, rollback, applied_at
             FROM config_history WHERE id = ?1",
        )?;

        let result = stmt
            .query_row(params![id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .ok();

        Ok(result.map(|(rid_s, action, desc, cmd_json, rb_json, applied)| {
            ConfigHistoryEntry {
                id,
                router_id: rid_s.parse().unwrap_or_else(|_| Uuid::new_v4()),
                action,
                description: desc,
                commands: serde_json::from_str(&cmd_json).unwrap_or_default(),
                rollback: serde_json::from_str(&rb_json).unwrap_or_default(),
                applied_at: applied,
            }
        }))
    }
}

#[derive(Debug, Clone)]
pub struct ConfigHistoryEntry {
    pub id: Uuid,
    pub router_id: Uuid,
    pub action: String,
    pub description: String,
    pub commands: Vec<String>,
    pub rollback: Vec<String>,
    pub applied_at: String,
}
