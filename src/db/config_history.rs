use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::params;
use uuid::Uuid;

use super::crypto::{decrypt, encrypt};
use super::RouterDb;

fn decode_commands(key: &[u8; 32], value: &str) -> Result<Vec<String>> {
    let json = if let Some(ciphertext) = value.strip_prefix("enc:") {
        decrypt(key, ciphertext).context("decrypting config history")?
    } else {
        value.to_string()
    };
    serde_json::from_str(&json).context("parsing config history commands")
}

#[derive(Debug, Clone)]
pub struct ConfigHistoryEntry {
    pub id: Uuid,
    pub router_id: Uuid,
    pub action: String,
    pub description: String,
    #[allow(dead_code)]
    pub commands: Vec<String>,
    pub rollback: Vec<String>,
    pub applied_at: String,
}

impl RouterDb {
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
        let cmd_json = format!(
            "enc:{}",
            encrypt(&self.key, &serde_json::to_string(commands)?)?
        );
        let rb_json = format!(
            "enc:{}",
            encrypt(&self.key, &serde_json::to_string(rollback)?)?
        );

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
                commands: decode_commands(&self.key, &cmd_json)?,
                rollback: decode_commands(&self.key, &rb_json)?,
                applied_at: applied,
            });
        }
        Ok(entries)
    }

    #[allow(dead_code)]
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

        result
            .map(|(rid_s, action, desc, cmd_json, rb_json, applied)| {
                Ok(ConfigHistoryEntry {
                    id,
                    router_id: rid_s.parse().unwrap_or_else(|_| Uuid::new_v4()),
                    action,
                    description: desc,
                    commands: decode_commands(&self.key, &cmd_json)?,
                    rollback: decode_commands(&self.key, &rb_json)?,
                    applied_at: applied,
                })
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_encrypts_commands_and_can_read_them_back() -> Result<()> {
        let conn = rusqlite::Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE config_history (
                id TEXT PRIMARY KEY, router_id TEXT, action TEXT, description TEXT,
                commands TEXT, rollback TEXT, applied_at TEXT);",
        )?;
        let db = RouterDb { conn, key: [7; 32] };
        let router_id = Uuid::new_v4();
        let command =
            "nv set vrf default router bgp neighbor swp51 password 'test-secret'".to_string();
        db.insert_config_history(router_id, "create", "test", &[command.clone()], &[])?;
        let raw: String = db
            .conn
            .query_row("SELECT commands FROM config_history", [], |row| row.get(0))?;
        assert!(!raw.contains("test-secret"));
        assert_eq!(
            db.load_config_history(router_id)?[0].commands,
            vec![command]
        );
        Ok(())
    }
}
