use anyhow::Result;
use chrono::Utc;
use rusqlite::params;
use uuid::Uuid;

use super::RouterDb;

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
        let cmd_json = serde_json::to_string(commands).unwrap_or_else(|_| "[]".into());
        let rb_json = serde_json::to_string(rollback).unwrap_or_else(|_| "[]".into());

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

        Ok(result.map(
            |(rid_s, action, desc, cmd_json, rb_json, applied)| ConfigHistoryEntry {
                id,
                router_id: rid_s.parse().unwrap_or_else(|_| Uuid::new_v4()),
                action,
                description: desc,
                commands: serde_json::from_str(&cmd_json).unwrap_or_default(),
                rollback: serde_json::from_str(&rb_json).unwrap_or_default(),
                applied_at: applied,
            },
        ))
    }
}
