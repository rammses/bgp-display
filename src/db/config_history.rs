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

pub(crate) fn is_native_receipt_action(action: &str) -> bool {
    action.starts_with("mikrotik_receipt:")
}

impl ConfigHistoryEntry {
    pub fn is_replayable(&self) -> bool {
        !is_native_receipt_action(&self.action) && !self.rollback.is_empty()
    }

    // The history module stays private; this shared predicate is used by the
    // background service without moving SQLite ownership out of App.
    pub(crate) fn is_native_receipt_action(action: &str) -> bool {
        is_native_receipt_action(action)
    }
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
    fn mikrotik_receipt_prefix_cannot_be_replayed_even_with_forged_rollback() {
        let entry = ConfigHistoryEntry {
            id: Uuid::new_v4(),
            router_id: Uuid::nil(),
            action: "mikrotik_receipt:verified".into(),
            description: "safe".into(),
            commands: vec!["{}".into()],
            rollback: vec!["injected".into()],
            applied_at: String::new(),
        };
        assert!(!entry.is_replayable());
        let mut legacy = entry.clone();
        legacy.action = "create".into();
        assert!(legacy.is_replayable());
    }

    #[tokio::test]
    async fn mikrotik_receipt_sec004_real_apply_target_and_direction_survive_history_reopen(
    ) -> Result<()> {
        use crate::router::mikrotik::test_support::{
            configuration_replies, documented_snapshot, Reply, TranscriptExecutor,
        };
        use crate::router::mikrotik::{
            apply_native, preview_native, NativeIntent, NativeOutcome, NativeReceipt,
        };
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let fixture = Fixture(
            std::path::PathBuf::from("/tmp/opencode")
                .join(format!("bgp-lm-sec004-history-{}.sqlite", Uuid::new_v4())),
        );
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&fixture.0)?,
        );
        let conn = rusqlite::Connection::open(&fixture.0)?;
        conn.execute_batch("CREATE TABLE config_history (id TEXT PRIMARY KEY,router_id TEXT,action TEXT,description TEXT,commands TEXT,rollback TEXT,applied_at TEXT);")?;
        let db = RouterDb { conn, key: [7; 32] };
        let snapshot = documented_snapshot();
        let mut expected = Vec::new();
        for (index, disabled) in [(0, true), (1, false)] {
            let preview = preview_native(
                &snapshot,
                NativeIntent::SetDisabled {
                    target: snapshot.peers[index].connection.clone().unwrap(),
                    disabled,
                },
                Uuid::new_v4(),
            )?;
            let mut replies = configuration_replies(&snapshot.inventory);
            replies.push(Reply::Failure {
                code: "timeout",
                started: true,
            });
            replies.extend(configuration_replies(&snapshot.inventory));
            let receipt = apply_native(&TranscriptExecutor::new(replies), preview).await;
            assert_eq!(receipt.outcome, NativeOutcome::Indeterminate);
            db.insert_config_history(
                receipt.router_id,
                &format!("mikrotik_receipt:{}", receipt.operation),
                "safe receipt",
                &[serde_json::to_string(&receipt)?],
                &[],
            )?;
            expected.push(receipt);
        }
        drop(db);
        let reopened = RouterDb {
            conn: rusqlite::Connection::open(&fixture.0)?,
            key: [7; 32],
        };
        let loaded = reopened.load_config_history(snapshot.router_id)?;
        assert_eq!(loaded.len(), 2);
        let mut receipts = Vec::new();
        for entry in &loaded {
            assert!(!entry.is_replayable() && entry.rollback.is_empty());
            receipts.push(serde_json::from_str::<NativeReceipt>(&entry.commands[0])?);
        }
        for receipt in &expected {
            assert!(receipts.contains(receipt));
        }
        assert!(receipts
            .iter()
            .any(|r| r.summary.contains("name=\"peer-a\"")
                && r.summary.contains("id=\"*2\"")
                && r.summary.contains("Disable (disabled=true)")));
        assert!(receipts
            .iter()
            .any(|r| r.summary.contains("name=\"peer-b\"")
                && r.summary.contains("id=\"*3\"")
                && r.summary.contains("Enable (disabled=false)")));
        Ok(())
    }

    #[test]
    fn mikrotik_receipt_restart_loading_preserves_encryption_prefix_and_legacy_formats(
    ) -> Result<()> {
        // A real close/reopen of a private synthetic SQLite fixture. Do not use
        // RouterDb::open (the user's real application database/data directory).
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let fixture = Fixture(
            std::path::PathBuf::from("/tmp/opencode")
                .join(format!("bgp-lm-task5-history-{}.sqlite", Uuid::new_v4())),
        );
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&fixture.0)?,
        );
        let conn = rusqlite::Connection::open(&fixture.0)?;
        conn.execute_batch("CREATE TABLE config_history (id TEXT PRIMARY KEY,router_id TEXT,action TEXT,description TEXT,commands TEXT,rollback TEXT,applied_at TEXT);")?;
        let db = RouterDb { conn, key: [7; 32] };
        let rid = Uuid::nil();
        let receipt = crate::router::mikrotik::NativeReceipt {
            router_id: rid,
            operation: Uuid::new_v4(),
            instance: "blue".into(),
            registration: crate::router::mikrotik::test_support::documented_registration(),
            outcome: crate::router::mikrotik::NativeOutcome::Indeterminate,
            verified_steps: vec!["Create enabled reject input chain".into()],
            uncertain_steps: vec!["Create enabled reject output chain".into()],
            unapplied_steps: vec!["Create disabled connection with both deny-all bindings".into()],
            summary: "safe result".into(),
        };
        let json = serde_json::to_string(&receipt)?;
        db.insert_config_history(rid, "mikrotik_receipt:test", "safe", &[json.clone()], &[])?;
        db.insert_config_history(
            rid,
            "create",
            "legacy encrypted",
            &["legacy-create".into()],
            &["legacy-delete".into()],
        )?;
        db.conn.execute(
            "INSERT INTO config_history VALUES (?1,?2,'edit','legacy plaintext',?3,?4,'old')",
            params![
                Uuid::new_v4().to_string(),
                rid.to_string(),
                "[\"legacy-edit\"]",
                "[\"legacy-undo\"]"
            ],
        )?;
        let (raw_commands, raw_rollback): (String, String) = db.conn.query_row(
            "SELECT commands,rollback FROM config_history WHERE action='mikrotik_receipt:test'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert!(raw_commands.starts_with("enc:") && raw_rollback.starts_with("enc:"));
        assert!(!raw_commands.contains("safe result"));
        drop(db);
        let reopened = RouterDb {
            conn: rusqlite::Connection::open(&fixture.0)?,
            key: [7; 32],
        };
        let loaded = reopened.load_config_history(rid)?;
        assert_eq!(loaded.len(), 3);
        let native = loaded
            .iter()
            .find(|e| e.action.starts_with("mikrotik_receipt:"))
            .unwrap();
        assert!(!native.is_replayable());
        assert!(native.rollback.is_empty());
        assert_eq!(
            serde_json::from_str::<crate::router::mikrotik::NativeReceipt>(&native.commands[0])?,
            receipt
        );
        assert_eq!(native.commands, vec![json]);
        for entry in loaded
            .iter()
            .filter(|e| !e.action.starts_with("mikrotik_receipt:"))
        {
            assert!(entry.is_replayable());
        }
        assert_eq!(
            loaded
                .iter()
                .find(|e| e.description == "legacy encrypted")
                .unwrap()
                .rollback,
            vec!["legacy-delete"]
        );
        assert_eq!(
            loaded
                .iter()
                .find(|e| e.description == "legacy plaintext")
                .unwrap()
                .rollback,
            vec!["legacy-undo"]
        );
        Ok(())
    }

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
