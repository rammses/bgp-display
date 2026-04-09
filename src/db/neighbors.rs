use anyhow::Result;
use chrono::Utc;
use rusqlite::params;
use uuid::Uuid;

use super::crypto::{decrypt, encrypt};
use super::RouterDb;
use crate::bgp::NeighborDraft;

impl RouterDb {
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
            let draft = NeighborDraft {
                id: id_s.parse().ok(),
                router_id: Some(router_id),
                neighbor_ip,
                remote_as: remote_as.to_string(),
                description,
                update_source: update_source.unwrap_or_default(),
                next_hop_self: nhs != 0,
                route_reflector_client: rrc != 0,
                hold_time: hold.to_string(),
                keepalive: keep.to_string(),
                password,
                bfd: bfd != 0,
                soft_reconfiguration_inbound: soft != 0,
                address_family: af,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc)),
                updated_at: chrono::DateTime::parse_from_rfc3339(&updated_s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc)),
                ..Default::default()
            };
            drafts.push(draft);
        }
        Ok(drafts)
    }

    pub fn load_all_neighbors(
        &self,
    ) -> Result<std::collections::HashMap<Uuid, Vec<NeighborDraft>>> {
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
}
