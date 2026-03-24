use anyhow::Result;
use rusqlite::params;
use uuid::Uuid;

use super::RouterDb;
use crate::bgp::PeerTemplate;

impl RouterDb {
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
                if t.update_source.is_empty() {
                    None
                } else {
                    Some(&t.update_source)
                },
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
}
