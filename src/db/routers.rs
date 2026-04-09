use anyhow::Result;
use rusqlite::params;

use super::crypto::{decrypt, encrypt};
use super::RouterDb;
use crate::router::{RouterConfig, RouterVendor};

impl RouterDb {
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
                "a10" => RouterVendor::A10,
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
}
