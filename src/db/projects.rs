use anyhow::Result;
use rusqlite::params;

use super::RouterDb;

impl RouterDb {
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
}
