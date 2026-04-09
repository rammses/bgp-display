use super::truncate_error;
use super::types::{WizardMode, WizardStep};
use super::App;
use crate::router::ConnectionStatus;
use uuid::Uuid;

impl App {
    /// Called when a BGP fetch fails.
    ///
    /// The full SSH error detail goes to the file log only; the UI log gets a
    /// compact message so it doesn't scroll away useful entries.
    pub fn handle_bgp_error(&mut self, id: Uuid, err: String) {
        let name = self
            .routers
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| id.to_string());

        // Full detail → file log only
        tracing::error!(router = %name, error = %err, "BGP fetch failed");

        // Compact summary → UI (title bar + SSH log)
        let short = truncate_error(&err, 80);
        self.conn_log(format!("{name}: fetch failed — {short}"));
        // Strip "SSH error: " prefix since ConnectionStatus::Display adds "Error: "
        let status_msg = err.strip_prefix("SSH error: ").unwrap_or(&err);
        self.router_status
            .insert(id, ConnectionStatus::Error(truncate_error(status_msg, 50)));
    }

    // ── SSH session lifecycle ─────────────────────────────────────────────────

    /// Called when the background SSH warm-up finishes.
    pub fn handle_ssh_warm_complete(&mut self, ready: usize, failed: Vec<(String, String)>) {
        if failed.is_empty() {
            let msg = format!("SSH ready: all {ready} routers connected");
            self.conn_log(&msg);
            self.set_status(&msg);
        } else {
            let fail_names: Vec<&str> = failed.iter().map(|(n, _)| n.as_str()).collect();
            let msg = format!(
                "SSH warm: {ready} OK, {} failed ({})",
                failed.len(),
                fail_names.join(", "),
            );
            self.conn_log(&msg);
            self.set_status(&msg);
            for (name, err) in &failed {
                tracing::warn!(router = %name, error = %err, "SSH warm-up failed");
            }
        }
    }

    /// Called by the periodic health check task.
    pub fn handle_ssh_health_report(&mut self, healthy: usize, rewarmed: usize, dead: Vec<String>) {
        if !dead.is_empty() {
            let msg = format!(
                "SSH health: {} healthy, {} re-warmed, {} dead ({})",
                healthy,
                rewarmed,
                dead.len(),
                dead.join(", ")
            );
            self.conn_log(&msg);
            tracing::warn!(healthy, rewarmed, dead = ?dead, "SSH health report — dead sessions");
        } else if rewarmed > 0 {
            let msg = format!("SSH health: {} healthy, {} re-warmed", healthy, rewarmed);
            self.conn_log(&msg);
            tracing::info!(healthy, rewarmed, "SSH health report — all recovered");
        } else {
            tracing::debug!(healthy, "SSH health report — all healthy");
        }
    }

    // ── Config push event handlers ─────────────────────────────────────────────

    pub fn handle_config_applied(&mut self, router_id: Uuid, description: String) {
        let msg = format!("Config applied: {description}");
        self.log(&msg);
        self.conn_log(&msg);
        self.set_status(msg);
        self.wizard_step = WizardStep::Result(true);
        self.wizard_result_msg = Some(format!("Successfully applied: {description}"));

        // Persist neighbor to DB on successful create/edit; remove on delete
        match &self.wizard_mode {
            WizardMode::NeighborCreate | WizardMode::NeighborEdit(_) => {
                if let Some(draft) = &self.wizard_draft {
                    if let Some(db) = &self.router_db {
                        let _ = db.upsert_neighbor(router_id, draft);
                    }
                    // Update in-memory desired state
                    let entry = self.desired_neighbors.entry(router_id).or_default();
                    let ip = draft.neighbor_ip.trim().to_string();
                    if let Some(pos) = entry.iter().position(|d| d.neighbor_ip.trim() == ip) {
                        entry[pos] = draft.clone();
                    } else {
                        entry.push(draft.clone());
                    }
                }
            }
            WizardMode::NeighborDelete(ip) => {
                let ip_s = ip.to_string();
                if let Some(db) = &self.router_db {
                    let _ = db.delete_neighbor(router_id, &ip_s);
                }
                if let Some(entry) = self.desired_neighbors.get_mut(&router_id) {
                    entry.retain(|d| d.neighbor_ip.trim() != ip_s);
                }
            }
            _ => {}
        }
    }

    pub fn handle_config_error(&mut self, _router_id: Uuid, description: String, error: String) {
        let msg = format!("Config FAILED ({description}): {error}");
        self.log(&msg);
        self.conn_log(&msg);
        self.set_status(format!("Config failed: {description}"));
        self.wizard_step = WizardStep::Result(false);
        self.wizard_result_msg = Some(format!("Failed: {error}"));
    }
}
