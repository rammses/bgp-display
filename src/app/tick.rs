use crate::events::FetchRequest;
use crate::router::ConnectionStatus;
use crate::router::RouterConfig;
use ratatui::widgets::TableState;
use uuid::Uuid;

use super::types::ActiveTab;
use super::types::PingStats;
use super::App;

impl App {
    // ── Helpers ───────────────────────────────────────────────────────────────

    pub fn selected_router(&self) -> Option<&RouterConfig> {
        self.router_list_state
            .selected()
            .and_then(|i| self.routers.get(i))
    }

    pub fn connection_status(&self) -> ConnectionStatus {
        self.selected_router()
            .and_then(|r| self.router_status.get(&r.id))
            .cloned()
            .unwrap_or(ConnectionStatus::Disconnected)
    }

    pub fn reload_selected_router(&mut self) {
        // Close per-peer route drill-down on router switch
        self.peer_route_view = None;
        self.peer_route_table_state = TableState::default();
        // Clear any pending update since user is explicitly reloading/switching
        self.pending_bgp_update = None;
        self.pending_route_update = None;
        self.has_pending_update = false;

        if let Some(router) = self.selected_router() {
            let rid = router.id;
            // Instantly display cached data if available
            if let Some(cached) = self.bgp_cache.get(&rid) {
                self.current_summary = Some(cached.summary.clone());
                self.current_peers = cached.peers.clone();
                self.current_routes = cached.routes.clone();
                self.rendered_config = cached.config.clone();
                self.config_lines = self
                    .rendered_config
                    .lines()
                    .map(|l| l.to_string())
                    .collect();
                if !self.config_lines.is_empty() && self.config_list_state.selected().is_none() {
                    self.config_list_state.select(Some(0));
                }
                self.config_rm_name = None;
                self.config_routemap = None;
            } else {
                self.current_summary = None;
                self.current_peers = vec![];
                self.current_routes = vec![];
                self.rendered_config = String::new();
                self.config_lines = vec![];
            }
        }
        self.update_peer_filter();
        self.update_route_filter();
    }

    /// Request a BGP refresh for the currently selected router via the fetch service.
    pub fn request_refresh_selected(&self) {
        if let Some(router) = self.selected_router() {
            self.send_fetch(FetchRequest::RefreshRouter(router.id));
        }
    }

    pub fn tick(&mut self) {
        self.tick_counter = self.tick_counter.wrapping_add(1);
        self.ping_tick = self.ping_tick.wrapping_add(1);

        if self.ping_tick >= 25 {
            self.ping_tick = 0;
            self.request_ping();
        }

        if self.current_tab != ActiveTab::Config {
            self.bgp_refresh_tick = self.bgp_refresh_tick.wrapping_add(1);
            if self.bgp_refresh_tick >= 150 {
                self.bgp_refresh_tick = 0;
                self.request_refresh_all_connected();
            }
        }

        if let Some(rm_name) = self.routemap_fetch_queued.take() {
            self.request_routemap_fetch(rm_name);
        }
    }

    fn request_refresh_all_connected(&self) {
        let ids: Vec<Uuid> = self
            .routers
            .iter()
            .filter(|r| self.router_status.get(&r.id) == Some(&ConnectionStatus::Connected))
            .map(|r| r.id)
            .collect();
        if !ids.is_empty() {
            self.send_fetch(FetchRequest::RefreshMany(ids));
        }
    }

    pub fn request_ping(&self) {
        let targets: Vec<(Uuid, String)> = self
            .routers
            .iter()
            .map(|r| (r.id, format!("{}:{}", r.hostname, r.ssh_port)))
            .collect();
        if !targets.is_empty() {
            self.send_fetch(FetchRequest::Ping(targets));
        }
    }

    /// Called when a background ping probe completes.
    pub fn handle_ping_result(&mut self, id: Uuid, rtt: Option<std::time::Duration>) {
        let reachable = rtt.is_some();
        let new_status = if reachable {
            ConnectionStatus::Connected
        } else {
            ConnectionStatus::Disconnected
        };
        let prev = self
            .router_status
            .get(&id)
            .cloned()
            .unwrap_or(ConnectionStatus::Disconnected);

        let came_online = reachable && prev != ConnectionStatus::Connected;

        self.ping_stats
            .entry(id)
            .or_insert_with(PingStats::new)
            .record(rtt);

        if prev != new_status {
            let name = self
                .routers
                .iter()
                .find(|r| r.id == id)
                .map(|r| r.name.clone())
                .unwrap_or_else(|| id.to_string());
            let rtt_info = rtt
                .map(|d| format!(" ({:.1} ms)", d.as_secs_f64() * 1000.0))
                .unwrap_or_default();
            let msg = match &new_status {
                ConnectionStatus::Connected => format!("{name} came ONLINE{rtt_info}"),
                ConnectionStatus::Disconnected => format!("{name} went OFFLINE"),
                _ => return,
            };
            self.conn_log(msg);
        }
        self.router_status.insert(id, new_status);

        if came_online {
            self.send_fetch(FetchRequest::RefreshRouter(id));
        }
    }
}
