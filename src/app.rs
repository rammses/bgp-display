use crate::{
    bgp::{BgpPeer, BgpRoute, BgpSummary},
    config::AppConfig,
    db::RouterDb,
    events::AppEvent,
    router::{ConnectionStatus, RouterBackend, RouterConfig, RouterVendor},
};
use ratatui::widgets::{ListState, TableState};
use std::collections::HashMap;
use tokio::sync::mpsc;
use uuid::Uuid;

// ─── Editor Mode ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditorMode {
    Browse,
    EditField,
}

/// Displayable field labels for the router editor form.
pub const EDITOR_FIELDS:  &[&str] = &["Name", "Hostname", "Port", "Username", "Password", "Vendor"];
pub const EDITOR_NFIELDS: usize   = 6;

// ─── Active Tab ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Dashboard = 0,
    Peers     = 1,
    Routes    = 2,
    Config    = 3,
    Logs      = 4,
    Routers   = 5,
    ConnLog   = 6,
}

impl ActiveTab {
    pub const ALL: [ActiveTab; 7] = [
        ActiveTab::Dashboard,
        ActiveTab::Peers,
        ActiveTab::Routes,
        ActiveTab::Config,
        ActiveTab::Logs,
        ActiveTab::Routers,
        ActiveTab::ConnLog,
    ];

    pub fn next(self) -> Self {
        match self {
            ActiveTab::Dashboard => ActiveTab::Peers,
            ActiveTab::Peers     => ActiveTab::Routes,
            ActiveTab::Routes    => ActiveTab::Config,
            ActiveTab::Config    => ActiveTab::Logs,
            ActiveTab::Logs      => ActiveTab::Routers,
            ActiveTab::Routers   => ActiveTab::ConnLog,
            ActiveTab::ConnLog   => ActiveTab::Dashboard,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            ActiveTab::Dashboard => ActiveTab::ConnLog,
            ActiveTab::Peers     => ActiveTab::Dashboard,
            ActiveTab::Routes    => ActiveTab::Peers,
            ActiveTab::Config    => ActiveTab::Routes,
            ActiveTab::Logs      => ActiveTab::Config,
            ActiveTab::Routers   => ActiveTab::Logs,
            ActiveTab::ConnLog   => ActiveTab::Routers,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ActiveTab::Dashboard => "1 Dashboard",
            ActiveTab::Peers     => "2 Peers",
            ActiveTab::Routes    => "3 Routes",
            ActiveTab::Config    => "4 Config",
            ActiveTab::Logs      => "5 Logs",
            ActiveTab::Routers   => "6 Routers",
            ActiveTab::ConnLog   => "7 ConnLog",
        }
    }
}

// ─── App State ────────────────────────────────────────────────────────────────

pub struct App {
    // Navigation
    pub current_tab: ActiveTab,
    pub should_quit: bool,

    // Routers
    pub routers:           Vec<RouterConfig>,
    pub router_list_state: ListState,
    #[allow(dead_code)]
    pub backends:          HashMap<Uuid, RouterBackend>,

    // Per-router connectivity (updated by background TCP probe)
    pub router_status: HashMap<Uuid, ConnectionStatus>,

    // BGP data for the currently selected router
    pub current_summary:   Option<BgpSummary>,
    pub current_peers:     Vec<BgpPeer>,
    pub current_routes:    Vec<BgpRoute>,
    pub peer_table_state:  TableState,
    pub route_table_state: TableState,

    // Rendered Cisco config stanza for Config tab
    pub rendered_config:   String,
    pub config_lines:      Vec<String>,
    pub config_list_state: ListState,
    pub config_rm_name:    Option<String>,
    pub config_routemap:   Option<crate::bgp::RouteMapDetail>,

    // General logs
    pub logs:           Vec<String>,
    pub log_list_state: ListState,

    // Connectivity-only log (online/offline events)
    pub conn_logs:      Vec<String>,
    pub conn_log_state: ListState,

    // Router editor
    pub editor_list_state: ListState,
    pub editor_mode:       EditorMode,
    pub editor_field:      usize,
    pub editor_buf:        String,
    pub editor_draft:      Option<RouterConfig>,

    // Status bar
    pub status_message: Option<String>,
    pub tick_counter:   u64,

    // Background ping
    pub event_tx: Option<mpsc::UnboundedSender<AppEvent>>,
    ping_tick:    u8,

    // Encrypted SQLite database (holds router configs)
    pub router_db: Option<RouterDb>,
}

impl App {
    pub fn new(cfg: AppConfig, router_db: RouterDb) -> Self {
        let n = cfg.routers.len();
        let mut app = Self {
            current_tab:       ActiveTab::Dashboard,
            should_quit:       false,
            routers:           cfg.routers,
            router_list_state: ListState::default(),
            backends:          HashMap::new(),
            router_status:     HashMap::new(),
            current_summary:   None,
            current_peers:     vec![],
            current_routes:    vec![],
            peer_table_state:  TableState::default(),
            route_table_state: TableState::default(),
            rendered_config:   String::new(),
            config_lines:      vec![],
            config_list_state: ListState::default(),
            config_rm_name:    None,
            config_routemap:   None,
            logs:              vec!["bgp-link-manager started".into()],
            log_list_state:    ListState::default(),
            conn_logs:         vec![],
            conn_log_state:    ListState::default(),
            editor_list_state: ListState::default(),
            editor_mode:       EditorMode::Browse,
            editor_field:      0,
            editor_buf:        String::new(),
            editor_draft:      None,
            status_message:    None,
            tick_counter:      0,
            event_tx:          None,
            ping_tick:         0,
            router_db:         Some(router_db),
        };

        if n > 0 {
            app.router_list_state.select(Some(0));
            app.editor_list_state.select(Some(0));
            app.peer_table_state.select(Some(0));
            app.route_table_state.select(Some(0));
        }

        app.reload_selected_router();
        app
    }

    pub fn set_event_tx(&mut self, tx: mpsc::UnboundedSender<AppEvent>) {
        self.event_tx = Some(tx);
    }

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
        if let Some(router) = self.selected_router() {
            let rid = router.id;
            if self.backends.get(&rid).is_none() {
                self.current_summary = None;
                self.current_peers   = vec![];
                self.current_routes  = vec![];
                self.rendered_config = String::new();
            }
        }
        self.spawn_bgp_fetch_selected();
    }

    /// Spawn a BGP data fetch for the currently selected router.
    pub fn spawn_bgp_fetch_selected(&self) {
        if let Some(router) = self.selected_router().cloned() {
            self.spawn_bgp_fetch_for(router);
        }
    }

    /// Spawn a BGP data fetch for a specific router.
    pub fn spawn_bgp_fetch_for(&self, router: RouterConfig) {
        let Some(tx) = self.event_tx.clone() else { return };
        tokio::spawn(async move {
            let result: anyhow::Result<(crate::bgp::BgpSummary, Vec<crate::bgp::BgpRoute>)> =
                match router.vendor {
                    RouterVendor::VyOs => {
                        let mut b = crate::router::vyos::VyOsBackend::new(&router);
                        match b.refresh().await {
                            Ok(s) => { let r = b.get_routes().await.unwrap_or_default(); Ok((s, r)) }
                            Err(e) => Err(e),
                        }
                    }
                    RouterVendor::Cisco => {
                        let mut b = crate::router::cisco::CiscoBackend::new(&router);
                        match b.refresh().await {
                            Ok(s) => { let r = b.get_routes().await.unwrap_or_default(); Ok((s, r)) }
                            Err(e) => Err(e),
                        }
                    }
                };
            match result {
                Ok((summary, routes)) => {
                    let _ = tx.send(AppEvent::RouteData(router.id, routes));
                    let _ = tx.send(AppEvent::BgpData(router.id, Box::new(summary)));
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::BgpError(router.id, e.to_string()));
                }
            }
        });
    }

    pub fn tick(&mut self) {
        self.tick_counter = self.tick_counter.wrapping_add(1);
        self.ping_tick    = self.ping_tick.wrapping_add(1);
        // Probe every ~5 s (25 ticks × 200 ms)
        if self.ping_tick >= 25 {
            self.ping_tick = 0;
            self.spawn_ping();
        }
    }

    /// Spawn non-blocking async TCP reachability probes for every router.
    pub fn spawn_ping(&self) {
        let Some(tx) = self.event_tx.clone() else { return };
        for router in &self.routers {
            let id   = router.id;
            let addr = format!("{}:{}", router.hostname, router.ssh_port);
            let tx   = tx.clone();
            tokio::spawn(async move {
                let reachable = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    tokio::net::TcpStream::connect(&addr),
                )
                .await
                .is_ok_and(|r| r.is_ok());
                let _ = tx.send(AppEvent::PingResult(id, reachable));
            });
        }
    }

    /// Called when a background ping probe completes.
    pub fn handle_ping_result(&mut self, id: Uuid, reachable: bool) {
        let new_status = if reachable {
            ConnectionStatus::Connected
        } else {
            ConnectionStatus::Disconnected
        };
        let prev = self.router_status.get(&id)
            .cloned()
            .unwrap_or(ConnectionStatus::Disconnected);

        // If the router just came online, trigger a BGP fetch
        let came_online = reachable
            && prev != ConnectionStatus::Connected;

        if prev != new_status {
            let name = self.routers.iter()
                .find(|r| r.id == id)
                .map(|r| r.name.clone())
                .unwrap_or_else(|| id.to_string());
            let msg = match &new_status {
                ConnectionStatus::Connected    => format!("{name} came ONLINE"),
                ConnectionStatus::Disconnected => format!("{name} went OFFLINE"),
                _ => return,
            };
            self.conn_log(msg.clone());
            self.log(msg);
        }
        self.router_status.insert(id, new_status);

        if came_online {
            if let Some(router) = self.routers.iter().find(|r| r.id == id).cloned() {
                self.spawn_bgp_fetch_for(router);
            }
        }
    }

    /// Called when a BGP fetch succeeds.
    pub fn handle_bgp_data(&mut self, id: Uuid, summary: BgpSummary) {
        self.router_status.insert(id, ConnectionStatus::Connected);

        // Update config stanza regardless of which router replied
        let rendered = crate::router::cisco::CiscoBackend::render_bgp_stanza(&summary);

        // Only update displayed data if this is the selected router
        if self.selected_router().map(|r| r.id) == Some(id) {
            self.current_peers   = summary.peers.clone();
            self.current_summary = Some(summary);
            // current_routes is populated by handle_route_data (sent before BgpData)
            self.rendered_config = rendered;
            self.config_lines = self.rendered_config.lines().map(|l| l.to_string()).collect();
            if !self.config_lines.is_empty() && self.config_list_state.selected().is_none() {
                self.config_list_state.select(Some(0));
            }
            self.config_rm_name  = None;
            self.config_routemap = None;
        }
    }

    /// Called when a route table fetch completes.
    pub fn handle_route_data(&mut self, id: Uuid, routes: Vec<BgpRoute>) {
        if self.selected_router().map(|r| r.id) == Some(id) {
            self.current_routes = routes;
        }
    }

    /// Called when a route-map detail fetch completes.
    pub fn handle_routemap_detail(&mut self, _id: Uuid, detail: crate::bgp::RouteMapDetail) {
        if self.config_rm_name.as_deref() == Some(detail.name.as_str()) {
            self.config_routemap = Some(detail);
        }
    }

    /// Spawn a background SSH fetch for a route-map's full detail.
    pub fn spawn_routemap_fetch(&self, rm_name: String) {
        let Some(router) = self.selected_router().cloned() else { return };
        let Some(tx) = self.event_tx.clone() else { return };
        tokio::spawn(async move {
            let detail = match router.vendor {
                RouterVendor::VyOs => {
                    let b = crate::router::vyos::VyOsBackend::new(&router);
                    b.fetch_route_map_detail(&rm_name).await
                }
                RouterVendor::Cisco => {
                    let b = crate::router::cisco::CiscoBackend::new(&router);
                    b.fetch_route_map_detail(&rm_name).await
                }
            };
            if let Ok(detail) = detail {
                let _ = tx.send(AppEvent::RouteMapDetail(router.id, Box::new(detail)));
            }
        });
    }

    /// Called when the selected config line changes — triggers route-map fetch if applicable.
    pub fn on_config_nav(&mut self) {
        let idx = match self.config_list_state.selected() {
            Some(i) => i,
            None    => return,
        };
        let line = self.config_lines.get(idx).cloned().unwrap_or_default();
        if let Some(rm_name) = extract_routemap_name_from_line(&line) {
            if self.config_rm_name.as_deref() != Some(&rm_name) {
                self.config_rm_name  = Some(rm_name.clone());
                self.config_routemap = None;
                self.spawn_routemap_fetch(rm_name);
            }
        } else {
            self.config_rm_name  = None;
            self.config_routemap = None;
        }
    }

    /// Called when a BGP fetch fails.
    pub fn handle_bgp_error(&mut self, id: Uuid, err: String) {
        let name = self.routers.iter()
            .find(|r| r.id == id)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| id.to_string());
        let msg = format!("{name}: BGP fetch failed — {err}");
        self.conn_log(msg.clone());
        self.log(msg);
        self.router_status.insert(id, ConnectionStatus::Error(err));
    }

    pub fn log(&mut self, msg: impl Into<String>) {
        let entry = format!(
            "[{}] {}",
            chrono::Local::now().format("%H:%M:%S"),
            msg.into()
        );
        self.logs.push(entry);
        if self.logs.len() > 500 {
            self.logs.remove(0);
        }
        let len = self.logs.len();
        self.log_list_state.select(Some(len.saturating_sub(1)));
    }

    pub fn conn_log(&mut self, msg: impl Into<String>) {
        let entry = format!(
            "[{}] {}",
            chrono::Local::now().format("%H:%M:%S"),
            msg.into()
        );
        self.conn_logs.push(entry);
        if self.conn_logs.len() > 500 {
            self.conn_logs.remove(0);
        }
        let len = self.conn_logs.len();
        self.conn_log_state.select(Some(len.saturating_sub(1)));
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some(msg.into());
    }

    // ── Router editor ─────────────────────────────────────────────────────────

    pub fn editor_start_add(&mut self) {
        self.editor_draft  = Some(RouterConfig::default());
        self.editor_field  = 0;
        self.editor_buf    = String::new();
        self.editor_mode   = EditorMode::EditField;
        self.set_status("New router — Tab/Enter: next field  Shift-Tab: prev  Esc: cancel");
    }

    pub fn editor_start_edit(&mut self) {
        if let Some(idx) = self.editor_list_state.selected() {
            if let Some(router) = self.routers.get(idx) {
                let draft = router.clone();
                self.editor_buf   = editor_field_value(&draft, 0);
                self.editor_field = 0;
                self.editor_draft = Some(draft);
                self.editor_mode  = EditorMode::EditField;
                self.set_status("Editing router — Tab/Enter: next field  Shift-Tab: prev  Esc: cancel");
            }
        }
    }

    pub fn editor_delete_selected(&mut self) {
        if let Some(idx) = self.editor_list_state.selected() {
            if idx < self.routers.len() {
                let removed = self.routers.remove(idx);
                self.router_status.remove(&removed.id);
                // Auto-persist deletion to DB immediately
                self.db_delete(removed.id);
                let msg = format!("Router '{}' removed", removed.name);
                self.conn_log(msg.clone());
                self.log(msg);
                if self.routers.is_empty() {
                    self.editor_list_state.select(None);
                } else {
                    self.editor_list_state.select(Some(idx.min(self.routers.len() - 1)));
                }
                self.set_status(format!("Deleted '{}' — saved to DB", removed.name));
            }
        }
    }

    pub fn editor_save_config(&mut self) {
        // No-op: all mutations are now auto-persisted. Keep the method so
        // existing key-bindings compile without changes.
        self.set_status("All changes are auto-saved to the encrypted DB");
    }

    pub fn editor_commit_and_advance(&mut self) {
        if let Some(draft) = self.editor_draft.as_mut() {
            apply_buf_to_draft(draft, self.editor_field, &self.editor_buf.clone());
        }
        if self.editor_field + 1 < EDITOR_NFIELDS {
            self.editor_field += 1;
            if let Some(draft) = self.editor_draft.as_ref() {
                self.editor_buf = editor_field_value(draft, self.editor_field);
            }
        } else {
            self.editor_persist_draft();
        }
    }

    pub fn editor_commit_and_retreat(&mut self) {
        if let Some(draft) = self.editor_draft.as_mut() {
            apply_buf_to_draft(draft, self.editor_field, &self.editor_buf.clone());
        }
        if self.editor_field > 0 {
            self.editor_field -= 1;
            if let Some(draft) = self.editor_draft.as_ref() {
                self.editor_buf = editor_field_value(draft, self.editor_field);
            }
        }
    }

    fn editor_persist_draft(&mut self) {
        if let Some(draft) = self.editor_draft.take() {
            let name = draft.name.clone();
            if let Some(pos) = self.routers.iter().position(|r| r.id == draft.id) {
                self.routers[pos] = draft.clone();
                self.conn_log(format!("Router '{name}' updated"));
                self.log(format!("Router '{name}' updated"));
            } else {
                self.routers.push(draft.clone());
                let new_idx = self.routers.len() - 1;
                self.editor_list_state.select(Some(new_idx));
                if self.router_list_state.selected().is_none() {
                    self.router_list_state.select(Some(0));
                }
                self.conn_log(format!("Router '{name}' added"));
                self.log(format!("Router '{name}' added"));
            }
            // Auto-persist to encrypted DB immediately
            self.db_upsert(&draft);
            self.editor_mode = EditorMode::Browse;
            self.editor_buf.clear();
            self.set_status(format!("'{name}' saved to DB ✓"));
        }
    }

    // ── DB write helpers ──────────────────────────────────────────────────────

    fn db_upsert(&self, r: &RouterConfig) {
        if let Some(db) = self.router_db.as_ref() {
            if let Err(e) = db.upsert(r) {
                eprintln!("warn: db upsert failed for '{}': {e}", r.name);
            }
        }
    }

    fn db_delete(&self, id: Uuid) {
        if let Some(db) = self.router_db.as_ref() {
            if let Err(e) = db.delete(id) {
                eprintln!("warn: db delete failed: {e}");
            }
        }
    }
}

// ─── Editor field helpers ─────────────────────────────────────────────────────

pub fn editor_field_value(r: &RouterConfig, field: usize) -> String {
    match field {
        0 => r.name.clone(),
        1 => r.hostname.clone(),
        2 => r.ssh_port.to_string(),
        3 => r.username.clone(),
        4 => r.password.clone().unwrap_or_default(),
        5 => r.vendor.to_string(),
        _ => String::new(),
    }
}

pub fn apply_buf_to_draft(draft: &mut RouterConfig, field: usize, buf: &str) {
    match field {
        0 => draft.name     = buf.to_string(),
        1 => draft.hostname = buf.to_string(),
        2 => draft.ssh_port = buf.parse().unwrap_or(22),
        3 => draft.username = buf.to_string(),
        4 => draft.password = if buf.is_empty() { None } else { Some(buf.to_string()) },
        5 => draft.vendor   = match buf.to_lowercase().as_str() {
                 "vyos" => RouterVendor::VyOs,
                 _      => RouterVendor::Cisco,
             },
        _ => {}
    }
}

/// Extract route-map name from a config line like "  neighbor X route-map NAME in".
fn extract_routemap_name_from_line(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let pos = parts.iter().position(|&p| p == "route-map")?;
    parts.get(pos + 1).map(|s| s.to_string())
}

// ─── Key Handler ─────────────────────────────────────────────────────────────

pub fn handle_key(app: &mut App, key: crossterm::event::KeyEvent) {
    use crossterm::event::{KeyCode, KeyModifiers};

    // ── Router editor captures all input while editing a field ────────────────
    if app.current_tab == ActiveTab::Routers && app.editor_mode == EditorMode::EditField {
        match key.code {
            KeyCode::Esc => {
                app.editor_mode = EditorMode::Browse;
                app.editor_draft = None;
                app.editor_buf.clear();
                app.set_status("Edit cancelled");
            }
            KeyCode::Backspace => { app.editor_buf.pop(); }
            KeyCode::Tab       => app.editor_commit_and_advance(),
            KeyCode::Enter     => app.editor_commit_and_advance(),
            KeyCode::BackTab   => app.editor_commit_and_retreat(),
            // Vendor field (5): Space cycles Cisco ↔ VyOs; other chars are ignored
            KeyCode::Char(' ') if app.editor_field == 5 => {
                if let Some(draft) = app.editor_draft.as_mut() {
                    draft.vendor = match draft.vendor {
                        RouterVendor::Cisco => RouterVendor::VyOs,
                        RouterVendor::VyOs  => RouterVendor::Cisco,
                    };
                    app.editor_buf = draft.vendor.to_string();
                }
            }
            KeyCode::Char(_) if app.editor_field == 5 => {
                // vendor field is cycle-only; ignore free text
            }
            KeyCode::Char(c)   => app.editor_buf.push(c),
            _ => {}
        }
        return;
    }

    // Global quit
    match (key.code, key.modifiers) {
        (KeyCode::Char('q'), _) | (KeyCode::Char('Q'), _) => {
            app.should_quit = true;
            return;
        }
        (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
            app.should_quit = true;
            return;
        }
        _ => {}
    }

    match key.code {
        // ── Tab switching ────────────────────────────────────────────────────
        KeyCode::Tab     => app.current_tab = app.current_tab.next(),
        KeyCode::BackTab => app.current_tab = app.current_tab.prev(),
        KeyCode::Char('1') => app.current_tab = ActiveTab::Dashboard,
        KeyCode::Char('2') => app.current_tab = ActiveTab::Peers,
        KeyCode::Char('3') => app.current_tab = ActiveTab::Routes,
        KeyCode::Char('4') => app.current_tab = ActiveTab::Config,
        KeyCode::Char('5') => app.current_tab = ActiveTab::Logs,
        KeyCode::Char('6') => app.current_tab = ActiveTab::Routers,
        KeyCode::Char('7') => app.current_tab = ActiveTab::ConnLog,

        // ── Navigation ───────────────────────────────────────────────────────
        KeyCode::Up   | KeyCode::Char('k') => navigate_up(app),
        KeyCode::Down | KeyCode::Char('j') => navigate_down(app),

        // ── Refresh ──────────────────────────────────────────────────────────
        KeyCode::Char('r') | KeyCode::F(5) => {
            app.reload_selected_router();
            app.set_status("Refreshing…");
            app.log("Manual refresh triggered");
            app.spawn_ping();
        }

        // ── Router editor actions (Routers tab only) ──────────────────────────
        KeyCode::Char('a') if app.current_tab == ActiveTab::Routers => {
            app.editor_start_add();
        }
        KeyCode::Char('d') if app.current_tab == ActiveTab::Routers => {
            app.editor_delete_selected();
        }
        KeyCode::Char('s') if app.current_tab == ActiveTab::Routers => {
            app.editor_save_config();
        }
        KeyCode::Enter if app.current_tab == ActiveTab::Routers => {
            app.editor_start_edit();
        }

        _ => {}
    }
}

fn navigate_up(app: &mut App) {
    match app.current_tab {
        ActiveTab::Dashboard => {
            if app.routers.is_empty() { return; }
            let next = match app.router_list_state.selected() {
                Some(0) | None => app.routers.len() - 1,
                Some(i)        => i - 1,
            };
            app.router_list_state.select(Some(next));
            app.reload_selected_router();
        }
        ActiveTab::Peers => {
            if app.current_peers.is_empty() { return; }
            let next = match app.peer_table_state.selected() {
                Some(0) | None => app.current_peers.len() - 1,
                Some(i)        => i - 1,
            };
            app.peer_table_state.select(Some(next));
        }
        ActiveTab::Routes => {
            if app.current_routes.is_empty() { return; }
            let next = match app.route_table_state.selected() {
                Some(0) | None => app.current_routes.len() - 1,
                Some(i)        => i - 1,
            };
            app.route_table_state.select(Some(next));
        }
        ActiveTab::Logs => {
            if app.logs.is_empty() { return; }
            let next = match app.log_list_state.selected() {
                Some(0) | None => app.logs.len() - 1,
                Some(i)        => i - 1,
            };
            app.log_list_state.select(Some(next));
        }
        ActiveTab::Config => {
            if app.config_lines.is_empty() { return; }
            let next = match app.config_list_state.selected() {
                Some(0) | None => app.config_lines.len() - 1,
                Some(i)        => i - 1,
            };
            app.config_list_state.select(Some(next));
            app.on_config_nav();
        }
        ActiveTab::Routers => {
            if app.routers.is_empty() { return; }
            let next = match app.editor_list_state.selected() {
                Some(0) | None => app.routers.len() - 1,
                Some(i)        => i - 1,
            };
            app.editor_list_state.select(Some(next));
        }
        ActiveTab::ConnLog => {
            if app.conn_logs.is_empty() { return; }
            let next = match app.conn_log_state.selected() {
                Some(0) | None => app.conn_logs.len() - 1,
                Some(i)        => i - 1,
            };
            app.conn_log_state.select(Some(next));
        }
        _ => {}
    }
}

fn navigate_down(app: &mut App) {
    match app.current_tab {
        ActiveTab::Dashboard => {
            if app.routers.is_empty() { return; }
            let next = match app.router_list_state.selected() {
                Some(i) => (i + 1) % app.routers.len(),
                None    => 0,
            };
            app.router_list_state.select(Some(next));
            app.reload_selected_router();
        }
        ActiveTab::Peers => {
            if app.current_peers.is_empty() { return; }
            let next = match app.peer_table_state.selected() {
                Some(i) => (i + 1) % app.current_peers.len(),
                None    => 0,
            };
            app.peer_table_state.select(Some(next));
        }
        ActiveTab::Routes => {
            if app.current_routes.is_empty() { return; }
            let next = match app.route_table_state.selected() {
                Some(i) => (i + 1) % app.current_routes.len(),
                None    => 0,
            };
            app.route_table_state.select(Some(next));
        }
        ActiveTab::Logs => {
            if app.logs.is_empty() { return; }
            let next = match app.log_list_state.selected() {
                Some(i) => (i + 1) % app.logs.len(),
                None    => 0,
            };
            app.log_list_state.select(Some(next));
        }
        ActiveTab::Config => {
            if app.config_lines.is_empty() { return; }
            let next = match app.config_list_state.selected() {
                Some(i) => (i + 1) % app.config_lines.len(),
                None    => 0,
            };
            app.config_list_state.select(Some(next));
            app.on_config_nav();
        }
        ActiveTab::Routers => {
            if app.routers.is_empty() { return; }
            let next = match app.editor_list_state.selected() {
                Some(i) => (i + 1) % app.routers.len(),
                None    => 0,
            };
            app.editor_list_state.select(Some(next));
        }
        ActiveTab::ConnLog => {
            if app.conn_logs.is_empty() { return; }
            let next = match app.conn_log_state.selected() {
                Some(i) => (i + 1) % app.conn_logs.len(),
                None    => 0,
            };
            app.conn_log_state.select(Some(next));
        }
        _ => {}
    }
}


