use crate::{
    bgp::{BgpPeer, BgpRoute, BgpSummary},
    config::AppConfig,
    db::RouterDb,
    events::AppEvent,
    router::{ConnectionStatus, Project, RouterBackend, RouterConfig, RouterVendor},
};
use ratatui::widgets::{ListState, TableState};
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::sync::mpsc;
use uuid::Uuid;

// ─── Editor Mode ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditorMode {
    Browse,
    EditField,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectEditorMode {
    /// Browsing the project list
    Browse,
    /// Typing a project name (create / rename)
    EditName,
    /// Toggling routers in/out of the selected project
    ToggleRouters,
}

/// Displayable field labels for the router editor form.
pub const EDITOR_FIELDS:  &[&str] = &["Name", "Hostname", "Port", "Username", "Password", "Vendor"];
pub const EDITOR_NFIELDS: usize   = 6;

// ─── Filter Mode ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterMode {
    /// No filter active.
    Off,
    /// Filter bar visible and user is typing.
    Typing,
    /// Filter applied and bar visible, but not actively typing.
    Active,
}

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
            ActiveTab::Logs      => "5 BGP Log",
            ActiveTab::Routers   => "6 Routers",
            ActiveTab::ConnLog   => "7 SSH Log",
        }
    }
}

// ─── Per-router BGP cache ──────────────────────────────────────────────────────

/// Cached BGP data for a single router, allowing instant display on switch.
pub struct BgpCache {
    pub summary: BgpSummary,
    pub peers:   Vec<BgpPeer>,
    pub routes:  Vec<BgpRoute>,
    pub config:  String,
}

// ─── Per-peer route drill-down state ─────────────────────────────────────────

pub struct PeerRouteView {
    pub peer_ip:   IpAddr,
    pub direction: crate::bgp::PeerRouteDirection,
    pub routes:    Option<Vec<BgpRoute>>,
    pub error:     Option<String>,
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

    // Per-router BGP data cache (kept across router switches)
    pub bgp_cache: HashMap<Uuid, BgpCache>,

    // BGP data for the currently selected router
    pub current_summary:   Option<BgpSummary>,
    pub current_peers:     Vec<BgpPeer>,
    pub current_routes:    Vec<BgpRoute>,
    pub peer_table_state:  TableState,
    pub route_table_state: TableState,

    // Filter state — Peers tab
    pub peer_filter:      String,
    pub peer_filter_mode: FilterMode,
    /// Indices into current_peers that pass the current filter (all when Off).
    pub peer_indices:     Vec<usize>,

    // Filter state — Routes tab
    pub route_filter:      String,
    pub route_filter_mode: FilterMode,
    /// Indices into current_routes that pass the current filter (all when Off).
    pub route_indices:     Vec<usize>,

    // Per-peer route drill-down (Peers tab)
    pub peer_route_view:        Option<PeerRouteView>,
    pub peer_route_table_state: TableState,

    // Rendered Cisco config stanza for Config tab
    pub rendered_config:   String,
    pub config_lines:      Vec<String>,
    pub config_list_state: ListState,
    pub config_rm_name:    Option<String>,
    pub config_routemap:   Option<crate::bgp::RouteMapDetail>,
    pub routemap_detail_scroll: u16,
    /// Per-router route-map detail cache: (router_id, rm_name) → detail
    pub routemap_cache:    HashMap<(Uuid, String), crate::bgp::RouteMapDetail>,

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

    // Background BGP refresh for all connected routers (~30 s)
    bgp_refresh_tick: u16,

    // Pending BGP update (deferred when user is actively on Config tab)
    pub pending_bgp_update:  Option<(Uuid, BgpSummary, String)>,
    pub pending_route_update: Option<(Uuid, Vec<BgpRoute>)>,
    pub has_pending_update:  bool,

    // Projects
    pub all_routers:          Vec<RouterConfig>,
    pub projects:             Vec<Project>,
    pub active_project:       Option<Uuid>,
    pub project_list_state:   ListState,
    pub project_popup:        bool,
    pub project_editor_mode:  ProjectEditorMode,
    pub project_editor_buf:   String,
    pub project_toggle_state: ListState,

    // Encrypted SQLite database (holds router configs)
    pub router_db: Option<RouterDb>,
}

impl App {
    pub fn new(cfg: AppConfig, router_db: RouterDb) -> Self {
        let n = cfg.routers.len();
        let mut app = Self {
            current_tab:       ActiveTab::Dashboard,
            should_quit:       false,
            routers:           cfg.routers.clone(),
            router_list_state: ListState::default(),
            backends:          HashMap::new(),
            router_status:     HashMap::new(),
            bgp_cache:         HashMap::new(),
            current_summary:   None,
            current_peers:     vec![],
            current_routes:    vec![],
            peer_table_state:  TableState::default(),
            route_table_state: TableState::default(),
            peer_filter:       String::new(),
            peer_filter_mode:  FilterMode::Off,
            peer_indices:      vec![],
            route_filter:      String::new(),
            route_filter_mode: FilterMode::Off,
            route_indices:     vec![],
            peer_route_view:        None,
            peer_route_table_state: TableState::default(),
            rendered_config:   String::new(),
            config_lines:      vec![],
            config_list_state: ListState::default(),
            config_rm_name:    None,
            config_routemap:   None,
            routemap_detail_scroll: 0,
            routemap_cache:    HashMap::new(),
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
            bgp_refresh_tick:  0,
            pending_bgp_update:  None,
            pending_route_update: None,
            has_pending_update:  false,
            all_routers:       cfg.routers,
            projects:          cfg.projects,
            active_project:    None,
            project_list_state:   ListState::default(),
            project_popup:        false,
            project_editor_mode:  ProjectEditorMode::Browse,
            project_editor_buf:   String::new(),
            project_toggle_state: ListState::default(),
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

    // ── Filter helpers ────────────────────────────────────────────────────────

    /// Recompute `peer_indices` from the current filter and peers list.
    pub fn update_peer_filter(&mut self) {
        let filter = self.peer_filter.to_lowercase();
        self.peer_indices = (0..self.current_peers.len())
            .filter(|&i| {
                if filter.is_empty() { return true; }
                let p = &self.current_peers[i];
                p.neighbor_ip.to_string().contains(&filter)
                    || p.remote_as.to_string().contains(&filter)
                    || p.state.as_str().to_lowercase().contains(&filter)
                    || p.description.as_deref().unwrap_or("").to_lowercase().contains(&filter)
                    || p.route_map_in.as_deref().unwrap_or("").to_lowercase().contains(&filter)
                    || p.route_map_out.as_deref().unwrap_or("").to_lowercase().contains(&filter)
                    || p.session_type().to_lowercase().contains(&filter)
            })
            .collect();
        // Keep selection valid
        match self.peer_table_state.selected() {
            Some(i) if i >= self.peer_indices.len() => {
                self.peer_table_state.select(if self.peer_indices.is_empty() { None } else { Some(0) });
            }
            None if !self.peer_indices.is_empty() => {
                self.peer_table_state.select(Some(0));
            }
            _ => {}
        }
    }

    /// Recompute `route_indices` from the current filter and routes list.
    pub fn update_route_filter(&mut self) {
        let filter = self.route_filter.to_lowercase();
        self.route_indices = (0..self.current_routes.len())
            .filter(|&i| {
                if filter.is_empty() { return true; }
                let r = &self.current_routes[i];
                r.network.to_lowercase().contains(&filter)
                    || r.next_hop.to_lowercase().contains(&filter)
                    || r.as_path_str().contains(&filter)
                    || r.communities.iter().any(|c| c.to_lowercase().contains(&filter))
                    || r.origin.to_string().to_lowercase().contains(&filter)
            })
            .collect();
        match self.route_table_state.selected() {
            Some(i) if i >= self.route_indices.len() => {
                self.route_table_state.select(if self.route_indices.is_empty() { None } else { Some(0) });
            }
            None if !self.route_indices.is_empty() => {
                self.route_table_state.select(Some(0));
            }
            _ => {}
        }
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
        // Close per-peer route drill-down on router switch
        self.peer_route_view = None;
        self.peer_route_table_state = TableState::default();
        // Clear any pending update since user is explicitly reloading/switching
        self.pending_bgp_update  = None;
        self.pending_route_update = None;
        self.has_pending_update  = false;

        if let Some(router) = self.selected_router() {
            let rid = router.id;
            // Instantly display cached data if available
            if let Some(cached) = self.bgp_cache.get(&rid) {
                self.current_summary = Some(cached.summary.clone());
                self.current_peers   = cached.peers.clone();
                self.current_routes  = cached.routes.clone();
                self.rendered_config = cached.config.clone();
                self.config_lines    = self.rendered_config.lines().map(|l| l.to_string()).collect();
                if !self.config_lines.is_empty() && self.config_list_state.selected().is_none() {
                    self.config_list_state.select(Some(0));
                }
                self.config_rm_name  = None;
                self.config_routemap = None;
            } else {
                self.current_summary = None;
                self.current_peers   = vec![];
                self.current_routes  = vec![];
                self.rendered_config = String::new();
                self.config_lines    = vec![];
            }
        }
        self.update_peer_filter();
        self.update_route_filter();
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
                    RouterVendor::CitrixVpx => {
                        let mut b = crate::router::citrix::CitrixVpxBackend::new(&router);
                        match b.refresh().await {
                            Ok(s) => { let r = b.get_routes().await.unwrap_or_default(); Ok((s, r)) }
                            Err(e) => Err(e),
                        }
                    }
                    RouterVendor::PfSense => {
                        let mut b = crate::router::pfsense::PfSenseBackend::new(&router);
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
        // Refresh BGP data for all connected routers every ~30 s (150 ticks × 200 ms)
        self.bgp_refresh_tick = self.bgp_refresh_tick.wrapping_add(1);
        if self.bgp_refresh_tick >= 150 {
            self.bgp_refresh_tick = 0;
            self.spawn_bgp_fetch_all_connected();
        }
    }

    /// Spawn BGP data fetches for every router that is currently connected.
    pub fn spawn_bgp_fetch_all_connected(&self) {
        for router in &self.routers {
            let is_connected = self.router_status.get(&router.id)
                == Some(&ConnectionStatus::Connected);
            if is_connected {
                self.spawn_bgp_fetch_for(router.clone());
            }
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
            self.conn_log(msg);
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

        let rendered = crate::router::cisco::CiscoBackend::render_bgp_stanza(&summary);

        let is_selected = self.selected_router().map(|r| r.id) == Some(id);

        // Check if the data actually changed compared to the cache
        let data_changed = self.bgp_cache.get(&id)
            .map(|cached| !cached.summary.content_eq(&summary) || cached.config != rendered)
            .unwrap_or(true); // no cache = treat as changed

        // Always update the per-router cache
        let entry = self.bgp_cache.entry(id).or_insert_with(|| BgpCache {
            summary: summary.clone(),
            peers:   vec![],
            routes:  vec![],
            config:  String::new(),
        });
        entry.summary = summary.clone();
        entry.peers   = summary.peers.clone();
        entry.config  = rendered.clone();

        if is_selected {
            if !data_changed {
                // Data hasn't changed — don't disturb the user at all
                return;
            }

            // If user is actively browsing the Config tab, defer the update
            if self.current_tab == ActiveTab::Config && !self.config_lines.is_empty() {
                self.pending_bgp_update  = Some((id, summary, rendered));
                self.has_pending_update  = true;
                return;
            }

            // Otherwise apply immediately
            self.apply_bgp_update(id, summary, rendered);
        }
    }

    /// Apply a BGP data update to the displayed state.
    fn apply_bgp_update(&mut self, id: Uuid, summary: BgpSummary, rendered: String) {
        self.current_peers   = summary.peers.clone();
        self.current_summary = Some(summary);
        self.rendered_config = rendered;
        self.config_lines = self.rendered_config.lines().map(|l| l.to_string()).collect();
        if !self.config_lines.is_empty() && self.config_list_state.selected().is_none() {
            self.config_list_state.select(Some(0));
        }
        self.config_rm_name  = None;
        self.config_routemap = None;
        // Invalidate cached route-map details for this router since BGP data changed
        self.routemap_cache.retain(|&(rid, _), _| rid != id);
        self.update_peer_filter();
    }

    /// Accept pending BGP update and apply it to the displayed state.
    pub fn accept_pending_update(&mut self) {
        if let Some((id, summary, rendered)) = self.pending_bgp_update.take() {
            self.apply_bgp_update(id, summary, rendered);
        }
        if let Some((id, routes)) = self.pending_route_update.take() {
            if let Some(entry) = self.bgp_cache.get_mut(&id) {
                entry.routes = routes.clone();
            }
            self.current_routes = routes;
        }
        self.has_pending_update = false;
        self.update_peer_filter();
        self.update_route_filter();
        self.set_status("Update applied");
        self.log("Pending BGP update applied");
    }

    /// Dismiss pending update notification without applying.
    pub fn dismiss_pending_update(&mut self) {
        self.pending_bgp_update  = None;
        self.pending_route_update = None;
        self.has_pending_update  = false;
    }

    /// Called when a route table fetch completes.
    pub fn handle_route_data(&mut self, id: Uuid, routes: Vec<BgpRoute>) {
        let is_selected = self.selected_router().map(|r| r.id) == Some(id);

        // Check if routes actually changed
        let data_changed = self.bgp_cache.get(&id)
            .map(|cached| cached.routes != routes)
            .unwrap_or(true);

        // Always update the cache
        if let Some(entry) = self.bgp_cache.get_mut(&id) {
            entry.routes = routes.clone();
        }

        if is_selected {
            if !data_changed {
                return;
            }

            // If user is on Config tab with a pending BGP update, bundle routes too
            if self.has_pending_update {
                self.pending_route_update = Some((id, routes));
                return;
            }

            self.current_routes = routes;
            self.update_route_filter();
        }
    }

    /// Called when a route-map detail fetch completes.
    pub fn handle_routemap_detail(&mut self, id: Uuid, detail: crate::bgp::RouteMapDetail) {
        // Cache the result for this router + route-map name
        self.routemap_cache.insert((id, detail.name.clone()), detail.clone());
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
                RouterVendor::CitrixVpx => {
                    let b = crate::router::citrix::CitrixVpxBackend::new(&router);
                    b.fetch_route_map_detail(&rm_name).await
                }
                RouterVendor::PfSense => {
                    let b = crate::router::pfsense::PfSenseBackend::new(&router);
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
                self.config_rm_name = Some(rm_name.clone());
                self.routemap_detail_scroll = 0;

                // Check cache first — show instantly if available
                let rid = self.selected_router().map(|r| r.id);
                if let Some(rid) = rid {
                    if let Some(cached) = self.routemap_cache.get(&(rid, rm_name.clone())) {
                        self.config_routemap = Some(cached.clone());
                        return;
                    }
                }

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
        self.log(msg);
        self.router_status.insert(id, ConnectionStatus::Error(err));
    }

    // ── Per-peer route drill-down ─────────────────────────────────────────────

    /// Open the per-peer route drill-down for the currently selected peer.
    pub fn open_peer_route_view(&mut self, dir: crate::bgp::PeerRouteDirection) {
        let ip = match self.peer_table_state.selected()
            .and_then(|i| self.peer_indices.get(i))
            .and_then(|&idx| self.current_peers.get(idx))
        {
            Some(p) => p.neighbor_ip,
            None    => return,
        };
        self.peer_route_view = Some(PeerRouteView {
            peer_ip:   ip,
            direction: dir,
            routes:    None,
            error:     None,
        });
        self.peer_route_table_state = TableState::default();
        self.spawn_peer_routes_fetch(ip, dir);
        self.set_status(format!("Fetching {} routes for {}…", dir.label(), ip));
    }

    pub fn close_peer_route_view(&mut self) {
        self.peer_route_view = None;
        self.peer_route_table_state = TableState::default();
    }

    /// Toggle between Received and Advertised in the drill-down view.
    pub fn toggle_peer_route_direction(&mut self) {
        let (ip, dir) = match self.peer_route_view.as_mut() {
            Some(view) => {
                view.direction = view.direction.toggle();
                view.routes    = None;
                view.error     = None;
                (view.peer_ip, view.direction)
            }
            None => return,
        };
        self.peer_route_table_state = TableState::default();
        self.spawn_peer_routes_fetch(ip, dir);
        self.set_status(format!("Fetching {} routes for {}…", dir.label(), ip));
    }

    /// Spawn a background SSH fetch for per-peer routes.
    pub fn spawn_peer_routes_fetch(&self, ip: IpAddr, dir: crate::bgp::PeerRouteDirection) {
        let Some(router) = self.selected_router().cloned() else { return };
        let Some(tx)     = self.event_tx.clone() else { return };
        tokio::spawn(async move {
            let result = match router.vendor {
                RouterVendor::Cisco => {
                    let b = crate::router::cisco::CiscoBackend::new(&router);
                    b.get_peer_routes(ip, dir).await
                }
                RouterVendor::VyOs => {
                    let b = crate::router::vyos::VyOsBackend::new(&router);
                    b.get_peer_routes(ip, dir).await
                }
                RouterVendor::CitrixVpx => {
                    let b = crate::router::citrix::CitrixVpxBackend::new(&router);
                    b.get_peer_routes(ip, dir).await
                }
                RouterVendor::PfSense => {
                    let b = crate::router::pfsense::PfSenseBackend::new(&router);
                    b.get_peer_routes(ip, dir).await
                }
            };
            match result {
                Ok(routes) => { let _ = tx.send(AppEvent::PeerRoutes(router.id, ip, dir, routes)); }
                Err(e)     => { let _ = tx.send(AppEvent::PeerRoutesError(router.id, ip, dir, e.to_string())); }
            }
        });
    }

    /// Called when per-peer routes arrive from the background task.
    pub fn handle_peer_routes(&mut self, _id: Uuid, ip: IpAddr, dir: crate::bgp::PeerRouteDirection, routes: Vec<BgpRoute>) {
        let count = routes.len();
        if let Some(view) = self.peer_route_view.as_mut() {
            if view.peer_ip == ip && view.direction == dir {
                view.routes = Some(routes);
                view.error  = None;
            } else {
                return;
            }
        } else {
            return;
        }
        if count > 0 {
            self.peer_route_table_state.select(Some(0));
        }
        self.set_status(format!("{} {} routes for {}", count, dir.label().to_lowercase(), ip));
    }

    /// Called when a per-peer routes fetch fails.
    pub fn handle_peer_routes_error(&mut self, _id: Uuid, ip: IpAddr, dir: crate::bgp::PeerRouteDirection, err: String) {
        if let Some(view) = self.peer_route_view.as_mut() {
            if view.peer_ip == ip && view.direction == dir {
                view.error  = Some(err.clone());
                view.routes = Some(vec![]);
            }
        }
        self.log(format!("Peer routes error {ip}: {err}"));
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

    // ── Project management ────────────────────────────────────────────────────

    /// Rebuild `self.routers` from visible set and reset selection.
    pub fn apply_project_filter(&mut self) {
        let ids: Option<Vec<Uuid>> = self.active_project.and_then(|pid| {
            self.projects.iter().find(|p| p.id == pid).map(|p| p.router_ids.clone())
        });
        self.routers = match ids {
            Some(ref ids) => self.all_routers.iter()
                .filter(|r| ids.contains(&r.id))
                .cloned()
                .collect(),
            None => self.all_routers.clone(),
        };
        // Reset selection
        if self.routers.is_empty() {
            self.router_list_state.select(None);
            self.editor_list_state.select(None);
        } else {
            self.router_list_state.select(Some(0));
            self.editor_list_state.select(Some(0));
        }
        self.reload_selected_router();
    }

    /// Active project name for display.
    pub fn active_project_name(&self) -> Option<&str> {
        self.active_project.and_then(|pid| {
            self.projects.iter().find(|p| p.id == pid).map(|p| p.name.as_str())
        })
    }

    pub fn select_project(&mut self, idx: Option<usize>) {
        match idx {
            Some(i) => {
                if let Some(proj) = self.projects.get(i) {
                    self.active_project = Some(proj.id);
                    let name = proj.name.clone();
                    self.apply_project_filter();
                    self.log(format!("Switched to project '{name}'"));
                    self.set_status(format!("Project: {name}"));
                }
            }
            None => {
                self.active_project = None;
                self.apply_project_filter();
                self.log("Showing all routers");
                self.set_status("All routers");
            }
        }
    }

    pub fn project_add(&mut self) {
        self.project_editor_mode = ProjectEditorMode::EditName;
        self.project_editor_buf  = String::new();
        self.set_status("Enter project name — Enter: save  Esc: cancel");
    }

    pub fn project_save_name(&mut self) {
        let name = self.project_editor_buf.trim().to_string();
        if name.is_empty() {
            self.project_editor_mode = ProjectEditorMode::Browse;
            return;
        }
        let proj = Project::new(name.clone());
        self.db_upsert_project(&proj);
        self.projects.push(proj);
        let idx = self.projects.len() - 1;
        self.project_list_state.select(Some(idx));
        self.project_editor_mode = ProjectEditorMode::Browse;
        self.project_editor_buf.clear();
        self.log(format!("Project '{name}' created"));
        self.set_status(format!("Project '{name}' created"));
    }

    pub fn project_delete_selected(&mut self) {
        if let Some(idx) = self.project_list_state.selected() {
            if idx < self.projects.len() {
                let removed = self.projects.remove(idx);
                self.db_delete_project(removed.id);
                // If this was the active project, clear filter
                if self.active_project == Some(removed.id) {
                    self.active_project = None;
                    self.apply_project_filter();
                }
                let msg = format!("Project '{}' deleted", removed.name);
                self.log(msg.clone());
                self.set_status(msg);
                if self.projects.is_empty() {
                    self.project_list_state.select(None);
                } else {
                    self.project_list_state.select(Some(idx.min(self.projects.len() - 1)));
                }
            }
        }
    }

    pub fn project_enter_toggle_routers(&mut self) {
        if self.project_list_state.selected().is_some() {
            self.project_editor_mode = ProjectEditorMode::ToggleRouters;
            if !self.all_routers.is_empty() {
                self.project_toggle_state.select(Some(0));
            }
            self.set_status("Space: toggle router  Enter/Esc: done");
        }
    }

    pub fn project_toggle_router(&mut self) {
        let proj_idx = match self.project_list_state.selected() {
            Some(i) => i,
            None    => return,
        };
        let router_idx = match self.project_toggle_state.selected() {
            Some(i) => i,
            None    => return,
        };
        let rid = match self.all_routers.get(router_idx) {
            Some(r) => r.id,
            None    => return,
        };
        let proj = match self.projects.get_mut(proj_idx) {
            Some(p) => p,
            None    => return,
        };
        if let Some(pos) = proj.router_ids.iter().position(|&id| id == rid) {
            proj.router_ids.remove(pos);
        } else {
            proj.router_ids.push(rid);
        }
        let proj_snapshot = proj.clone();
        self.db_upsert_project(&proj_snapshot);
        // Re-apply filter if this is the active project
        if self.active_project == Some(proj_snapshot.id) {
            let ids = proj_snapshot.router_ids;
            self.routers = self.all_routers.iter()
                .filter(|r| ids.contains(&r.id))
                .cloned()
                .collect();
            if self.routers.is_empty() {
                self.router_list_state.select(None);
            } else if self.router_list_state.selected().map(|i| i >= self.routers.len()).unwrap_or(true) {
                self.router_list_state.select(Some(0));
            }
        }
    }

    fn db_upsert_project(&self, p: &Project) {
        if let Some(db) = self.router_db.as_ref() {
            if let Err(e) = db.upsert_project(p) {
                eprintln!("warn: db upsert_project failed for '{}': {e}", p.name);
            }
        }
    }

    fn db_delete_project(&self, id: Uuid) {
        if let Some(db) = self.router_db.as_ref() {
            if let Err(e) = db.delete_project(id) {
                eprintln!("warn: db delete_project failed: {e}");
            }
        }
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
                // Also remove from all_routers
                if let Some(pos) = self.all_routers.iter().position(|r| r.id == removed.id) {
                    self.all_routers.remove(pos);
                }
                // Auto-persist deletion to DB immediately
                self.db_delete(removed.id);
                let msg = format!("Router '{}' removed", removed.name);
                self.conn_log(msg);
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
                // Also update in all_routers
                if let Some(apos) = self.all_routers.iter().position(|r| r.id == draft.id) {
                    self.all_routers[apos] = draft.clone();
                }
                self.conn_log(format!("Router '{name}' updated"));
            } else {
                self.routers.push(draft.clone());
                self.all_routers.push(draft.clone());
                let new_idx = self.routers.len() - 1;
                self.editor_list_state.select(Some(new_idx));
                if self.router_list_state.selected().is_none() {
                    self.router_list_state.select(Some(0));
                }
                self.conn_log(format!("Router '{name}' added"));
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
                 "vyos"      => RouterVendor::VyOs,
                 "citrixvpx" | "citrix" => RouterVendor::CitrixVpx,
                 "pfsense"   => RouterVendor::PfSense,
                 _           => RouterVendor::Cisco,
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
                        RouterVendor::Cisco     => RouterVendor::VyOs,
                        RouterVendor::VyOs      => RouterVendor::CitrixVpx,
                        RouterVendor::CitrixVpx => RouterVendor::PfSense,
                        RouterVendor::PfSense   => RouterVendor::Cisco,
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

    // ── Project popup captures all input when open ───────────────────────────
    if app.project_popup {
        match app.project_editor_mode {
            ProjectEditorMode::EditName => {
                match key.code {
                    KeyCode::Esc => {
                        app.project_editor_mode = ProjectEditorMode::Browse;
                        app.project_editor_buf.clear();
                    }
                    KeyCode::Backspace => { app.project_editor_buf.pop(); }
                    KeyCode::Enter     => app.project_save_name(),
                    KeyCode::Char(c)   => app.project_editor_buf.push(c),
                    _ => {}
                }
                return;
            }
            ProjectEditorMode::ToggleRouters => {
                match key.code {
                    KeyCode::Esc | KeyCode::Enter => {
                        app.project_editor_mode = ProjectEditorMode::Browse;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.all_routers.is_empty() { return; }
                        let next = match app.project_toggle_state.selected() {
                            Some(0) | None => app.all_routers.len() - 1,
                            Some(i)        => i - 1,
                        };
                        app.project_toggle_state.select(Some(next));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.all_routers.is_empty() { return; }
                        let next = match app.project_toggle_state.selected() {
                            Some(i) => (i + 1) % app.all_routers.len(),
                            None    => 0,
                        };
                        app.project_toggle_state.select(Some(next));
                    }
                    KeyCode::Char(' ') => app.project_toggle_router(),
                    _ => {}
                }
                return;
            }
            ProjectEditorMode::Browse => {
                match key.code {
                    KeyCode::Esc | KeyCode::Char('p') => {
                        app.project_popup = false;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.projects.is_empty() { return; }
                        let next = match app.project_list_state.selected() {
                            Some(0) | None => app.projects.len() - 1,
                            Some(i)        => i - 1,
                        };
                        app.project_list_state.select(Some(next));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.projects.is_empty() { return; }
                        let next = match app.project_list_state.selected() {
                            Some(i) => (i + 1) % app.projects.len(),
                            None    => 0,
                        };
                        app.project_list_state.select(Some(next));
                    }
                    KeyCode::Enter => {
                        // Switch to selected project
                        let idx = app.project_list_state.selected();
                        app.select_project(idx);
                        app.project_popup = false;
                    }
                    KeyCode::Char('0') => {
                        // Show all routers (clear project filter)
                        app.select_project(None);
                        app.project_popup = false;
                    }
                    KeyCode::Char('a') => app.project_add(),
                    KeyCode::Char('d') => app.project_delete_selected(),
                    KeyCode::Char('e') => app.project_enter_toggle_routers(),
                    _ => {}
                }
                return;
            }
        }
    }

    // ── Filter input capture (Peers / Routes tab, while Typing) ────────────────────
    if app.peer_filter_mode == FilterMode::Typing && app.current_tab == ActiveTab::Peers {
        match key.code {
            KeyCode::Esc => {
                app.peer_filter.clear();
                app.peer_filter_mode = FilterMode::Off;
                app.update_peer_filter();
            }
            KeyCode::Enter => {
                app.peer_filter_mode = if app.peer_filter.is_empty() {
                    FilterMode::Off
                } else {
                    FilterMode::Active
                };
            }
            KeyCode::Backspace => {
                app.peer_filter.pop();
                app.update_peer_filter();
            }
            KeyCode::Char(c) => {
                app.peer_filter.push(c);
                app.update_peer_filter();
            }
            _ => {}
        }
        return;
    }
    if app.route_filter_mode == FilterMode::Typing && app.current_tab == ActiveTab::Routes {
        match key.code {
            KeyCode::Esc => {
                app.route_filter.clear();
                app.route_filter_mode = FilterMode::Off;
                app.update_route_filter();
            }
            KeyCode::Enter => {
                app.route_filter_mode = if app.route_filter.is_empty() {
                    FilterMode::Off
                } else {
                    FilterMode::Active
                };
            }
            KeyCode::Backspace => {
                app.route_filter.pop();
                app.update_route_filter();
            }
            KeyCode::Char(c) => {
                app.route_filter.push(c);
                app.update_route_filter();
            }
            _ => {}
        }
        return;
    }

    // ── Per-peer route drill-down: capture all input while view is open ───────
    if app.peer_route_view.is_some() && app.current_tab == ActiveTab::Peers {
        use crate::bgp::PeerRouteDirection;
        match key.code {
            KeyCode::Esc => { app.close_peer_route_view(); }
            KeyCode::Char('i') => {
                if app.peer_route_view.as_ref().map(|v| v.direction) != Some(PeerRouteDirection::Received) {
                    app.toggle_peer_route_direction();
                }
            }
            KeyCode::Char('o') => {
                if app.peer_route_view.as_ref().map(|v| v.direction) != Some(PeerRouteDirection::Advertised) {
                    app.toggle_peer_route_direction();
                }
            }
            KeyCode::Tab => { app.toggle_peer_route_direction(); }
            KeyCode::Char('r') | KeyCode::F(5) => {
                let (ip, dir) = match app.peer_route_view.as_mut() {
                    Some(view) => {
                        view.routes = None;
                        view.error  = None;
                        (view.peer_ip, view.direction)
                    }
                    None => return,
                };
                app.spawn_peer_routes_fetch(ip, dir);
                app.set_status(format!("Refreshing {} routes for {}…", dir.label(), ip));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let len = app.peer_route_view.as_ref()
                    .and_then(|v| v.routes.as_ref())
                    .map(|r: &Vec<BgpRoute>| r.len())
                    .unwrap_or(0);
                if len > 0 {
                    let next = match app.peer_route_table_state.selected() {
                        Some(0) | None => len - 1,
                        Some(i)        => i - 1,
                    };
                    app.peer_route_table_state.select(Some(next));
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let len = app.peer_route_view.as_ref()
                    .and_then(|v| v.routes.as_ref())
                    .map(|r: &Vec<BgpRoute>| r.len())
                    .unwrap_or(0);
                if len > 0 {
                    let next = match app.peer_route_table_state.selected() {
                        Some(i) => (i + 1) % len,
                        None    => 0,
                    };
                    app.peer_route_table_state.select(Some(next));
                }
            }
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
        KeyCode::Tab     => {
            // Auto-apply pending update when leaving Config tab
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = app.current_tab.next();
        }
        KeyCode::BackTab => {
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = app.current_tab.prev();
        }
        KeyCode::Char('1') => { if app.current_tab == ActiveTab::Config && app.has_pending_update { app.accept_pending_update(); } app.current_tab = ActiveTab::Dashboard; }
        KeyCode::Char('2') => { if app.current_tab == ActiveTab::Config && app.has_pending_update { app.accept_pending_update(); } app.current_tab = ActiveTab::Peers; }
        KeyCode::Char('3') => { if app.current_tab == ActiveTab::Config && app.has_pending_update { app.accept_pending_update(); } app.current_tab = ActiveTab::Routes; }
        KeyCode::Char('4') => app.current_tab = ActiveTab::Config,
        KeyCode::Char('5') => { if app.current_tab == ActiveTab::Config && app.has_pending_update { app.accept_pending_update(); } app.current_tab = ActiveTab::Logs; }
        KeyCode::Char('6') => { if app.current_tab == ActiveTab::Config && app.has_pending_update { app.accept_pending_update(); } app.current_tab = ActiveTab::Routers; }
        KeyCode::Char('7') => { if app.current_tab == ActiveTab::Config && app.has_pending_update { app.accept_pending_update(); } app.current_tab = ActiveTab::ConnLog; }

        // ── Navigation ───────────────────────────────────────────────────────
        KeyCode::Up   | KeyCode::Char('k') => navigate_up(app),
        KeyCode::Down | KeyCode::Char('j') => navigate_down(app),

        // ── Open filter (Peers / Routes tab) ──────────────────────────────────
        KeyCode::Char('/') if app.current_tab == ActiveTab::Peers => {
            app.peer_filter_mode = FilterMode::Typing;
        }
        KeyCode::Char('/') if app.current_tab == ActiveTab::Routes => {
            app.route_filter_mode = FilterMode::Typing;
        }

        // ── Dismiss active filter with Esc (Peers / Routes tab) ──────────────────
        KeyCode::Esc if app.current_tab == ActiveTab::Peers
            && app.peer_filter_mode != FilterMode::Off => {
            app.peer_filter.clear();
            app.peer_filter_mode = FilterMode::Off;
            app.update_peer_filter();
        }
        KeyCode::Esc if app.current_tab == ActiveTab::Routes
            && app.route_filter_mode != FilterMode::Off => {
            app.route_filter.clear();
            app.route_filter_mode = FilterMode::Off;
            app.update_route_filter();
        }

        // ── Scroll route-map detail (Config tab) ─────────────────────────────
        KeyCode::PageDown => {
            if app.current_tab == ActiveTab::Config && app.config_routemap.is_some() {
                app.routemap_detail_scroll = app.routemap_detail_scroll.saturating_add(10);
            }
        }
        KeyCode::PageUp => {
            if app.current_tab == ActiveTab::Config && app.config_routemap.is_some() {
                app.routemap_detail_scroll = app.routemap_detail_scroll.saturating_sub(10);
            }
        }

        // ── Refresh ──────────────────────────────────────────────────────────
        KeyCode::Char('r') | KeyCode::F(5) => {
            app.reload_selected_router();
            app.set_status("Refreshing…");
            app.log("Manual refresh triggered");
            app.spawn_ping();
        }

        // ── Accept / dismiss pending BGP update (Config tab) ─────────────────
        KeyCode::Char('y') if app.current_tab == ActiveTab::Config && app.has_pending_update => {
            app.accept_pending_update();
        }
        KeyCode::Char('n') if app.current_tab == ActiveTab::Config && app.has_pending_update => {
            app.dismiss_pending_update();
            app.set_status("Update dismissed");
        }

        // ── Project selector ─────────────────────────────────────────────────
        KeyCode::Char('p') => {
            app.project_popup = true;
            if !app.projects.is_empty() && app.project_list_state.selected().is_none() {
                app.project_list_state.select(Some(0));
            }
            app.set_status("Projects — Enter: switch  a: add  d: delete  e: edit routers  0: all  Esc: close");
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

        // ── Open per-peer route view (Peers tab) ─────────────────────────────
        KeyCode::Enter if app.current_tab == ActiveTab::Peers => {
            app.open_peer_route_view(crate::bgp::PeerRouteDirection::Received);
        }
        KeyCode::Char('i') if app.current_tab == ActiveTab::Peers => {
            app.open_peer_route_view(crate::bgp::PeerRouteDirection::Received);
        }
        KeyCode::Char('o') if app.current_tab == ActiveTab::Peers => {
            app.open_peer_route_view(crate::bgp::PeerRouteDirection::Advertised);
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
            if app.peer_indices.is_empty() { return; }
            let len = app.peer_indices.len();
            let next = match app.peer_table_state.selected() {
                Some(0) | None => len - 1,
                Some(i)        => i - 1,
            };
            app.peer_table_state.select(Some(next));
        }
        ActiveTab::Routes => {
            if app.route_indices.is_empty() { return; }
            let len = app.route_indices.len();
            let next = match app.route_table_state.selected() {
                Some(0) | None => len - 1,
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
            if app.peer_indices.is_empty() { return; }
            let next = match app.peer_table_state.selected() {
                Some(i) => (i + 1) % app.peer_indices.len(),
                None    => 0,
            };
            app.peer_table_state.select(Some(next));
        }
        ActiveTab::Routes => {
            if app.route_indices.is_empty() { return; }
            let next = match app.route_table_state.selected() {
                Some(i) => (i + 1) % app.route_indices.len(),
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
    }
}


