use crate::{
    bgp::{BgpPeer, BgpRoute, BgpSummary, CommunityListEntry, NeighborDraft, PeerTemplate, PrefixListEntry, RouteMapEntry},
    config::AppConfig,
    db::RouterDb,
    events::{AppEvent, FetchRequest},
    router::{ConnectionStatus, Project, RouterBackend, RouterConfig, RouterVendor},
};
use ratatui::widgets::{ListState, TableState};
use std::collections::{HashMap, VecDeque};
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
pub const EDITOR_FIELDS: &[&str] = &[
    "Name", "Hostname", "Port", "Username", "Password", "Vendor", "VDOM",
];
pub const EDITOR_NFIELDS: usize = 7;

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

// ─── Wizard Mode ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WizardMode {
    Closed,
    NeighborCreate,
    NeighborEdit(IpAddr),
    NeighborDelete(IpAddr),
    RouteMapEdit(String),
    PrefixListEdit(String),
    CommunityListEdit(String),
}

// ─── Confirm Action ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmAction {
    DeleteRouter(Uuid),
    DeleteProject(Uuid),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WizardStep {
    Fields,
    Review,
    Applying,
    Result(bool),
}

// ─── Active Tab ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Dashboard = 0,
    Peers = 1,
    Routes = 2,
    Config = 3,
    Logs = 4,
    Routers = 5,
    ConnLog = 6,
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
            ActiveTab::Peers => ActiveTab::Routes,
            ActiveTab::Routes => ActiveTab::Config,
            ActiveTab::Config => ActiveTab::Logs,
            ActiveTab::Logs => ActiveTab::Routers,
            ActiveTab::Routers => ActiveTab::ConnLog,
            ActiveTab::ConnLog => ActiveTab::Dashboard,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            ActiveTab::Dashboard => ActiveTab::ConnLog,
            ActiveTab::Peers => ActiveTab::Dashboard,
            ActiveTab::Routes => ActiveTab::Peers,
            ActiveTab::Config => ActiveTab::Routes,
            ActiveTab::Logs => ActiveTab::Config,
            ActiveTab::Routers => ActiveTab::Logs,
            ActiveTab::ConnLog => ActiveTab::Routers,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ActiveTab::Dashboard => "1 Dashboard",
            ActiveTab::Peers => "2 Peers",
            ActiveTab::Routes => "3 Routes",
            ActiveTab::Config => "4 Config",
            ActiveTab::Logs => "5 BGP Log",
            ActiveTab::Routers => "6 Routers",
            ActiveTab::ConnLog => "7 SSH Log",
        }
    }
}

// ─── Per-router BGP cache ──────────────────────────────────────────────────────

/// Cached BGP data for a single router, allowing instant display on switch.
pub struct BgpCache {
    pub summary: BgpSummary,
    pub peers: Vec<BgpPeer>,
    pub routes: Vec<BgpRoute>,
    pub config: String,
}

// ─── Per-router ping stats ──────────────────────────────────────────────────

const PING_HISTORY_LEN: usize = 30;

pub struct PingStats {
    /// Ring buffer of recent probes: Some(rtt) = success, None = timeout/failed.
    pub history: VecDeque<Option<std::time::Duration>>,
    /// Last measured RTT (None if last probe failed).
    pub last_rtt: Option<std::time::Duration>,
    /// Timestamp of the most recent probe.
    pub last_probe: Option<chrono::DateTime<chrono::Utc>>,
}

impl PingStats {
    pub fn new() -> Self {
        Self {
            history: VecDeque::with_capacity(PING_HISTORY_LEN),
            last_rtt: None,
            last_probe: None,
        }
    }

    pub fn record(&mut self, rtt: Option<std::time::Duration>) {
        if self.history.len() >= PING_HISTORY_LEN {
            self.history.pop_front();
        }
        self.history.push_back(rtt);
        self.last_rtt = rtt;
        self.last_probe = Some(chrono::Utc::now());
    }

    pub fn loss_pct(&self) -> f64 {
        if self.history.is_empty() {
            return 0.0;
        }
        let fails = self.history.iter().filter(|r| r.is_none()).count();
        (fails as f64 / self.history.len() as f64) * 100.0
    }

    pub fn avg_rtt_ms(&self) -> Option<f64> {
        let successes: Vec<f64> = self
            .history
            .iter()
            .filter_map(|r| r.map(|d| d.as_secs_f64() * 1000.0))
            .collect();
        if successes.is_empty() {
            return None;
        }
        Some(successes.iter().sum::<f64>() / successes.len() as f64)
    }

    pub fn max_rtt_ms(&self) -> Option<f64> {
        self.history
            .iter()
            .filter_map(|r| r.map(|d| d.as_secs_f64() * 1000.0))
            .reduce(f64::max)
    }

    pub fn min_rtt_ms(&self) -> Option<f64> {
        self.history
            .iter()
            .filter_map(|r| r.map(|d| d.as_secs_f64() * 1000.0))
            .reduce(f64::min)
    }

    /// RTT values in ms for sparkline (0.0 for failed probes).
    pub fn sparkline_data(&self) -> Vec<u64> {
        self.history
            .iter()
            .map(|r| match r {
                Some(d) => (d.as_secs_f64() * 1000.0).round() as u64,
                None => 0,
            })
            .collect()
    }
}

// ─── Per-peer route drill-down state ─────────────────────────────────────────

pub struct PeerRouteView {
    pub peer_ip: IpAddr,
    pub direction: crate::bgp::PeerRouteDirection,
    pub routes: Option<Vec<BgpRoute>>,
    pub error: Option<String>,
}

// ─── App State ────────────────────────────────────────────────────────────────

pub struct App {
    // Navigation
    pub current_tab: ActiveTab,
    pub should_quit: bool,

    // Routers
    pub routers: Vec<RouterConfig>,
    pub router_list_state: ListState,
    #[allow(dead_code)]
    pub backends: HashMap<Uuid, RouterBackend>,

    // Per-router connectivity (updated by background TCP probe)
    pub router_status: HashMap<Uuid, ConnectionStatus>,
    pub ping_stats: HashMap<Uuid, PingStats>,

    // Per-router BGP data cache (kept across router switches)
    pub bgp_cache: HashMap<Uuid, BgpCache>,

    // BGP data for the currently selected router
    pub current_summary: Option<BgpSummary>,
    pub current_peers: Vec<BgpPeer>,
    pub current_routes: Vec<BgpRoute>,
    pub peer_table_state: TableState,
    pub route_table_state: TableState,

    // Filter state — Peers tab
    pub peer_filter: String,
    pub peer_filter_mode: FilterMode,
    /// Indices into current_peers that pass the current filter (all when Off).
    pub peer_indices: Vec<usize>,

    // Filter state — Routes tab
    pub route_filter: String,
    pub route_filter_mode: FilterMode,
    pub route_indices: Vec<usize>,

    // Filter state — Config tab
    pub config_filter: String,
    pub config_filter_mode: FilterMode,
    pub config_indices: Vec<usize>,

    // Filter state — Logs tab
    pub log_filter: String,
    pub log_filter_mode: FilterMode,
    pub log_indices: Vec<usize>,

    // Filter state — ConnLog tab
    pub conn_log_filter: String,
    pub conn_log_filter_mode: FilterMode,
    pub conn_log_indices: Vec<usize>,

    // Per-peer route drill-down (Peers tab)
    pub peer_route_view: Option<PeerRouteView>,
    pub peer_route_table_state: TableState,

    // Rendered Cisco config stanza for Config tab
    pub rendered_config: String,
    pub config_lines: Vec<String>,
    pub config_list_state: ListState,
    pub config_rm_name: Option<String>,
    pub config_routemap: Option<crate::bgp::RouteMapDetail>,
    pub routemap_detail_scroll: u16,
    /// Per-router route-map detail cache: (router_id, rm_name) → detail
    pub routemap_cache: HashMap<(Uuid, String), crate::bgp::RouteMapDetail>,

    // General logs
    pub logs: Vec<String>,
    pub log_list_state: ListState,

    // Connectivity-only log (online/offline events)
    pub conn_logs: Vec<String>,
    pub conn_log_state: ListState,

    // Router editor
    pub editor_list_state: ListState,
    pub editor_mode: EditorMode,
    pub editor_field: usize,
    pub editor_buf: String,
    pub editor_draft: Option<RouterConfig>,

    // Status bar
    pub status_message: Option<String>,
    pub tick_counter: u64,

    // Background event + fetch channels
    pub event_tx: Option<mpsc::UnboundedSender<AppEvent>>,
    pub fetch_tx: Option<mpsc::UnboundedSender<FetchRequest>>,
    ping_tick: u8,

    // Background BGP refresh for all connected routers (~30 s)
    bgp_refresh_tick: u16,

    // Debounced route-map SSH fetch — set in on_config_nav(), drained once per tick
    routemap_fetch_queued: Option<String>,

    // Pending BGP update (deferred when user is actively on Config tab)
    pub pending_bgp_update: Option<(Uuid, BgpSummary, String)>,
    pub pending_route_update: Option<(Uuid, Vec<BgpRoute>)>,
    pub has_pending_update: bool,

    // Projects
    pub all_routers: Vec<RouterConfig>,
    pub projects: Vec<Project>,
    pub active_project: Option<Uuid>,
    pub project_list_state: ListState,
    pub project_popup: bool,
    pub project_editor_mode: ProjectEditorMode,
    pub project_editor_buf: String,
    pub project_toggle_state: ListState,

    // Encrypted SQLite database (holds router configs)
    pub router_db: Option<RouterDb>,

    // BGP Neighbor Wizard
    pub wizard_mode: WizardMode,
    pub wizard_step: WizardStep,
    pub wizard_field: usize,
    pub wizard_buf: String,
    pub wizard_draft: Option<NeighborDraft>,
    pub wizard_preview: Vec<String>,
    pub wizard_error: Option<String>,
    pub wizard_result_msg: Option<String>,

    // Route-map editor state
    pub rm_editor_entries: Vec<RouteMapEntry>,
    pub rm_editor_name: String,
    pub rm_editor_selected: usize,
    pub rm_editor_editing: bool,
    pub rm_editor_field: usize,
    pub rm_editor_buf: String,

    // Prefix-list editor state
    pub pl_editor_entries: Vec<PrefixListEntry>,
    pub pl_editor_name: String,
    pub pl_editor_selected: usize,
    pub pl_editor_editing: bool,
    pub pl_editor_field: usize,
    pub pl_editor_buf: String,

    // Community-list editor state
    pub cl_editor_entries: Vec<CommunityListEntry>,
    pub cl_editor_name: String,
    pub cl_editor_selected: usize,
    pub cl_editor_editing: bool,
    pub cl_editor_field: usize,
    pub cl_editor_buf: String,

    // Confirmation dialog (delete router / delete project)
    pub confirm_action: Option<ConfirmAction>,

    // Desired-state neighbor tracking (persisted in DB)
    pub desired_neighbors: HashMap<Uuid, Vec<NeighborDraft>>,

    // Config history for rollback
    pub config_history: Vec<crate::db::ConfigHistoryEntry>,

    // Peer templates (loaded from DB)
    pub peer_templates: Vec<PeerTemplate>,

    // Peer-down alert: tick counter at which the alert was raised (flashes for ~5 s)
    pub peer_down_alert_tick: Option<u64>,

    // Config history popup
    pub show_history: bool,
    pub history_list_state: ListState,

    // Help overlay
    pub show_help: bool,

    // Diff view for neighbor edits (label, change description)
    pub wizard_diff: Vec<(String, String)>,

    // Peer state transition history: (router_id, peer_ip) → deque of (timestamp, old_state, new_state)
    pub peer_state_history: HashMap<(Uuid, IpAddr), VecDeque<(chrono::DateTime<chrono::Utc>, String, String)>>,

    // Clone neighbor to another router
    pub clone_target_router: Option<usize>,
    pub clone_draft: Option<NeighborDraft>,
}

impl App {
    pub fn new(cfg: AppConfig, router_db: RouterDb) -> Self {
        let n = cfg.routers.len();
        let mut app = Self {
            current_tab: ActiveTab::Dashboard,
            should_quit: false,
            routers: cfg.routers.clone(),
            router_list_state: ListState::default(),
            backends: HashMap::new(),
            router_status: HashMap::new(),
            ping_stats: HashMap::new(),
            bgp_cache: HashMap::new(),
            current_summary: None,
            current_peers: vec![],
            current_routes: vec![],
            peer_table_state: TableState::default(),
            route_table_state: TableState::default(),
            peer_filter: String::new(),
            peer_filter_mode: FilterMode::Off,
            peer_indices: vec![],
            route_filter: String::new(),
            route_filter_mode: FilterMode::Off,
            route_indices: vec![],
            config_filter: String::new(),
            config_filter_mode: FilterMode::Off,
            config_indices: vec![],
            log_filter: String::new(),
            log_filter_mode: FilterMode::Off,
            log_indices: vec![],
            conn_log_filter: String::new(),
            conn_log_filter_mode: FilterMode::Off,
            conn_log_indices: vec![],
            peer_route_view: None,
            peer_route_table_state: TableState::default(),
            rendered_config: String::new(),
            config_lines: vec![],
            config_list_state: ListState::default(),
            config_rm_name: None,
            config_routemap: None,
            routemap_detail_scroll: 0,
            routemap_cache: HashMap::new(),
            logs: vec![format!(
                "bgp-link-manager started — logs: {}",
                crate::logging::log_path().display()
            )],
            log_list_state: ListState::default(),
            conn_logs: vec![],
            conn_log_state: ListState::default(),
            editor_list_state: ListState::default(),
            editor_mode: EditorMode::Browse,
            editor_field: 0,
            editor_buf: String::new(),
            editor_draft: None,
            status_message: None,
            tick_counter: 0,
            event_tx: None,
            fetch_tx: None,
            ping_tick: 0,
            bgp_refresh_tick: 0,
            routemap_fetch_queued: None,
            pending_bgp_update: None,
            pending_route_update: None,
            has_pending_update: false,
            all_routers: cfg.routers,
            projects: cfg.projects,
            active_project: None,
            project_list_state: ListState::default(),
            project_popup: false,
            project_editor_mode: ProjectEditorMode::Browse,
            project_editor_buf: String::new(),
            project_toggle_state: ListState::default(),
            router_db: Some(router_db),

            wizard_mode: WizardMode::Closed,
            wizard_step: WizardStep::Fields,
            wizard_field: 0,
            wizard_buf: String::new(),
            wizard_draft: None,
            wizard_preview: vec![],
            wizard_error: None,
            wizard_result_msg: None,

            rm_editor_entries: vec![],
            rm_editor_name: String::new(),
            rm_editor_selected: 0,
            rm_editor_editing: false,
            rm_editor_field: 0,
            rm_editor_buf: String::new(),

            pl_editor_entries: vec![],
            pl_editor_name: String::new(),
            pl_editor_selected: 0,
            pl_editor_editing: false,
            pl_editor_field: 0,
            pl_editor_buf: String::new(),

            cl_editor_entries: vec![],
            cl_editor_name: String::new(),
            cl_editor_selected: 0,
            cl_editor_editing: false,
            cl_editor_field: 0,
            cl_editor_buf: String::new(),

            confirm_action: None,

            desired_neighbors: HashMap::new(),
            config_history: vec![],
            peer_templates: vec![],

            peer_down_alert_tick: None,

            show_history: false,
            history_list_state: ListState::default(),

            show_help: false,

            wizard_diff: vec![],
            peer_state_history: HashMap::new(),

            clone_target_router: None,
            clone_draft: None,
        };

        if n > 0 {
            app.router_list_state.select(Some(0));
            app.editor_list_state.select(Some(0));
            app.peer_table_state.select(Some(0));
            app.route_table_state.select(Some(0));
        }

        // Load desired neighbors and peer templates from DB
        if let Some(db) = &app.router_db {
            if let Ok(neighbors) = db.load_all_neighbors() {
                app.desired_neighbors = neighbors;
            }
            if let Ok(templates) = db.load_peer_templates() {
                app.peer_templates = templates;
            }
        }

        app.reload_selected_router();
        app
    }

    pub fn set_event_tx(&mut self, tx: mpsc::UnboundedSender<AppEvent>) {
        self.event_tx = Some(tx);
    }

    pub fn set_fetch_tx(&mut self, tx: mpsc::UnboundedSender<FetchRequest>) {
        self.fetch_tx = Some(tx);
    }

    pub fn send_fetch(&self, req: FetchRequest) {
        if let Some(tx) = &self.fetch_tx {
            let _ = tx.send(req);
        }
    }

    // ── Peer Template helpers ────────────────────────────────────────────────

    pub fn apply_template_to_draft(&mut self, template_idx: usize) {
        let template = match self.peer_templates.get(template_idx) {
            Some(t) => t.clone(),
            None => return,
        };
        if let Some(ref mut draft) = self.wizard_draft {
            if let Some(ref ras) = template.remote_as {
                draft.remote_as = ras.clone();
            }
            if let Some(ref prefix) = template.description_prefix {
                if draft.description.is_empty() {
                    draft.description = prefix.clone();
                }
            }
            draft.update_source = template.update_source;
            draft.next_hop_self = template.next_hop_self;
            draft.route_reflector_client = template.route_reflector_client;
            draft.hold_time = template.hold_time;
            draft.keepalive = template.keepalive;
            draft.bfd = template.bfd;
            draft.soft_reconfiguration_inbound = template.soft_reconfiguration_inbound;
        }
    }

    // ── JSON Export / Import ────────────────────────────────────────────────

    pub fn export_config(&self) -> String {
        let routers: Vec<crate::export::ExportRouter> = self
            .all_routers
            .iter()
            .map(|r| crate::export::ExportRouter {
                name: r.name.clone(),
                hostname: r.hostname.clone(),
                vendor: r.vendor.to_string(),
                ssh_port: r.ssh_port,
                username: r.username.clone(),
                local_as: r.local_as,
                vdom: r.vdom.clone(),
            })
            .collect();

        let router_name = |id: &Uuid| -> String {
            self.all_routers
                .iter()
                .find(|r| r.id == *id)
                .map(|r| r.name.clone())
                .unwrap_or_default()
        };

        let projects: Vec<crate::export::ExportProject> = self
            .projects
            .iter()
            .map(|p| crate::export::ExportProject {
                name: p.name.clone(),
                router_names: p.router_ids.iter().map(|id| router_name(id)).collect(),
            })
            .collect();

        let mut neighbors = Vec::new();
        for (rid, drafts) in &self.desired_neighbors {
            let rname = router_name(rid);
            for d in drafts {
                neighbors.push(crate::export::ExportNeighbor {
                    router_name: rname.clone(),
                    neighbor_ip: d.neighbor_ip.clone(),
                    remote_as: d.remote_as.clone(),
                    description: d.description.clone(),
                    update_source: d.update_source.clone(),
                    next_hop_self: d.next_hop_self,
                    route_reflector_client: d.route_reflector_client,
                    hold_time: d.hold_time.clone(),
                    keepalive: d.keepalive.clone(),
                    bfd: d.bfd,
                    soft_reconfiguration_inbound: d.soft_reconfiguration_inbound,
                });
            }
        }

        crate::export::export_json(&routers, &projects, &neighbors, &self.peer_templates)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    pub fn import_config(&mut self, json: &str) -> anyhow::Result<String> {
        let data = crate::export::import_json(json)?;

        let mut routers_added = 0u32;
        let mut projects_added = 0u32;
        let mut neighbors_added = 0u32;
        let mut templates_added = 0u32;

        let db = self.router_db.as_ref().ok_or_else(|| anyhow::anyhow!("no database"))?;

        // Import routers (skip if name already exists)
        for er in &data.routers {
            if self.all_routers.iter().any(|r| r.name == er.name) {
                continue;
            }
            let vendor = match er.vendor.to_lowercase().as_str() {
                "vyos" => RouterVendor::VyOs,
                "citrixvpx" | "citrix" => RouterVendor::CitrixVpx,
                "pfsense" => RouterVendor::PfSense,
                "fortigate" => RouterVendor::FortiGate,
                _ => RouterVendor::Cisco,
            };
            let rc = RouterConfig {
                id: Uuid::new_v4(),
                name: er.name.clone(),
                hostname: er.hostname.clone(),
                vendor,
                ssh_port: er.ssh_port,
                username: er.username.clone(),
                password: None,
                local_as: er.local_as,
                router_id: None,
                vdom: er.vdom.clone(),
            };
            db.upsert(&rc)?;
            self.all_routers.push(rc);
            routers_added += 1;
        }

        // Import projects (skip if name already exists)
        for ep in &data.projects {
            if self.projects.iter().any(|p| p.name == ep.name) {
                continue;
            }
            let rids: Vec<Uuid> = ep
                .router_names
                .iter()
                .filter_map(|n| self.all_routers.iter().find(|r| &r.name == n).map(|r| r.id))
                .collect();
            let proj = Project {
                id: Uuid::new_v4(),
                name: ep.name.clone(),
                router_ids: rids,
            };
            db.upsert_project(&proj)?;
            self.projects.push(proj);
            projects_added += 1;
        }

        // Import neighbors
        for en in &data.neighbors {
            let router = match self.all_routers.iter().find(|r| r.name == en.router_name) {
                Some(r) => r.clone(),
                None => continue,
            };
            let mut draft = NeighborDraft::default();
            draft.router_id = Some(router.id);
            draft.neighbor_ip = en.neighbor_ip.clone();
            draft.remote_as = en.remote_as.clone();
            draft.description = en.description.clone();
            draft.update_source = en.update_source.clone();
            draft.next_hop_self = en.next_hop_self;
            draft.route_reflector_client = en.route_reflector_client;
            draft.hold_time = en.hold_time.clone();
            draft.keepalive = en.keepalive.clone();
            draft.bfd = en.bfd;
            draft.soft_reconfiguration_inbound = en.soft_reconfiguration_inbound;
            draft.address_family = crate::bgp::AddressFamily::from_ip(&en.neighbor_ip);
            db.upsert_neighbor(router.id, &draft)?;
            self.desired_neighbors
                .entry(router.id)
                .or_default()
                .push(draft);
            neighbors_added += 1;
        }

        // Import peer templates (skip if name already exists)
        for t in &data.peer_templates {
            if self.peer_templates.iter().any(|pt| pt.name == t.name) {
                continue;
            }
            let mut tmpl = t.clone();
            tmpl.id = Uuid::new_v4();
            db.upsert_peer_template(&tmpl)?;
            self.peer_templates.push(tmpl);
            templates_added += 1;
        }

        Ok(format!(
            "Imported {} routers, {} projects, {} neighbors, {} templates",
            routers_added, projects_added, neighbors_added, templates_added
        ))
    }

    // ── Filter helpers ────────────────────────────────────────────────────────

    /// Recompute `peer_indices` from the current filter and peers list.
    pub fn update_peer_filter(&mut self) {
        let filter = self.peer_filter.to_lowercase();
        self.peer_indices = (0..self.current_peers.len())
            .filter(|&i| {
                if filter.is_empty() {
                    return true;
                }
                let p = &self.current_peers[i];
                p.neighbor_ip.to_string().contains(&filter)
                    || p.remote_as.to_string().contains(&filter)
                    || p.state.as_str().to_lowercase().contains(&filter)
                    || p.description
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&filter)
                    || p.route_map_in
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&filter)
                    || p.route_map_out
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&filter)
                    || p.session_type().to_lowercase().contains(&filter)
            })
            .collect();
        // Keep selection valid
        match self.peer_table_state.selected() {
            Some(i) if i >= self.peer_indices.len() => {
                self.peer_table_state
                    .select(if self.peer_indices.is_empty() {
                        None
                    } else {
                        Some(0)
                    });
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
                if filter.is_empty() {
                    return true;
                }
                let r = &self.current_routes[i];
                r.network.to_lowercase().contains(&filter)
                    || r.next_hop.to_lowercase().contains(&filter)
                    || r.as_path_str().contains(&filter)
                    || r.communities
                        .iter()
                        .any(|c| c.to_lowercase().contains(&filter))
                    || r.origin.to_string().to_lowercase().contains(&filter)
            })
            .collect();
        match self.route_table_state.selected() {
            Some(i) if i >= self.route_indices.len() => {
                self.route_table_state
                    .select(if self.route_indices.is_empty() {
                        None
                    } else {
                        Some(0)
                    });
            }
            None if !self.route_indices.is_empty() => {
                self.route_table_state.select(Some(0));
            }
            _ => {}
        }
    }

    pub fn update_config_filter(&mut self) {
        let filter = self.config_filter.to_lowercase();
        self.config_indices = (0..self.config_lines.len())
            .filter(|&i| {
                if filter.is_empty() {
                    return true;
                }
                self.config_lines[i].to_lowercase().contains(&filter)
            })
            .collect();
        match self.config_list_state.selected() {
            Some(i) if i >= self.config_indices.len() => {
                self.config_list_state
                    .select(if self.config_indices.is_empty() {
                        None
                    } else {
                        Some(0)
                    });
            }
            None if !self.config_indices.is_empty() => {
                self.config_list_state.select(Some(0));
            }
            _ => {}
        }
    }

    pub fn update_log_filter(&mut self) {
        let filter = self.log_filter.to_lowercase();
        self.log_indices = (0..self.logs.len())
            .filter(|&i| {
                if filter.is_empty() {
                    return true;
                }
                self.logs[i].to_lowercase().contains(&filter)
            })
            .collect();
        match self.log_list_state.selected() {
            Some(i) if i >= self.log_indices.len() => {
                self.log_list_state
                    .select(if self.log_indices.is_empty() {
                        None
                    } else {
                        Some(0)
                    });
            }
            None if !self.log_indices.is_empty() => {
                self.log_list_state.select(Some(0));
            }
            _ => {}
        }
    }

    pub fn update_conn_log_filter(&mut self) {
        let filter = self.conn_log_filter.to_lowercase();
        self.conn_log_indices = (0..self.conn_logs.len())
            .filter(|&i| {
                if filter.is_empty() {
                    return true;
                }
                self.conn_logs[i].to_lowercase().contains(&filter)
            })
            .collect();
        match self.conn_log_state.selected() {
            Some(i) if i >= self.conn_log_indices.len() => {
                self.conn_log_state
                    .select(if self.conn_log_indices.is_empty() {
                        None
                    } else {
                        Some(0)
                    });
            }
            None if !self.conn_log_indices.is_empty() => {
                self.conn_log_state.select(Some(0));
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

    /// Called when a BGP fetch succeeds.
    pub fn handle_bgp_data(&mut self, id: Uuid, summary: BgpSummary, rendered: String) {
        self.router_status.insert(id, ConnectionStatus::Connected);

        let is_selected = self.selected_router().map(|r| r.id) == Some(id);

        let router_name = self
            .routers
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| id.to_string());

        // Detect peer state transitions by comparing against cached peers.
        // Collect changes first to avoid borrow conflicts with self.log() etc.
        let mut state_changes: Vec<(IpAddr, String, String, bool, bool)> = Vec::new();
        if let Some(cached) = self.bgp_cache.get(&id) {
            for new_peer in &summary.peers {
                if let Some(old_peer) = cached
                    .peers
                    .iter()
                    .find(|p| p.neighbor_ip == new_peer.neighbor_ip)
                {
                    if let Some((old_state, new_state)) = new_peer.state_changed_from(old_peer) {
                        let is_down = old_state == crate::bgp::BgpState::Established
                            && new_state != crate::bgp::BgpState::Established;
                        let is_up = old_state != crate::bgp::BgpState::Established
                            && new_state == crate::bgp::BgpState::Established;
                        state_changes.push((
                            new_peer.neighbor_ip,
                            old_state.to_string(),
                            new_state.to_string(),
                            is_down,
                            is_up,
                        ));
                    }
                }
            }
        }
        for (ip, old_s, new_s, is_down, is_up) in state_changes {
            let arrow = if is_down {
                "▼ DOWN"
            } else if is_up {
                "▲ UP"
            } else {
                "→"
            };
            let msg = format!("[{router_name}] Peer {ip} {arrow}: {old_s} → {new_s}");
            self.log(&msg);
            self.conn_log(&msg);

            let key = (id, ip);
            let history = self.peer_state_history.entry(key).or_default();
            history.push_back((chrono::Utc::now(), old_s.clone(), new_s.clone()));
            while history.len() > 100 {
                history.pop_front();
            }

            if is_down {
                self.peer_down_alert_tick = Some(self.tick_counter);
                self.set_status(format!("⚠ PEER DOWN: {ip} on {router_name}"));
            } else if is_up {
                self.set_status(format!("✓ Peer {ip} on {router_name} is Established"));
            }
        }

        // Check if the data actually changed compared to the cache
        let data_changed = self
            .bgp_cache
            .get(&id)
            .map(|cached| !cached.summary.content_eq(&summary) || cached.config != rendered)
            .unwrap_or(true); // no cache = treat as changed

        // Always update the per-router cache
        let entry = self.bgp_cache.entry(id).or_insert_with(|| BgpCache {
            summary: summary.clone(),
            peers: vec![],
            routes: vec![],
            config: String::new(),
        });
        entry.summary = summary.clone();
        entry.peers = summary.peers.clone();
        entry.config = rendered.clone();

        if is_selected {
            if !data_changed {
                // Data hasn't changed — don't disturb the user at all
                return;
            }

            // If user is actively browsing the Config tab, defer the update
            if self.current_tab == ActiveTab::Config && !self.config_lines.is_empty() {
                self.pending_bgp_update = Some((id, summary, rendered));
                self.has_pending_update = true;
                return;
            }

            // Otherwise apply immediately
            self.apply_bgp_update(id, summary, rendered);
        }
    }

    /// Apply a BGP data update to the displayed state.
    fn apply_bgp_update(&mut self, id: Uuid, summary: BgpSummary, rendered: String) {
        self.current_peers = summary.peers.clone();
        self.current_summary = Some(summary);
        self.rendered_config = rendered;
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
        self.pending_bgp_update = None;
        self.pending_route_update = None;
        self.has_pending_update = false;
    }

    /// Called when a route table fetch completes.
    pub fn handle_route_data(&mut self, id: Uuid, routes: Vec<BgpRoute>) {
        let is_selected = self.selected_router().map(|r| r.id) == Some(id);

        // Check if routes actually changed
        let data_changed = self
            .bgp_cache
            .get(&id)
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
        self.routemap_cache
            .insert((id, detail.name.clone()), detail.clone());
        if self.config_rm_name.as_deref() == Some(detail.name.as_str()) {
            self.config_routemap = Some(detail);
        }
    }

    fn request_routemap_fetch(&self, rm_name: String) {
        let Some(router) = self.selected_router() else {
            return;
        };
        self.send_fetch(FetchRequest::FetchRouteMap {
            router_id: router.id,
            rm_name,
        });
    }

    /// Called when the selected config line changes — triggers route-map fetch if applicable.
    pub fn on_config_nav(&mut self) {
        let idx = match self.config_list_state.selected() {
            Some(i) => i,
            None => return,
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
                // Queue the fetch — drained once per tick (200 ms) to prevent
                // a storm of SSH calls when scrolling through config lines quickly.
                self.routemap_fetch_queued = Some(rm_name);
            }
        } else {
            self.config_rm_name = None;
            self.config_routemap = None;
            self.routemap_fetch_queued = None;
        }
    }

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

    // ── Neighbor shutdown toggle ─────────────────────────────────────────────

    pub fn toggle_peer_shutdown(&mut self) {
        let peer_ip = match self
            .peer_table_state
            .selected()
            .and_then(|i| self.peer_indices.get(i))
            .and_then(|&idx| self.current_peers.get(idx))
        {
            Some(p) => p.neighbor_ip,
            None => return,
        };

        let router = match self.selected_router() {
            Some(r) => r.clone(),
            None => return,
        };

        let local_as = router.local_as.unwrap_or(0);
        if local_as == 0 {
            self.set_status("Cannot toggle shutdown: unknown local AS");
            return;
        }

        let is_established = self
            .current_peers
            .iter()
            .find(|p| p.neighbor_ip == peer_ip)
            .map(|p| p.state.is_established())
            .unwrap_or(false);

        let (commands, desc) = if is_established {
            (
                crate::router::commands::shutdown_neighbor_commands(
                    &router.vendor,
                    peer_ip,
                    local_as,
                ),
                format!("Shutdown neighbor {peer_ip}"),
            )
        } else {
            (
                crate::router::commands::no_shutdown_neighbor_commands(
                    &router.vendor,
                    peer_ip,
                    local_as,
                ),
                format!("No-shutdown neighbor {peer_ip}"),
            )
        };

        self.send_fetch(FetchRequest::ApplyConfig {
            router_id: router.id,
            commands,
            description: desc.clone(),
        });
        self.set_status(desc);
    }

    // ── Clone neighbor to another router ─────────────────────────────────────

    pub fn start_clone_peer(&mut self) {
        let router_id = match self.selected_router() {
            Some(r) => r.id,
            None => return,
        };

        let peer_ip = match self
            .peer_table_state
            .selected()
            .and_then(|i| self.peer_indices.get(i))
            .and_then(|&idx| self.current_peers.get(idx))
        {
            Some(p) => p.neighbor_ip,
            None => return,
        };

        let from_desired = self.desired_neighbors.get(&router_id).and_then(|neighbors| {
            neighbors
                .iter()
                .find(|d| d.neighbor_ip.trim() == peer_ip.to_string())
                .cloned()
        });

        let draft = if let Some(mut d) = from_desired {
            d.id = None;
            d.router_id = None;
            d.created_at = None;
            d.updated_at = None;
            d
        } else if let Some(peer) = self.current_peers.iter().find(|p| p.neighbor_ip == peer_ip) {
            let mut d = NeighborDraft::default();
            d.neighbor_ip = peer.neighbor_ip.to_string();
            d.remote_as = peer.remote_as.to_string();
            d.description = peer.description.clone().unwrap_or_default();
            d.update_source = peer
                .update_source
                .map(|s| s.to_string())
                .unwrap_or_default();
            d.next_hop_self = peer.next_hop_self;
            d.route_reflector_client = peer.route_reflector_client;
            d.hold_time = peer.hold_time.to_string();
            d.keepalive = peer.keepalive.to_string();
            d.bfd = peer.bfd_state.is_some();
            d.address_family = crate::bgp::AddressFamily::from_ip(&peer.neighbor_ip.to_string());
            d
        } else {
            return;
        };

        self.clone_draft = Some(draft);
        self.clone_target_router = Some(0);
        self.set_status(format!("Clone neighbor {peer_ip} — select target router"));
    }

    pub fn execute_clone(&mut self) {
        let draft = match self.clone_draft.take() {
            Some(d) => d,
            None => return,
        };
        let target_idx = match self.clone_target_router.take() {
            Some(i) => i,
            None => return,
        };
        let target_router = match self.all_routers.get(target_idx) {
            Some(r) => r.clone(),
            None => {
                self.set_status("Clone failed: invalid target router");
                return;
            }
        };

        let local_as = self
            .bgp_cache
            .get(&target_router.id)
            .map(|c| c.summary.local_as)
            .or(target_router.local_as)
            .unwrap_or(0);

        let commands = crate::router::commands::create_neighbor_commands(
            &target_router.vendor,
            &draft,
            local_as,
        );

        let desc = format!(
            "Clone neighbor {} to {}",
            draft.neighbor_ip, target_router.name
        );

        let ip_str = draft.neighbor_ip.clone();
        let rollback_cmds = if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
            crate::router::commands::delete_neighbor_commands(
                &target_router.vendor,
                ip,
                local_as,
                &draft.description,
            )
        } else {
            vec![]
        };

        if let Some(db) = &self.router_db {
            let _ = db.insert_config_history(
                target_router.id,
                "neighbor_clone",
                &desc,
                &commands,
                &rollback_cmds,
            );
        }

        self.send_fetch(FetchRequest::ApplyConfig {
            router_id: target_router.id,
            commands,
            description: desc.clone(),
        });
        self.set_status(desc);
    }

    pub fn cancel_clone(&mut self) {
        self.clone_draft = None;
        self.clone_target_router = None;
        self.set_status("Clone cancelled");
    }

    // ── Wizard helpers ────────────────────────────────────────────────────────

    pub fn wizard_open_create(&mut self) {
        self.wizard_mode = WizardMode::NeighborCreate;
        self.wizard_step = WizardStep::Fields;
        self.wizard_field = 0;
        self.wizard_buf.clear();
        self.wizard_draft = Some(NeighborDraft::default());
        self.wizard_preview.clear();
        self.wizard_error = None;
        self.wizard_result_msg = None;
    }

    pub fn wizard_open_edit(&mut self, peer_ip: IpAddr) {
        let router_id = self.selected_router().map(|r| r.id);

        // Prefer the stored desired-state draft (has password etc.)
        let from_desired = router_id.and_then(|rid| {
            self.desired_neighbors.get(&rid).and_then(|neighbors| {
                neighbors
                    .iter()
                    .find(|d| d.neighbor_ip.trim() == peer_ip.to_string())
                    .cloned()
            })
        });

        let draft = if let Some(d) = from_desired {
            d
        } else if let Some(peer) = self.current_peers.iter().find(|p| p.neighbor_ip == peer_ip)
        {
            let mut d = NeighborDraft::default();
            d.router_id = router_id;
            d.neighbor_ip = peer.neighbor_ip.to_string();
            d.remote_as = peer.remote_as.to_string();
            d.description = peer.description.clone().unwrap_or_default();
            d.update_source = peer
                .update_source
                .map(|s| s.to_string())
                .unwrap_or_default();
            d.next_hop_self = peer.next_hop_self;
            d.route_reflector_client = peer.route_reflector_client;
            d.hold_time = peer.hold_time.to_string();
            d.keepalive = peer.keepalive.to_string();
            d.bfd = peer.bfd_state.is_some();
            d.address_family =
                crate::bgp::AddressFamily::from_ip(&peer.neighbor_ip.to_string());
            d
        } else {
            return;
        };

        self.wizard_mode = WizardMode::NeighborEdit(peer_ip);
        self.wizard_step = WizardStep::Fields;
        self.wizard_field = 0;
        self.wizard_buf = draft.field_value(0);
        self.wizard_draft = Some(draft);
        self.wizard_preview.clear();
        self.wizard_error = None;
        self.wizard_result_msg = None;
    }

    pub fn wizard_open_delete(&mut self, peer_ip: IpAddr) {
        self.wizard_mode = WizardMode::NeighborDelete(peer_ip);
        self.wizard_step = WizardStep::Review;
        self.wizard_error = None;
        self.wizard_result_msg = None;

        if let Some(peer) = self.current_peers.iter().find(|p| p.neighbor_ip == peer_ip) {
            let desc = peer.description.clone().unwrap_or_default();
            let local_as = self
                .current_summary
                .as_ref()
                .map(|s| s.local_as)
                .unwrap_or(0);
            let vendor = self
                .selected_router()
                .map(|r| r.vendor.clone())
                .unwrap_or(RouterVendor::Cisco);
            self.wizard_preview = crate::router::commands::delete_neighbor_commands(
                &vendor, peer_ip, local_as, &desc,
            );
        }
    }

    pub fn wizard_close(&mut self) {
        self.wizard_mode = WizardMode::Closed;
        self.wizard_step = WizardStep::Fields;
        self.wizard_draft = None;
        self.wizard_preview.clear();
        self.wizard_error = None;
        self.wizard_result_msg = None;
        self.wizard_diff.clear();
    }

    pub fn load_config_history(&mut self) {
        if let Some(router) = self.selected_router() {
            let rid = router.id;
            if let Some(db) = &self.router_db {
                self.config_history = db.load_config_history(rid).unwrap_or_default();
            }
        }
    }

    pub fn execute_rollback(&mut self, idx: usize) {
        if idx >= self.config_history.len() {
            return;
        }
        let entry = self.config_history[idx].clone();
        if entry.rollback.is_empty() {
            self.set_status("No rollback commands available for this entry");
            return;
        }
        self.send_fetch(FetchRequest::RollbackConfig {
            router_id: entry.router_id,
            history_id: entry.id,
            commands: entry.rollback.clone(),
            description: format!("Rollback: {}", entry.description),
        });
        self.set_status(format!("Rolling back: {}", entry.description));
    }

    pub fn wizard_generate_preview(&mut self) {
        if let Some(draft) = &self.wizard_draft {
            if let Err(e) = draft.validate() {
                self.wizard_error = Some(e);
                return;
            }
            self.wizard_error = None;
            let local_as = self
                .current_summary
                .as_ref()
                .map(|s| s.local_as)
                .unwrap_or(0);
            let vendor = self
                .selected_router()
                .map(|r| r.vendor.clone())
                .unwrap_or(RouterVendor::Cisco);
            self.wizard_preview =
                crate::router::commands::create_neighbor_commands(&vendor, draft, local_as);

            self.wizard_diff.clear();
            if let WizardMode::NeighborEdit(ip) = &self.wizard_mode {
                let router_id = self.selected_router().map(|r| r.id);
                let old_draft = router_id.and_then(|rid| {
                    self.desired_neighbors.get(&rid).and_then(|neighbors| {
                        neighbors
                            .iter()
                            .find(|d| d.neighbor_ip.trim() == ip.to_string())
                            .cloned()
                    })
                });
                if let Some(old) = old_draft {
                    for i in 0..NeighborDraft::NFIELDS {
                        let old_val = old.field_value(i);
                        let new_val = draft.field_value(i);
                        if old_val != new_val {
                            self.wizard_diff.push((
                                NeighborDraft::FIELDS[i].to_string(),
                                format!("{old_val} → {new_val}"),
                            ));
                        }
                    }
                }
            }

            self.wizard_step = WizardStep::Review;
        }
    }

    pub fn wizard_apply(&mut self) {
        if self.wizard_preview.is_empty() {
            return;
        }
        let router_id = match self.selected_router() {
            Some(r) => r.id,
            None => return,
        };
        let vendor = self
            .selected_router()
            .map(|r| r.vendor.clone())
            .unwrap_or(RouterVendor::Cisco);
        let local_as = self
            .current_summary
            .as_ref()
            .map(|s| s.local_as)
            .unwrap_or(0);

        let (description, action, rollback) = match &self.wizard_mode {
            WizardMode::NeighborCreate => {
                let desc = self
                    .wizard_draft
                    .as_ref()
                    .map(|d| d.description.clone())
                    .unwrap_or_default();
                let ip_str = self
                    .wizard_draft
                    .as_ref()
                    .and_then(|d| d.parsed_ip())
                    .map(|ip| ip.to_string())
                    .unwrap_or_default();
                let rb = if !ip_str.is_empty() {
                    crate::router::commands::delete_neighbor_commands(
                        &vendor,
                        ip_str.parse().unwrap(),
                        local_as,
                        &desc,
                    )
                } else {
                    vec![]
                };
                (format!("Create neighbor {desc}"), "neighbor_create", rb)
            }
            WizardMode::NeighborEdit(ip) => {
                // Rollback is re-applying the old draft from desired_neighbors
                let rb = self
                    .desired_neighbors
                    .get(&router_id)
                    .and_then(|neighbors| {
                        neighbors
                            .iter()
                            .find(|d| d.neighbor_ip.trim() == ip.to_string())
                    })
                    .map(|old_draft| {
                        crate::router::commands::create_neighbor_commands(
                            &vendor, old_draft, local_as,
                        )
                    })
                    .unwrap_or_default();
                (format!("Update neighbor {ip}"), "neighbor_edit", rb)
            }
            WizardMode::NeighborDelete(ip) => {
                // Rollback is re-creating from the stored draft
                let rb = self
                    .desired_neighbors
                    .get(&router_id)
                    .and_then(|neighbors| {
                        neighbors
                            .iter()
                            .find(|d| d.neighbor_ip.trim() == ip.to_string())
                    })
                    .map(|old_draft| {
                        crate::router::commands::create_neighbor_commands(
                            &vendor, old_draft, local_as,
                        )
                    })
                    .unwrap_or_default();
                (format!("Delete neighbor {ip}"), "neighbor_delete", rb)
            }
            WizardMode::RouteMapEdit(name) => {
                (format!("Update route-map {name}"), "routemap_save", vec![])
            }
            WizardMode::PrefixListEdit(name) => (
                format!("Update prefix-list {name}"),
                "prefixlist_save",
                vec![],
            ),
            WizardMode::CommunityListEdit(name) => (
                format!("Update community-list {name}"),
                "communitylist_save",
                vec![],
            ),
            WizardMode::Closed => return,
        };

        // Store config history for rollback
        if let Some(db) = &self.router_db {
            let _ = db.insert_config_history(
                router_id,
                action,
                &description,
                &self.wizard_preview,
                &rollback,
            );
        }

        self.wizard_step = WizardStep::Applying;
        self.send_fetch(FetchRequest::ApplyConfig {
            router_id,
            commands: self.wizard_preview.clone(),
            description,
        });
    }

    // ── Route-map editor helpers ──────────────────────────────────────────────

    pub fn open_routemap_editor(&mut self, name: &str) {
        let router_id = match self.selected_router() {
            Some(r) => r.id,
            None => return,
        };
        let detail = self.routemap_cache.get(&(router_id, name.to_string()));
        let entries = detail.map(|d| d.entries.clone()).unwrap_or_default();

        self.wizard_mode = WizardMode::RouteMapEdit(name.to_string());
        self.wizard_step = WizardStep::Fields;
        self.wizard_error = None;
        self.wizard_result_msg = None;
        self.rm_editor_name = name.to_string();
        self.rm_editor_entries = entries;
        self.rm_editor_selected = 0;
        self.rm_editor_editing = false;
    }

    pub fn rm_editor_generate_preview(&mut self) {
        let vendor = self
            .selected_router()
            .map(|r| r.vendor.clone())
            .unwrap_or(RouterVendor::Cisco);
        self.wizard_preview = crate::router::commands::routemap_save_commands(
            &vendor,
            &self.rm_editor_name,
            &self.rm_editor_entries,
        );
        self.wizard_step = WizardStep::Review;
    }

    // ── Prefix-list editor helpers ────────────────────────────────────────────

    pub fn open_prefixlist_editor(&mut self, name: &str) {
        if self.selected_router().is_none() {
            return;
        }
        let entries = self
            .routemap_cache
            .values()
            .flat_map(|d| d.prefix_lists.get(name).cloned())
            .next()
            .unwrap_or_default();

        self.wizard_mode = WizardMode::PrefixListEdit(name.to_string());
        self.wizard_step = WizardStep::Fields;
        self.wizard_error = None;
        self.wizard_result_msg = None;
        self.pl_editor_name = name.to_string();
        self.pl_editor_entries = entries;
        self.pl_editor_selected = 0;
        self.pl_editor_editing = false;
    }

    pub fn pl_editor_generate_preview(&mut self) {
        // Validate all entries before generating commands
        for (i, entry) in self.pl_editor_entries.iter().enumerate() {
            if let Err(e) = entry.validate() {
                self.wizard_error = Some(format!("Entry {} (seq {}): {e}", i + 1, entry.seq));
                return;
            }
        }
        self.wizard_error = None;

        let vendor = self
            .selected_router()
            .map(|r| r.vendor.clone())
            .unwrap_or(RouterVendor::Cisco);
        self.wizard_preview = crate::router::commands::prefixlist_save_commands(
            &vendor,
            &self.pl_editor_name,
            &self.pl_editor_entries,
        );
        self.wizard_step = WizardStep::Review;
    }

    // ── Community-list editor helpers ─────────────────────────────────────────

    pub fn open_communitylist_editor(&mut self, name: &str) {
        if self.selected_router().is_none() {
            return;
        }
        let entries: Vec<CommunityListEntry> = self
            .routemap_cache
            .values()
            .flat_map(|d| d.community_lists.get(name).cloned())
            .next()
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(i, raw)| {
                let parts: Vec<&str> = raw.splitn(2, char::is_whitespace).collect();
                CommunityListEntry {
                    seq: ((i + 1) * 5) as u32,
                    action: parts.first().unwrap_or(&"permit").to_string(),
                    community: parts.get(1).unwrap_or(&"").to_string(),
                }
            })
            .collect();

        self.wizard_mode = WizardMode::CommunityListEdit(name.to_string());
        self.wizard_step = WizardStep::Fields;
        self.wizard_error = None;
        self.wizard_result_msg = None;
        self.cl_editor_name = name.to_string();
        self.cl_editor_entries = entries;
        self.cl_editor_selected = 0;
        self.cl_editor_editing = false;
    }

    pub fn cl_editor_generate_preview(&mut self) {
        for (i, entry) in self.cl_editor_entries.iter().enumerate() {
            if let Err(e) = entry.validate() {
                self.wizard_error = Some(format!("Entry {} (seq {}): {e}", i + 1, entry.seq));
                return;
            }
        }
        self.wizard_error = None;

        let vendor = self
            .selected_router()
            .map(|r| r.vendor.clone())
            .unwrap_or(RouterVendor::Cisco);
        self.wizard_preview = crate::router::commands::communitylist_save_commands(
            &vendor,
            &self.cl_editor_name,
            &self.cl_editor_entries,
        );
        self.wizard_step = WizardStep::Review;
    }

    // ── Per-peer route drill-down ─────────────────────────────────────────────

    /// Open the per-peer route drill-down for the currently selected peer.
    pub fn open_peer_route_view(&mut self, dir: crate::bgp::PeerRouteDirection) {
        let ip = match self
            .peer_table_state
            .selected()
            .and_then(|i| self.peer_indices.get(i))
            .and_then(|&idx| self.current_peers.get(idx))
        {
            Some(p) => p.neighbor_ip,
            None => return,
        };
        self.peer_route_view = Some(PeerRouteView {
            peer_ip: ip,
            direction: dir,
            routes: None,
            error: None,
        });
        self.peer_route_table_state = TableState::default();
        self.request_peer_routes_fetch(ip, dir);
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
                view.routes = None;
                view.error = None;
                (view.peer_ip, view.direction)
            }
            None => return,
        };
        self.peer_route_table_state = TableState::default();
        self.request_peer_routes_fetch(ip, dir);
        self.set_status(format!("Fetching {} routes for {}…", dir.label(), ip));
    }

    fn request_peer_routes_fetch(&self, ip: IpAddr, dir: crate::bgp::PeerRouteDirection) {
        let Some(router) = self.selected_router() else {
            return;
        };
        self.send_fetch(FetchRequest::FetchPeerRoutes {
            router_id: router.id,
            ip,
            dir,
        });
    }

    /// Called when per-peer routes arrive from the background task.
    pub fn handle_peer_routes(
        &mut self,
        _id: Uuid,
        ip: IpAddr,
        dir: crate::bgp::PeerRouteDirection,
        routes: Vec<BgpRoute>,
    ) {
        let count = routes.len();
        if let Some(view) = self.peer_route_view.as_mut() {
            if view.peer_ip == ip && view.direction == dir {
                view.routes = Some(routes);
                view.error = None;
            } else {
                return;
            }
        } else {
            return;
        }
        if count > 0 {
            self.peer_route_table_state.select(Some(0));
        }
        self.set_status(format!(
            "{} {} routes for {}",
            count,
            dir.label().to_lowercase(),
            ip
        ));
    }

    /// Called when a per-peer routes fetch fails.
    pub fn handle_peer_routes_error(
        &mut self,
        _id: Uuid,
        ip: IpAddr,
        dir: crate::bgp::PeerRouteDirection,
        err: String,
    ) {
        if let Some(view) = self.peer_route_view.as_mut() {
            if view.peer_ip == ip && view.direction == dir {
                view.error = Some(err.clone());
                view.routes = Some(vec![]);
            }
        }
        tracing::warn!(peer = %ip, direction = %dir.label(), error = %err, "peer routes fetch failed");
        self.conn_log(format!(
            "Peer routes error {ip}: {}",
            truncate_error(&err, 60)
        ));
    }

    // ── Path-MTU probe ───────────────────────────────────────────────────────────

    pub fn request_mtu_probe(&self, target: IpAddr) {
        let Some(router) = self.selected_router() else {
            return;
        };
        self.send_fetch(FetchRequest::FetchMtu {
            router_id: router.id,
            target,
        });
    }

    /// Called when a path-MTU probe returns a result.
    pub fn handle_mtu_probe_result(&mut self, _id: Uuid, ip: IpAddr, max_bytes: u16) {
        use crate::bgp::MtuProbeState;
        let state = if max_bytes >= 1500 {
            MtuProbeState::Ok(max_bytes)
        } else if max_bytes > 0 {
            MtuProbeState::Degraded(max_bytes)
        } else {
            MtuProbeState::Failed("all probes failed".into())
        };
        if let Some(peer) = self.current_peers.iter_mut().find(|p| p.neighbor_ip == ip) {
            peer.mtu_probe = Some(state.clone());
        }
        let msg = match &state {
            MtuProbeState::Ok(n) => format!("MTU probe {ip}: OK (path MTU ≥ {n} B)"),
            MtuProbeState::Degraded(n) => format!("MTU probe {ip}: degraded — max frame {n} B"),
            MtuProbeState::Failed(e) => format!("MTU probe {ip}: failed — {e}"),
            MtuProbeState::Running => unreachable!(),
        };
        self.set_status(msg);
    }

    /// Called when a path-MTU probe SSH call fails entirely.
    pub fn handle_mtu_probe_error(&mut self, _id: Uuid, ip: IpAddr, err: String) {
        if let Some(peer) = self.current_peers.iter_mut().find(|p| p.neighbor_ip == ip) {
            peer.mtu_probe = Some(crate::bgp::MtuProbeState::Failed(err.clone()));
        }
        tracing::warn!(target = %ip, error = %err, "MTU probe failed");
        self.conn_log(format!(
            "MTU probe error {ip}: {}",
            truncate_error(&err, 60)
        ));
        self.set_status(format!("MTU probe to {ip} failed"));
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
            self.projects
                .iter()
                .find(|p| p.id == pid)
                .map(|p| p.router_ids.clone())
        });
        self.routers = match ids {
            Some(ref ids) => self
                .all_routers
                .iter()
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
            self.projects
                .iter()
                .find(|p| p.id == pid)
                .map(|p| p.name.as_str())
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
        self.project_editor_buf = String::new();
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

    pub fn project_request_delete(&mut self) {
        if let Some(idx) = self.project_list_state.selected() {
            if idx < self.projects.len() {
                self.confirm_action = Some(ConfirmAction::DeleteProject(self.projects[idx].id));
            }
        }
    }

    pub fn project_delete_selected(&mut self) {
        if let Some(idx) = self.project_list_state.selected() {
            if idx < self.projects.len() {
                let removed = self.projects.remove(idx);
                self.db_delete_project(removed.id);
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
                    self.project_list_state
                        .select(Some(idx.min(self.projects.len() - 1)));
                }
            }
        }
    }

    pub fn confirm_action_execute(&mut self) {
        if let Some(action) = self.confirm_action.take() {
            match action {
                ConfirmAction::DeleteRouter(_) => self.editor_delete_selected(),
                ConfirmAction::DeleteProject(_) => self.project_delete_selected(),
            }
        }
    }

    pub fn confirm_action_cancel(&mut self) {
        self.confirm_action = None;
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
            None => return,
        };
        let router_idx = match self.project_toggle_state.selected() {
            Some(i) => i,
            None => return,
        };
        let rid = match self.all_routers.get(router_idx) {
            Some(r) => r.id,
            None => return,
        };
        let proj = match self.projects.get_mut(proj_idx) {
            Some(p) => p,
            None => return,
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
            self.routers = self
                .all_routers
                .iter()
                .filter(|r| ids.contains(&r.id))
                .cloned()
                .collect();
            if self.routers.is_empty() {
                self.router_list_state.select(None);
            } else if self
                .router_list_state
                .selected()
                .map(|i| i >= self.routers.len())
                .unwrap_or(true)
            {
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
        self.editor_draft = Some(RouterConfig::default());
        self.editor_field = 0;
        self.editor_buf = String::new();
        self.editor_mode = EditorMode::EditField;
        self.set_status("New router — Tab/Enter: next field  Shift-Tab: prev  Esc: cancel");
    }

    pub fn editor_start_edit(&mut self) {
        if let Some(idx) = self.editor_list_state.selected() {
            if let Some(router) = self.routers.get(idx) {
                let draft = router.clone();
                self.editor_buf = editor_field_value(&draft, 0);
                self.editor_field = 0;
                self.editor_draft = Some(draft);
                self.editor_mode = EditorMode::EditField;
                self.set_status(
                    "Editing router — Tab/Enter: next field  Shift-Tab: prev  Esc: cancel",
                );
            }
        }
    }

    pub fn editor_request_delete(&mut self) {
        if let Some(idx) = self.editor_list_state.selected() {
            if idx < self.routers.len() {
                self.confirm_action = Some(ConfirmAction::DeleteRouter(self.routers[idx].id));
            }
        }
    }

    pub fn editor_delete_selected(&mut self) {
        if let Some(idx) = self.editor_list_state.selected() {
            if idx < self.routers.len() {
                let removed = self.routers.remove(idx);
                self.router_status.remove(&removed.id);
                if let Some(pos) = self.all_routers.iter().position(|r| r.id == removed.id) {
                    self.all_routers.remove(pos);
                }
                self.db_delete(removed.id);
                let msg = format!("Router '{}' removed", removed.name);
                self.conn_log(msg);
                if self.routers.is_empty() {
                    self.editor_list_state.select(None);
                } else {
                    self.editor_list_state
                        .select(Some(idx.min(self.routers.len() - 1)));
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
        6 => r.vdom.clone().unwrap_or_default(),
        _ => String::new(),
    }
}

pub fn apply_buf_to_draft(draft: &mut RouterConfig, field: usize, buf: &str) {
    match field {
        0 => draft.name = buf.to_string(),
        1 => draft.hostname = buf.to_string(),
        2 => draft.ssh_port = buf.parse().unwrap_or(22),
        3 => draft.username = buf.to_string(),
        4 => {
            draft.password = if buf.is_empty() {
                None
            } else {
                Some(buf.to_string())
            }
        }
        5 => {
            draft.vendor = match buf.to_lowercase().as_str() {
                "vyos" => RouterVendor::VyOs,
                "citrixvpx" | "citrix" => RouterVendor::CitrixVpx,
                "pfsense" => RouterVendor::PfSense,
                "fortigate" => RouterVendor::FortiGate,
                _ => RouterVendor::Cisco,
            }
        }
        6 => {
            draft.vdom = if buf.is_empty() {
                None
            } else {
                Some(buf.to_string())
            }
        }
        _ => {}
    }
}

/// Extract route-map name from a config line like "  neighbor X route-map NAME in".
pub fn extract_routemap_name_from_line(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let pos = parts.iter().position(|&p| p == "route-map")?;
    parts.get(pos + 1).map(|s| s.to_string())
}

/// Truncate an error message to at most `max` chars for compact UI display.
fn truncate_error(s: &str, max: usize) -> String {
    let line = s.lines().next().unwrap_or(s);
    if line.len() <= max {
        line.to_string()
    } else {
        format!("{}…", &line[..max])
    }
}

// ─── Key Handler ─────────────────────────────────────────────────────────────

pub fn handle_key(app: &mut App, key: crossterm::event::KeyEvent) {
    use crossterm::event::{KeyCode, KeyModifiers};

    // ── Confirmation dialog intercepts all input ─────────────────────────────
    if app.confirm_action.is_some() {
        match key.code {
            KeyCode::Char('y') | KeyCode::Enter => app.confirm_action_execute(),
            KeyCode::Char('n') | KeyCode::Esc => app.confirm_action_cancel(),
            _ => {}
        }
        return;
    }

    // ── Config history popup intercepts all input ────────────────────────────
    if app.show_history {
        match key.code {
            KeyCode::Esc | KeyCode::Char('h') => {
                app.show_history = false;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let i = app.history_list_state.selected().unwrap_or(0);
                if i > 0 {
                    app.history_list_state.select(Some(i - 1));
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let i = app.history_list_state.selected().unwrap_or(0);
                let max = app.config_history.len().saturating_sub(1);
                app.history_list_state.select(Some((i + 1).min(max)));
            }
            KeyCode::Char('u') => {
                if let Some(idx) = app.history_list_state.selected() {
                    app.execute_rollback(idx);
                    app.show_history = false;
                }
            }
            _ => {}
        }
        return;
    }

    // ── Help overlay intercepts all input ────────────────────────────────────
    if app.show_help {
        app.show_help = false;
        return;
    }

    // ── Clone-neighbor popup intercepts all input ────────────────────────────
    if app.clone_draft.is_some() {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(i) = app.clone_target_router.as_mut() {
                    if *i > 0 {
                        *i -= 1;
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(i) = app.clone_target_router.as_mut() {
                    let max = app.all_routers.len().saturating_sub(1);
                    *i = (*i + 1).min(max);
                }
            }
            KeyCode::Enter => app.execute_clone(),
            KeyCode::Esc => app.cancel_clone(),
            _ => {}
        }
        return;
    }

    // ── Router editor captures all input while editing a field ────────────────
    if app.current_tab == ActiveTab::Routers && app.editor_mode == EditorMode::EditField {
        match key.code {
            KeyCode::Esc => {
                app.editor_mode = EditorMode::Browse;
                app.editor_draft = None;
                app.editor_buf.clear();
                app.set_status("Edit cancelled");
            }
            KeyCode::Backspace => {
                app.editor_buf.pop();
            }
            KeyCode::Tab => app.editor_commit_and_advance(),
            KeyCode::Enter => app.editor_commit_and_advance(),
            KeyCode::BackTab => app.editor_commit_and_retreat(),
            // Vendor field (5): Space cycles Cisco ↔ VyOs; other chars are ignored
            KeyCode::Char(' ') if app.editor_field == 5 => {
                if let Some(draft) = app.editor_draft.as_mut() {
                    draft.vendor = match draft.vendor {
                        RouterVendor::Cisco => RouterVendor::VyOs,
                        RouterVendor::VyOs => RouterVendor::CitrixVpx,
                        RouterVendor::CitrixVpx => RouterVendor::PfSense,
                        RouterVendor::PfSense => RouterVendor::FortiGate,
                        RouterVendor::FortiGate => RouterVendor::Cisco,
                    };
                    app.editor_buf = draft.vendor.to_string();
                }
            }
            KeyCode::Char(_) if app.editor_field == 5 => {
                // vendor field is cycle-only; ignore free text
            }
            KeyCode::Char(c) => app.editor_buf.push(c),
            _ => {}
        }
        return;
    }

    // ── Wizard popup captures all input when open ─────────────────────────────
    if app.wizard_mode != WizardMode::Closed {
        handle_wizard_key(app, key);
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
                    KeyCode::Backspace => {
                        app.project_editor_buf.pop();
                    }
                    KeyCode::Enter => app.project_save_name(),
                    KeyCode::Char(c) => app.project_editor_buf.push(c),
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
                        if app.all_routers.is_empty() {
                            return;
                        }
                        let next = match app.project_toggle_state.selected() {
                            Some(0) | None => app.all_routers.len() - 1,
                            Some(i) => i - 1,
                        };
                        app.project_toggle_state.select(Some(next));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.all_routers.is_empty() {
                            return;
                        }
                        let next = match app.project_toggle_state.selected() {
                            Some(i) => (i + 1) % app.all_routers.len(),
                            None => 0,
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
                        if app.projects.is_empty() {
                            return;
                        }
                        let next = match app.project_list_state.selected() {
                            Some(0) | None => app.projects.len() - 1,
                            Some(i) => i - 1,
                        };
                        app.project_list_state.select(Some(next));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.projects.is_empty() {
                            return;
                        }
                        let next = match app.project_list_state.selected() {
                            Some(i) => (i + 1) % app.projects.len(),
                            None => 0,
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
                    KeyCode::Char('d') => app.project_request_delete(),
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
    if app.config_filter_mode == FilterMode::Typing && app.current_tab == ActiveTab::Config {
        match key.code {
            KeyCode::Esc => {
                app.config_filter.clear();
                app.config_filter_mode = FilterMode::Off;
                app.update_config_filter();
            }
            KeyCode::Enter => {
                app.config_filter_mode = if app.config_filter.is_empty() {
                    FilterMode::Off
                } else {
                    FilterMode::Active
                };
            }
            KeyCode::Backspace => {
                app.config_filter.pop();
                app.update_config_filter();
            }
            KeyCode::Char(c) => {
                app.config_filter.push(c);
                app.update_config_filter();
            }
            _ => {}
        }
        return;
    }
    if app.log_filter_mode == FilterMode::Typing && app.current_tab == ActiveTab::Logs {
        match key.code {
            KeyCode::Esc => {
                app.log_filter.clear();
                app.log_filter_mode = FilterMode::Off;
                app.update_log_filter();
            }
            KeyCode::Enter => {
                app.log_filter_mode = if app.log_filter.is_empty() {
                    FilterMode::Off
                } else {
                    FilterMode::Active
                };
            }
            KeyCode::Backspace => {
                app.log_filter.pop();
                app.update_log_filter();
            }
            KeyCode::Char(c) => {
                app.log_filter.push(c);
                app.update_log_filter();
            }
            _ => {}
        }
        return;
    }
    if app.conn_log_filter_mode == FilterMode::Typing && app.current_tab == ActiveTab::ConnLog {
        match key.code {
            KeyCode::Esc => {
                app.conn_log_filter.clear();
                app.conn_log_filter_mode = FilterMode::Off;
                app.update_conn_log_filter();
            }
            KeyCode::Enter => {
                app.conn_log_filter_mode = if app.conn_log_filter.is_empty() {
                    FilterMode::Off
                } else {
                    FilterMode::Active
                };
            }
            KeyCode::Backspace => {
                app.conn_log_filter.pop();
                app.update_conn_log_filter();
            }
            KeyCode::Char(c) => {
                app.conn_log_filter.push(c);
                app.update_conn_log_filter();
            }
            _ => {}
        }
        return;
    }

    // ── Per-peer route drill-down: capture all input while view is open ───────
    if app.peer_route_view.is_some() && app.current_tab == ActiveTab::Peers {
        use crate::bgp::PeerRouteDirection;
        match key.code {
            KeyCode::Esc => {
                app.close_peer_route_view();
            }
            KeyCode::Char('i') => {
                if app.peer_route_view.as_ref().map(|v| v.direction)
                    != Some(PeerRouteDirection::Received)
                {
                    app.toggle_peer_route_direction();
                }
            }
            KeyCode::Char('o') => {
                if app.peer_route_view.as_ref().map(|v| v.direction)
                    != Some(PeerRouteDirection::Advertised)
                {
                    app.toggle_peer_route_direction();
                }
            }
            KeyCode::Tab => {
                app.toggle_peer_route_direction();
            }
            KeyCode::Char('r') | KeyCode::F(5) => {
                let (ip, dir) = match app.peer_route_view.as_mut() {
                    Some(view) => {
                        view.routes = None;
                        view.error = None;
                        (view.peer_ip, view.direction)
                    }
                    None => return,
                };
                app.request_peer_routes_fetch(ip, dir);
                app.set_status(format!("Refreshing {} routes for {}…", dir.label(), ip));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let len = app
                    .peer_route_view
                    .as_ref()
                    .and_then(|v| v.routes.as_ref())
                    .map(|r: &Vec<BgpRoute>| r.len())
                    .unwrap_or(0);
                if len > 0 {
                    let next = match app.peer_route_table_state.selected() {
                        Some(0) | None => len - 1,
                        Some(i) => i - 1,
                    };
                    app.peer_route_table_state.select(Some(next));
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let len = app
                    .peer_route_view
                    .as_ref()
                    .and_then(|v| v.routes.as_ref())
                    .map(|r: &Vec<BgpRoute>| r.len())
                    .unwrap_or(0);
                if len > 0 {
                    let next = match app.peer_route_table_state.selected() {
                        Some(i) => (i + 1) % len,
                        None => 0,
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
        KeyCode::Tab => {
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
        KeyCode::Char('1') => {
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = ActiveTab::Dashboard;
            app.bgp_refresh_tick = 149;
        }
        KeyCode::Char('2') => {
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = ActiveTab::Peers;
            app.bgp_refresh_tick = 149;
        }
        KeyCode::Char('3') => {
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = ActiveTab::Routes;
            app.bgp_refresh_tick = 149;
        }
        KeyCode::Char('4') => app.current_tab = ActiveTab::Config,
        KeyCode::Char('5') => {
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = ActiveTab::Logs;
            app.bgp_refresh_tick = 149;
        }
        KeyCode::Char('6') => {
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = ActiveTab::Routers;
            app.bgp_refresh_tick = 149;
        }
        KeyCode::Char('7') => {
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = ActiveTab::ConnLog;
            app.bgp_refresh_tick = 149;
        }

        // ── Navigation ───────────────────────────────────────────────────────
        KeyCode::Up | KeyCode::Char('k') => navigate_up(app),
        KeyCode::Down | KeyCode::Char('j') => navigate_down(app),

        // ── Help overlay ─────────────────────────────────────────────────────
        KeyCode::Char('?') => {
            app.show_help = !app.show_help;
        }

        // ── Open filter ──────────────────────────────────────────────────────
        KeyCode::Char('/') if app.current_tab == ActiveTab::Peers => {
            app.peer_filter_mode = FilterMode::Typing;
        }
        KeyCode::Char('/') if app.current_tab == ActiveTab::Routes => {
            app.route_filter_mode = FilterMode::Typing;
        }
        KeyCode::Char('/') if app.current_tab == ActiveTab::Config => {
            app.config_filter_mode = FilterMode::Typing;
        }
        KeyCode::Char('/') if app.current_tab == ActiveTab::Logs => {
            app.log_filter_mode = FilterMode::Typing;
        }
        KeyCode::Char('/') if app.current_tab == ActiveTab::ConnLog => {
            app.conn_log_filter_mode = FilterMode::Typing;
        }

        // ── Dismiss active filter with Esc ───────────────────────────────────
        KeyCode::Esc
            if app.current_tab == ActiveTab::Peers && app.peer_filter_mode != FilterMode::Off =>
        {
            app.peer_filter.clear();
            app.peer_filter_mode = FilterMode::Off;
            app.update_peer_filter();
        }
        KeyCode::Esc
            if app.current_tab == ActiveTab::Routes && app.route_filter_mode != FilterMode::Off =>
        {
            app.route_filter.clear();
            app.route_filter_mode = FilterMode::Off;
            app.update_route_filter();
        }
        KeyCode::Esc
            if app.current_tab == ActiveTab::Config
                && app.config_filter_mode != FilterMode::Off =>
        {
            app.config_filter.clear();
            app.config_filter_mode = FilterMode::Off;
            app.update_config_filter();
        }
        KeyCode::Esc
            if app.current_tab == ActiveTab::Logs && app.log_filter_mode != FilterMode::Off =>
        {
            app.log_filter.clear();
            app.log_filter_mode = FilterMode::Off;
            app.update_log_filter();
        }
        KeyCode::Esc
            if app.current_tab == ActiveTab::ConnLog
                && app.conn_log_filter_mode != FilterMode::Off =>
        {
            app.conn_log_filter.clear();
            app.conn_log_filter_mode = FilterMode::Off;
            app.update_conn_log_filter();
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
            app.request_refresh_selected();
            app.set_status("Refreshing…");
            app.log("Manual refresh triggered");
            app.request_ping();
        }

        // ── Config history popup (Config tab) ─────────────────────────────────
        KeyCode::Char('h') if app.current_tab == ActiveTab::Config => {
            app.load_config_history();
            app.show_history = true;
            if !app.config_history.is_empty() {
                app.history_list_state.select(Some(0));
            }
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
            app.set_status(
                "Projects — Enter: switch  a: add  d: delete  e: edit routers  0: all  Esc: close",
            );
        }

        // ── Router editor actions (Routers tab only) ──────────────────────────
        KeyCode::Char('a') if app.current_tab == ActiveTab::Routers => {
            app.editor_start_add();
        }
        KeyCode::Char('d') if app.current_tab == ActiveTab::Routers => {
            app.editor_request_delete();
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

        // ── Path-MTU probe (Peers tab) ──────────────────────────────────────
        KeyCode::Char('m') if app.current_tab == ActiveTab::Peers => {
            if let Some(ip) = app
                .peer_table_state
                .selected()
                .and_then(|i| app.peer_indices.get(i))
                .and_then(|&idx| app.current_peers.get(idx))
                .map(|p| p.neighbor_ip)
            {
                if let Some(peer) = app.current_peers.iter_mut().find(|p| p.neighbor_ip == ip) {
                    peer.mtu_probe = Some(crate::bgp::MtuProbeState::Running);
                }
                app.request_mtu_probe(ip);
                app.set_status(format!("Running MTU probe to {ip}…"));
            }
        }

        // ── Neighbor shutdown toggle (Peers tab) ────────────────────────────
        KeyCode::Char('s')
            if app.current_tab == ActiveTab::Peers && app.peer_route_view.is_none() =>
        {
            app.toggle_peer_shutdown();
        }

        // ── BGP Neighbor Wizard (Peers tab) ─────────────────────────────────
        KeyCode::Char('n')
            if app.current_tab == ActiveTab::Peers || app.current_tab == ActiveTab::Dashboard =>
        {
            app.wizard_open_create();
        }
        KeyCode::Char('e')
            if app.current_tab == ActiveTab::Peers && app.peer_route_view.is_none() =>
        {
            if let Some(ip) = app
                .peer_table_state
                .selected()
                .and_then(|i| app.peer_indices.get(i))
                .and_then(|&idx| app.current_peers.get(idx))
                .map(|p| p.neighbor_ip)
            {
                app.wizard_open_edit(ip);
            }
        }
        KeyCode::Char('x')
            if app.current_tab == ActiveTab::Peers && app.peer_route_view.is_none() =>
        {
            if let Some(ip) = app
                .peer_table_state
                .selected()
                .and_then(|i| app.peer_indices.get(i))
                .and_then(|&idx| app.current_peers.get(idx))
                .map(|p| p.neighbor_ip)
            {
                app.wizard_open_delete(ip);
            }
        }
        KeyCode::Char('c')
            if app.current_tab == ActiveTab::Peers && app.peer_route_view.is_none() =>
        {
            app.start_clone_peer();
        }

        // ── Route-map / Prefix-list / Community-list editors (Config tab) ──
        KeyCode::Char('e') if app.current_tab == ActiveTab::Config => {
            if let Some(line) = app
                .config_list_state
                .selected()
                .and_then(|i| app.config_lines.get(i))
            {
                let trimmed = line.trim();
                if trimmed.contains("route-map") {
                    if let Some(name) = crate::app::extract_routemap_name_from_line(trimmed) {
                        app.open_routemap_editor(&name);
                    }
                } else if trimmed.contains("prefix-list") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if let Some(pos) = parts.iter().position(|&p| p == "prefix-list") {
                        if let Some(name) = parts.get(pos + 1) {
                            let name = name.to_string();
                            app.open_prefixlist_editor(&name);
                        }
                    }
                } else if trimmed.contains("community-list") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if let Some(pos) = parts.iter().position(|&p| p == "community-list") {
                        let name_pos = if parts.get(pos + 1).map(|&s| s == "standard" || s == "expanded").unwrap_or(false) {
                            pos + 2
                        } else {
                            pos + 1
                        };
                        if let Some(name) = parts.get(name_pos) {
                            let name = name.to_string();
                            app.open_communitylist_editor(&name);
                        }
                    }
                }
            }
        }

        // ── Direct prefix-list editor (Config tab, creates new if needed) ──
        KeyCode::Char('P') if app.current_tab == ActiveTab::Config => {
            app.open_prefixlist_editor("NEW-PREFIX-LIST");
        }

        // ── Direct community-list editor (Config tab, creates new if needed)
        KeyCode::Char('C') if app.current_tab == ActiveTab::Config => {
            app.open_communitylist_editor("NEW-COMMUNITY-LIST");
        }

        _ => {}
    }
}

fn navigate_up(app: &mut App) {
    match app.current_tab {
        ActiveTab::Dashboard => {
            if app.routers.is_empty() {
                return;
            }
            let next = match app.router_list_state.selected() {
                Some(0) | None => app.routers.len() - 1,
                Some(i) => i - 1,
            };
            app.router_list_state.select(Some(next));
            app.reload_selected_router();
        }
        ActiveTab::Peers => {
            if app.peer_indices.is_empty() {
                return;
            }
            let len = app.peer_indices.len();
            let next = match app.peer_table_state.selected() {
                Some(0) | None => len - 1,
                Some(i) => i - 1,
            };
            app.peer_table_state.select(Some(next));
        }
        ActiveTab::Routes => {
            if app.route_indices.is_empty() {
                return;
            }
            let len = app.route_indices.len();
            let next = match app.route_table_state.selected() {
                Some(0) | None => len - 1,
                Some(i) => i - 1,
            };
            app.route_table_state.select(Some(next));
        }
        ActiveTab::Logs => {
            let len = if app.log_filter_mode != FilterMode::Off {
                app.log_indices.len()
            } else {
                app.logs.len()
            };
            if len == 0 {
                return;
            }
            let next = match app.log_list_state.selected() {
                Some(0) | None => len - 1,
                Some(i) => i - 1,
            };
            app.log_list_state.select(Some(next));
        }
        ActiveTab::Config => {
            let len = if app.config_filter_mode != FilterMode::Off {
                app.config_indices.len()
            } else {
                app.config_lines.len()
            };
            if len == 0 {
                return;
            }
            let next = match app.config_list_state.selected() {
                Some(0) | None => len - 1,
                Some(i) => i - 1,
            };
            app.config_list_state.select(Some(next));
            app.on_config_nav();
        }
        ActiveTab::Routers => {
            if app.routers.is_empty() {
                return;
            }
            let next = match app.editor_list_state.selected() {
                Some(0) | None => app.routers.len() - 1,
                Some(i) => i - 1,
            };
            app.editor_list_state.select(Some(next));
        }
        ActiveTab::ConnLog => {
            let len = if app.conn_log_filter_mode != FilterMode::Off {
                app.conn_log_indices.len()
            } else {
                app.conn_logs.len()
            };
            if len == 0 {
                return;
            }
            let next = match app.conn_log_state.selected() {
                Some(0) | None => len - 1,
                Some(i) => i - 1,
            };
            app.conn_log_state.select(Some(next));
        }
    }
}

fn navigate_down(app: &mut App) {
    match app.current_tab {
        ActiveTab::Dashboard => {
            if app.routers.is_empty() {
                return;
            }
            let next = match app.router_list_state.selected() {
                Some(i) => (i + 1) % app.routers.len(),
                None => 0,
            };
            app.router_list_state.select(Some(next));
            app.reload_selected_router();
        }
        ActiveTab::Peers => {
            if app.peer_indices.is_empty() {
                return;
            }
            let next = match app.peer_table_state.selected() {
                Some(i) => (i + 1) % app.peer_indices.len(),
                None => 0,
            };
            app.peer_table_state.select(Some(next));
        }
        ActiveTab::Routes => {
            if app.route_indices.is_empty() {
                return;
            }
            let next = match app.route_table_state.selected() {
                Some(i) => (i + 1) % app.route_indices.len(),
                None => 0,
            };
            app.route_table_state.select(Some(next));
        }
        ActiveTab::Logs => {
            let len = if app.log_filter_mode != FilterMode::Off {
                app.log_indices.len()
            } else {
                app.logs.len()
            };
            if len == 0 {
                return;
            }
            let next = match app.log_list_state.selected() {
                Some(i) => (i + 1) % len,
                None => 0,
            };
            app.log_list_state.select(Some(next));
        }
        ActiveTab::Config => {
            let len = if app.config_filter_mode != FilterMode::Off {
                app.config_indices.len()
            } else {
                app.config_lines.len()
            };
            if len == 0 {
                return;
            }
            let next = match app.config_list_state.selected() {
                Some(i) => (i + 1) % len,
                None => 0,
            };
            app.config_list_state.select(Some(next));
            app.on_config_nav();
        }
        ActiveTab::Routers => {
            if app.routers.is_empty() {
                return;
            }
            let next = match app.editor_list_state.selected() {
                Some(i) => (i + 1) % app.routers.len(),
                None => 0,
            };
            app.editor_list_state.select(Some(next));
        }
        ActiveTab::ConnLog => {
            let len = if app.conn_log_filter_mode != FilterMode::Off {
                app.conn_log_indices.len()
            } else {
                app.conn_logs.len()
            };
            if len == 0 {
                return;
            }
            let next = match app.conn_log_state.selected() {
                Some(i) => (i + 1) % len,
                None => 0,
            };
            app.conn_log_state.select(Some(next));
        }
    }
}

// ─── Wizard Key Handler ──────────────────────────────────────────────────────

fn handle_wizard_key(app: &mut App, key: crossterm::event::KeyEvent) {
    match &app.wizard_mode {
        WizardMode::Closed => {}
        WizardMode::NeighborCreate | WizardMode::NeighborEdit(_) => {
            handle_neighbor_wizard_key(app, key);
        }
        WizardMode::NeighborDelete(_) => {
            handle_delete_wizard_key(app, key);
        }
        WizardMode::RouteMapEdit(_) => {
            handle_routemap_editor_key(app, key);
        }
        WizardMode::PrefixListEdit(_) => {
            handle_prefixlist_editor_key(app, key);
        }
        WizardMode::CommunityListEdit(_) => {
            handle_communitylist_editor_key(app, key);
        }
    }
}

fn handle_neighbor_wizard_key(app: &mut App, key: crossterm::event::KeyEvent) {
    use crossterm::event::KeyCode;

    match app.wizard_step {
        WizardStep::Fields => match key.code {
            KeyCode::Esc => app.wizard_close(),
            KeyCode::Tab | KeyCode::Down => {
                if let Some(draft) = app.wizard_draft.as_mut() {
                    if !NeighborDraft::is_toggle_field(app.wizard_field) {
                        draft.set_field(app.wizard_field, &app.wizard_buf);
                    }
                }
                app.wizard_field = (app.wizard_field + 1) % NeighborDraft::NFIELDS;
                app.wizard_buf = app
                    .wizard_draft
                    .as_ref()
                    .map(|d| match app.wizard_field {
                        8 => d.password.clone(),
                        f => d.field_value(f),
                    })
                    .unwrap_or_default();
            }
            KeyCode::BackTab | KeyCode::Up => {
                if let Some(draft) = app.wizard_draft.as_mut() {
                    if !NeighborDraft::is_toggle_field(app.wizard_field) {
                        draft.set_field(app.wizard_field, &app.wizard_buf);
                    }
                }
                app.wizard_field = if app.wizard_field == 0 {
                    NeighborDraft::NFIELDS - 1
                } else {
                    app.wizard_field - 1
                };
                app.wizard_buf = app
                    .wizard_draft
                    .as_ref()
                    .map(|d| match app.wizard_field {
                        8 => d.password.clone(),
                        f => d.field_value(f),
                    })
                    .unwrap_or_default();
            }
            KeyCode::Enter => {
                if let Some(draft) = app.wizard_draft.as_mut() {
                    if !NeighborDraft::is_toggle_field(app.wizard_field) {
                        draft.set_field(app.wizard_field, &app.wizard_buf);
                    }
                }
                app.wizard_generate_preview();
            }
            KeyCode::Char(' ') if NeighborDraft::is_toggle_field(app.wizard_field) => {
                if let Some(draft) = app.wizard_draft.as_mut() {
                    draft.toggle_field(app.wizard_field);
                }
            }
            KeyCode::Backspace => {
                if !NeighborDraft::is_toggle_field(app.wizard_field) {
                    app.wizard_buf.pop();
                }
            }
            KeyCode::Char(c) => {
                if !NeighborDraft::is_toggle_field(app.wizard_field) {
                    app.wizard_buf.push(c);
                }
            }
            _ => {}
        },
        WizardStep::Review => match key.code {
            KeyCode::Esc => {
                app.wizard_step = WizardStep::Fields;
                app.wizard_buf = app
                    .wizard_draft
                    .as_ref()
                    .map(|d| match app.wizard_field {
                        8 => d.password.clone(),
                        f => d.field_value(f),
                    })
                    .unwrap_or_default();
            }
            KeyCode::Enter => app.wizard_apply(),
            _ => {}
        },
        WizardStep::Applying => {}
        WizardStep::Result(_) => match key.code {
            KeyCode::Enter | KeyCode::Esc => app.wizard_close(),
            _ => {}
        },
    }
}

fn handle_delete_wizard_key(app: &mut App, key: crossterm::event::KeyEvent) {
    use crossterm::event::KeyCode;

    match app.wizard_step {
        WizardStep::Review => match key.code {
            KeyCode::Esc => app.wizard_close(),
            KeyCode::Char('y') | KeyCode::Enter => app.wizard_apply(),
            KeyCode::Char('n') => app.wizard_close(),
            _ => {}
        },
        WizardStep::Applying => {}
        WizardStep::Result(_) => match key.code {
            KeyCode::Enter | KeyCode::Esc => app.wizard_close(),
            _ => {}
        },
        _ => {}
    }
}

fn handle_routemap_editor_key(app: &mut App, key: crossterm::event::KeyEvent) {
    use crossterm::event::KeyCode;

    match app.wizard_step {
        WizardStep::Fields => {
            if app.rm_editor_editing {
                match key.code {
                    KeyCode::Esc => {
                        app.rm_editor_editing = false;
                    }
                    KeyCode::Tab => {
                        if let Some(entry) = app.rm_editor_entries.get_mut(app.rm_editor_selected) {
                            match app.rm_editor_field {
                                0 => {
                                    entry.sequence =
                                        app.rm_editor_buf.parse().unwrap_or(entry.sequence)
                                }
                                1 => entry.action = app.rm_editor_buf.clone(),
                                2 => {
                                    entry.match_clauses =
                                        app.rm_editor_buf.lines().map(|s| s.to_string()).collect()
                                }
                                3 => {
                                    entry.set_clauses =
                                        app.rm_editor_buf.lines().map(|s| s.to_string()).collect()
                                }
                                _ => {}
                            }
                        }
                        app.rm_editor_field = (app.rm_editor_field + 1) % 4;
                        if let Some(entry) = app.rm_editor_entries.get(app.rm_editor_selected) {
                            app.rm_editor_buf = match app.rm_editor_field {
                                0 => entry.sequence.to_string(),
                                1 => entry.action.clone(),
                                2 => entry.match_clauses.join("\n"),
                                3 => entry.set_clauses.join("\n"),
                                _ => String::new(),
                            };
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(entry) = app.rm_editor_entries.get_mut(app.rm_editor_selected) {
                            match app.rm_editor_field {
                                0 => {
                                    entry.sequence =
                                        app.rm_editor_buf.parse().unwrap_or(entry.sequence)
                                }
                                1 => entry.action = app.rm_editor_buf.clone(),
                                2 => {
                                    entry.match_clauses =
                                        app.rm_editor_buf.lines().map(|s| s.to_string()).collect()
                                }
                                3 => {
                                    entry.set_clauses =
                                        app.rm_editor_buf.lines().map(|s| s.to_string()).collect()
                                }
                                _ => {}
                            }
                        }
                        app.rm_editor_editing = false;
                    }
                    KeyCode::Char(' ') if app.rm_editor_field == 1 => {
                        app.rm_editor_buf = if app.rm_editor_buf == "permit" {
                            "deny".into()
                        } else {
                            "permit".into()
                        };
                    }
                    KeyCode::Backspace => {
                        app.rm_editor_buf.pop();
                    }
                    KeyCode::Char(c) => app.rm_editor_buf.push(c),
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Esc => app.wizard_close(),
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.rm_editor_selected > 0 {
                            app.rm_editor_selected -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.rm_editor_selected + 1 < app.rm_editor_entries.len() {
                            app.rm_editor_selected += 1;
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(entry) = app.rm_editor_entries.get(app.rm_editor_selected) {
                            app.rm_editor_editing = true;
                            app.rm_editor_field = 0;
                            app.rm_editor_buf = entry.sequence.to_string();
                        }
                    }
                    KeyCode::Char('a') => {
                        let seq = app
                            .rm_editor_entries
                            .last()
                            .map(|e| e.sequence + 10)
                            .unwrap_or(10);
                        app.rm_editor_entries.push(RouteMapEntry {
                            sequence: seq,
                            action: "permit".into(),
                            ..Default::default()
                        });
                        app.rm_editor_selected = app.rm_editor_entries.len() - 1;
                    }
                    KeyCode::Char('d') => {
                        if !app.rm_editor_entries.is_empty() {
                            app.rm_editor_entries.remove(app.rm_editor_selected);
                            if app.rm_editor_selected > 0
                                && app.rm_editor_selected >= app.rm_editor_entries.len()
                            {
                                app.rm_editor_selected =
                                    app.rm_editor_entries.len().saturating_sub(1);
                            }
                        }
                    }
                    KeyCode::Char('s') => {
                        app.rm_editor_generate_preview();
                    }
                    _ => {}
                }
            }
        }
        WizardStep::Review => match key.code {
            KeyCode::Esc => {
                app.wizard_step = WizardStep::Fields;
            }
            KeyCode::Enter => app.wizard_apply(),
            _ => {}
        },
        WizardStep::Applying => {}
        WizardStep::Result(_) => match key.code {
            KeyCode::Enter | KeyCode::Esc => app.wizard_close(),
            _ => {}
        },
    }
}

fn handle_prefixlist_editor_key(app: &mut App, key: crossterm::event::KeyEvent) {
    use crossterm::event::KeyCode;

    match app.wizard_step {
        WizardStep::Fields => {
            if app.pl_editor_editing {
                match key.code {
                    KeyCode::Esc => {
                        app.pl_editor_editing = false;
                    }
                    KeyCode::Tab if app.pl_editor_field == 99 => {}
                    KeyCode::Tab => {
                        if let Some(entry) = app.pl_editor_entries.get_mut(app.pl_editor_selected) {
                            match app.pl_editor_field {
                                0 => entry.seq = app.pl_editor_buf.parse().unwrap_or(entry.seq),
                                1 => entry.action = app.pl_editor_buf.clone(),
                                2 => entry.prefix = app.pl_editor_buf.clone(),
                                _ => {}
                            }
                        }
                        app.pl_editor_field = (app.pl_editor_field + 1) % 3;
                        if let Some(entry) = app.pl_editor_entries.get(app.pl_editor_selected) {
                            app.pl_editor_buf = match app.pl_editor_field {
                                0 => entry.seq.to_string(),
                                1 => entry.action.clone(),
                                2 => entry.prefix.clone(),
                                _ => String::new(),
                            };
                        }
                    }
                    KeyCode::Enter if app.pl_editor_field == 99 => {
                        if !app.pl_editor_buf.is_empty() {
                            app.pl_editor_name = app.pl_editor_buf.clone();
                        }
                        app.pl_editor_editing = false;
                    }
                    KeyCode::Enter => {
                        if let Some(entry) = app.pl_editor_entries.get_mut(app.pl_editor_selected) {
                            match app.pl_editor_field {
                                0 => entry.seq = app.pl_editor_buf.parse().unwrap_or(entry.seq),
                                1 => entry.action = app.pl_editor_buf.clone(),
                                2 => entry.prefix = app.pl_editor_buf.clone(),
                                _ => {}
                            }
                        }
                        app.pl_editor_editing = false;
                    }
                    KeyCode::Char(' ') if app.pl_editor_field == 1 => {
                        app.pl_editor_buf = if app.pl_editor_buf == "permit" {
                            "deny".into()
                        } else {
                            "permit".into()
                        };
                    }
                    KeyCode::Backspace => {
                        app.pl_editor_buf.pop();
                    }
                    KeyCode::Char(c) => app.pl_editor_buf.push(c),
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Esc => app.wizard_close(),
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.pl_editor_selected > 0 {
                            app.pl_editor_selected -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.pl_editor_selected + 1 < app.pl_editor_entries.len() {
                            app.pl_editor_selected += 1;
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(entry) = app.pl_editor_entries.get(app.pl_editor_selected) {
                            app.pl_editor_editing = true;
                            app.pl_editor_field = 0;
                            app.pl_editor_buf = entry.seq.to_string();
                        }
                    }
                    KeyCode::Char('a') => {
                        let seq = app.pl_editor_entries.last().map(|e| e.seq + 5).unwrap_or(5);
                        app.pl_editor_entries.push(PrefixListEntry {
                            seq,
                            action: "permit".into(),
                            prefix: String::new(),
                        });
                        app.pl_editor_selected = app.pl_editor_entries.len() - 1;
                    }
                    KeyCode::Char('d') => {
                        if !app.pl_editor_entries.is_empty() {
                            app.pl_editor_entries.remove(app.pl_editor_selected);
                            if app.pl_editor_selected > 0
                                && app.pl_editor_selected >= app.pl_editor_entries.len()
                            {
                                app.pl_editor_selected =
                                    app.pl_editor_entries.len().saturating_sub(1);
                            }
                        }
                    }
                    KeyCode::Char('N') => {
                        app.pl_editor_editing = true;
                        app.pl_editor_field = 99;
                        app.pl_editor_buf = app.pl_editor_name.clone();
                    }
                    KeyCode::Char('s') => {
                        app.pl_editor_generate_preview();
                    }
                    _ => {}
                }
            }
        }
        WizardStep::Review => match key.code {
            KeyCode::Esc => {
                app.wizard_step = WizardStep::Fields;
            }
            KeyCode::Enter => app.wizard_apply(),
            _ => {}
        },
        WizardStep::Applying => {}
        WizardStep::Result(_) => match key.code {
            KeyCode::Enter | KeyCode::Esc => app.wizard_close(),
            _ => {}
        },
    }
}

fn handle_communitylist_editor_key(app: &mut App, key: crossterm::event::KeyEvent) {
    use crossterm::event::KeyCode;

    match app.wizard_step {
        WizardStep::Fields => {
            if app.cl_editor_editing {
                match key.code {
                    KeyCode::Esc => {
                        app.cl_editor_editing = false;
                    }
                    KeyCode::Tab => {
                        if let Some(entry) = app.cl_editor_entries.get_mut(app.cl_editor_selected) {
                            match app.cl_editor_field {
                                0 => entry.seq = app.cl_editor_buf.parse().unwrap_or(entry.seq),
                                1 => entry.action = app.cl_editor_buf.clone(),
                                2 => entry.community = app.cl_editor_buf.clone(),
                                _ => {}
                            }
                        }
                        app.cl_editor_field = (app.cl_editor_field + 1) % 3;
                        if let Some(entry) = app.cl_editor_entries.get(app.cl_editor_selected) {
                            app.cl_editor_buf = match app.cl_editor_field {
                                0 => entry.seq.to_string(),
                                1 => entry.action.clone(),
                                2 => entry.community.clone(),
                                _ => String::new(),
                            };
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(entry) = app.cl_editor_entries.get_mut(app.cl_editor_selected) {
                            match app.cl_editor_field {
                                0 => entry.seq = app.cl_editor_buf.parse().unwrap_or(entry.seq),
                                1 => entry.action = app.cl_editor_buf.clone(),
                                2 => entry.community = app.cl_editor_buf.clone(),
                                _ => {}
                            }
                        }
                        app.cl_editor_editing = false;
                    }
                    KeyCode::Char(' ') if app.cl_editor_field == 1 => {
                        app.cl_editor_buf = if app.cl_editor_buf == "permit" {
                            "deny".into()
                        } else {
                            "permit".into()
                        };
                    }
                    KeyCode::Backspace => {
                        app.cl_editor_buf.pop();
                    }
                    KeyCode::Char(c) => app.cl_editor_buf.push(c),
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Esc => app.wizard_close(),
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.cl_editor_selected > 0 {
                            app.cl_editor_selected -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.cl_editor_selected + 1 < app.cl_editor_entries.len() {
                            app.cl_editor_selected += 1;
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(entry) = app.cl_editor_entries.get(app.cl_editor_selected) {
                            app.cl_editor_editing = true;
                            app.cl_editor_field = 0;
                            app.cl_editor_buf = entry.seq.to_string();
                        }
                    }
                    KeyCode::Char('a') => {
                        let seq = app.cl_editor_entries.last().map(|e| e.seq + 5).unwrap_or(5);
                        app.cl_editor_entries.push(CommunityListEntry {
                            seq,
                            action: "permit".into(),
                            community: String::new(),
                        });
                        app.cl_editor_selected = app.cl_editor_entries.len() - 1;
                    }
                    KeyCode::Char('d') => {
                        if !app.cl_editor_entries.is_empty() {
                            app.cl_editor_entries.remove(app.cl_editor_selected);
                            if app.cl_editor_selected > 0
                                && app.cl_editor_selected >= app.cl_editor_entries.len()
                            {
                                app.cl_editor_selected =
                                    app.cl_editor_entries.len().saturating_sub(1);
                            }
                        }
                    }
                    KeyCode::Char('s') => {
                        app.cl_editor_generate_preview();
                    }
                    _ => {}
                }
            }
        }
        WizardStep::Review => match key.code {
            KeyCode::Esc => {
                app.wizard_step = WizardStep::Fields;
            }
            KeyCode::Enter => app.wizard_apply(),
            _ => {}
        },
        WizardStep::Applying => {}
        WizardStep::Result(_) => match key.code {
            KeyCode::Enter | KeyCode::Esc => app.wizard_close(),
            _ => {}
        },
    }
}
