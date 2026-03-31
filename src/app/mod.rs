use crate::{
    bgp::{
        BgpPeer, BgpRoute, BgpSummary, CommunityListEntry, NeighborDraft, PeerTemplate,
        PrefixListEntry, RouteMapEntry,
    },
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

mod bgp_handlers;
mod filters;
mod helpers;
mod keys;
mod peer_actions;
mod policy_editors;
mod projects;
mod router_editor;
mod ssh_handlers;
mod tick;
mod types;
mod wizard;
mod wizard_keys;

pub(crate) use helpers::truncate_error;
pub use helpers::{apply_buf_to_draft, editor_field_value};
pub use keys::handle_key;
pub use types::*;

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
    /// Per-router prefix-list cache: (router_id, pl_name) → entries
    pub prefix_list_cache: HashMap<(Uuid, String), Vec<PrefixListEntry>>,
    /// Per-router community-list cache: (router_id, cl_name) → entries
    pub community_list_cache: HashMap<(Uuid, String), Vec<CommunityListEntry>>,
    /// Prefix-list name currently shown in Config tab right panel
    pub config_pl_name: Option<String>,

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
    /// When true, user is drilling into match/set clauses of the selected entry
    pub rm_clause_mode: bool,
    /// "match" or "set"
    pub rm_clause_type: String,
    /// Index within the clause list
    pub rm_clause_idx: usize,
    /// Buffer for editing a clause value
    pub rm_clause_buf: String,
    /// Whether currently editing the clause text
    pub rm_clause_editing: bool,

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
    #[allow(clippy::type_complexity)]
    pub peer_state_history:
        HashMap<(Uuid, IpAddr), VecDeque<(chrono::DateTime<chrono::Utc>, String, String)>>,

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
            prefix_list_cache: HashMap::new(),
            community_list_cache: HashMap::new(),
            config_pl_name: None,
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
            rm_clause_mode: false,
            rm_clause_type: String::new(),
            rm_clause_idx: 0,
            rm_clause_buf: String::new(),
            rm_clause_editing: false,

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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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
                router_names: p.router_ids.iter().map(&router_name).collect(),
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

    #[allow(dead_code)]
    pub fn import_config(&mut self, json: &str) -> anyhow::Result<String> {
        let data = crate::export::import_json(json)?;

        let mut routers_added = 0u32;
        let mut projects_added = 0u32;
        let mut neighbors_added = 0u32;
        let mut templates_added = 0u32;

        let db = self
            .router_db
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no database"))?;

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
                "a10" => RouterVendor::A10,
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
            let draft = NeighborDraft {
                router_id: Some(router.id),
                neighbor_ip: en.neighbor_ip.clone(),
                remote_as: en.remote_as.clone(),
                description: en.description.clone(),
                update_source: en.update_source.clone(),
                next_hop_self: en.next_hop_self,
                route_reflector_client: en.route_reflector_client,
                hold_time: en.hold_time.clone(),
                keepalive: en.keepalive.clone(),
                bfd: en.bfd,
                soft_reconfiguration_inbound: en.soft_reconfiguration_inbound,
                address_family: crate::bgp::AddressFamily::from_ip(&en.neighbor_ip),
                ..Default::default()
            };
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
}
