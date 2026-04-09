use crate::bgp::{BgpPeer, BgpRoute, BgpSummary};
use std::collections::VecDeque;
use std::net::IpAddr;
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
