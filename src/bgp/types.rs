use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ─── BGP Session State ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
    Unknown(String),
}

impl BgpState {
    #[allow(dead_code)]
    pub fn from_str(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "idle" => BgpState::Idle,
            "connect" => BgpState::Connect,
            "active" => BgpState::Active,
            "opensent" => BgpState::OpenSent,
            "openconfirm" => BgpState::OpenConfirm,
            "established" => BgpState::Established,
            other => BgpState::Unknown(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            BgpState::Idle => "Idle",
            BgpState::Connect => "Connect",
            BgpState::Active => "Active",
            BgpState::OpenSent => "OpenSent",
            BgpState::OpenConfirm => "OpenConfirm",
            BgpState::Established => "Established",
            BgpState::Unknown(s) => s.as_str(),
        }
    }

    pub fn is_established(&self) -> bool {
        matches!(self, BgpState::Established)
    }
}

impl std::fmt::Display for BgpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─── Route Origin ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RouteOrigin {
    Igp,        // i  – originated via IGP
    Egp,        // e  – originated via EGP
    Incomplete, // ?  – origin unknown
}

impl std::fmt::Display for RouteOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteOrigin::Igp => write!(f, "i"),
            RouteOrigin::Egp => write!(f, "e"),
            RouteOrigin::Incomplete => write!(f, "?"),
        }
    }
}

// ─── Route Status Flags ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RouteStatus {
    BestExternal, // *>
    Best,         // >
    Valid,        // *
    Internal,     // i
    Suppressed,   // s
    History,      // h
}

impl std::fmt::Display for RouteStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteStatus::BestExternal => write!(f, "*>"),
            RouteStatus::Best => write!(f, ">"),
            RouteStatus::Valid => write!(f, "* "),
            RouteStatus::Internal => write!(f, " i"),
            RouteStatus::Suppressed => write!(f, "s "),
            RouteStatus::History => write!(f, "h "),
        }
    }
}

// ─── Per-peer route direction ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRouteDirection {
    Received,
    Advertised,
}

impl PeerRouteDirection {
    pub fn label(self) -> &'static str {
        match self {
            PeerRouteDirection::Received => "Received",
            PeerRouteDirection::Advertised => "Advertised",
        }
    }
    pub fn toggle(self) -> Self {
        match self {
            PeerRouteDirection::Received => PeerRouteDirection::Advertised,
            PeerRouteDirection::Advertised => PeerRouteDirection::Received,
        }
    }
}

// ─── MTU probe state ────────────────────────────────────────────────────────

/// State of an on-demand path-MTU probe launched with the `m` key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MtuProbeState {
    /// Probe is in progress.
    Running,
    /// All probes at this frame size succeeded (path MTU ≥ n bytes, IP total).
    Ok(u16),
    /// Full-size probe failed; this smaller frame size worked (tunnel / IPSec path).
    Degraded(u16),
    /// All probes or SSH command failed.
    Failed(String),
}

// ─── BGP Peer ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BgpPeer {
    pub neighbor_ip: IpAddr,
    pub remote_as: u32,
    pub local_as: u32,
    pub state: BgpState,
    pub uptime: Option<String>,
    pub prefixes_received: u64,
    pub prefixes_advertised: u64,
    pub description: Option<String>,
    pub update_source: Option<IpAddr>,
    pub next_hop_self: bool,
    pub route_reflector_client: bool,
    pub password_configured: bool,
    pub msg_rcvd: u64,
    pub msg_sent: u64,
    pub hold_time: u16,
    pub keepalive: u16,
    pub communities: Vec<String>,
    pub route_map_in: Option<String>,
    pub route_map_out: Option<String>,
    // ── Reliability fields (parsed from `show ip bgp neighbors`) ─────────────
    pub reset_count: u32,
    pub last_reset_reason: Option<String>,
    pub notifs_sent: u32,
    pub notifs_rcvd: u32,
    pub bfd_state: Option<String>,
    /// On-demand path-MTU probe result (`m` key in Peers tab).
    pub mtu_probe: Option<MtuProbeState>,
}

impl BgpPeer {
    pub fn session_type(&self) -> &'static str {
        if self.remote_as == self.local_as {
            "iBGP"
        } else {
            "eBGP"
        }
    }

    /// Returns `Some((old_state, new_state))` if the state differs from `other`.
    pub fn state_changed_from(&self, other: &BgpPeer) -> Option<(BgpState, BgpState)> {
        if self.state != other.state {
            Some((other.state.clone(), self.state.clone()))
        } else {
            None
        }
    }
}

// ─── BGP Route ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BgpRoute {
    pub status: RouteStatus,
    pub network: String,  // CIDR, e.g. "10.0.0.0/8"
    pub next_hop: String, // IP or "0.0.0.0" for locally originated
    pub metric: Option<u32>,
    pub local_pref: Option<u32>,
    pub weight: u32,
    pub as_path: Vec<u32>, // empty for iBGP/local routes
    pub origin: RouteOrigin,
    pub communities: Vec<String>,
}

impl BgpRoute {
    pub fn as_path_str(&self) -> String {
        if self.as_path.is_empty() {
            String::new()
        } else {
            self.as_path
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        }
    }
}

// ─── BGP Summary ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpSummary {
    pub router_id: IpAddr,
    pub local_as: u32,
    pub table_version: u64,
    pub peers: Vec<BgpPeer>,
    pub fetched_at: DateTime<Utc>,
}

impl BgpSummary {
    /// Content-equal comparison ignoring `fetched_at` timestamp.
    pub fn content_eq(&self, other: &Self) -> bool {
        self.router_id == other.router_id
            && self.local_as == other.local_as
            && self.table_version == other.table_version
            && self.peers == other.peers
    }
}

impl BgpSummary {
    pub fn established_count(&self) -> usize {
        self.peers
            .iter()
            .filter(|p| p.state.is_established())
            .count()
    }

    pub fn total_prefixes(&self) -> u64 {
        self.peers.iter().map(|p| p.prefixes_received).sum()
    }
}
