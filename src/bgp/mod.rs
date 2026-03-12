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
            "idle"        => BgpState::Idle,
            "connect"     => BgpState::Connect,
            "active"      => BgpState::Active,
            "opensent"    => BgpState::OpenSent,
            "openconfirm" => BgpState::OpenConfirm,
            "established" => BgpState::Established,
            other         => BgpState::Unknown(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            BgpState::Idle        => "Idle",
            BgpState::Connect     => "Connect",
            BgpState::Active      => "Active",
            BgpState::OpenSent    => "OpenSent",
            BgpState::OpenConfirm => "OpenConfirm",
            BgpState::Established => "Established",
            BgpState::Unknown(s)  => s.as_str(),
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
            RouteOrigin::Igp        => write!(f, "i"),
            RouteOrigin::Egp        => write!(f, "e"),
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
            RouteStatus::Best         => write!(f, ">"),
            RouteStatus::Valid        => write!(f, "* "),
            RouteStatus::Internal     => write!(f, " i"),
            RouteStatus::Suppressed   => write!(f, "s "),
            RouteStatus::History      => write!(f, "h "),
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
            PeerRouteDirection::Received   => "Received",
            PeerRouteDirection::Advertised => "Advertised",
        }
    }
    pub fn toggle(self) -> Self {
        match self {
            PeerRouteDirection::Received   => PeerRouteDirection::Advertised,
            PeerRouteDirection::Advertised => PeerRouteDirection::Received,
        }
    }
}

// ─── BGP Peer ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BgpPeer {
    pub neighbor_ip:            IpAddr,
    pub remote_as:              u32,
    pub local_as:               u32,
    pub state:                  BgpState,
    pub uptime:                 Option<String>,
    pub prefixes_received:      u64,
    pub prefixes_advertised:    u64,
    pub description:            Option<String>,
    pub update_source:          Option<IpAddr>,
    pub next_hop_self:          bool,
    pub route_reflector_client: bool,
    pub password_configured:    bool,
    pub msg_rcvd:               u64,
    pub msg_sent:               u64,
    pub hold_time:              u16,
    pub keepalive:              u16,
    pub communities:            Vec<String>,
    pub route_map_in:           Option<String>,
    pub route_map_out:          Option<String>,
}

impl BgpPeer {
    pub fn session_type(&self) -> &'static str {
        if self.remote_as == self.local_as { "iBGP" } else { "eBGP" }
    }
}

// ─── BGP Route ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BgpRoute {
    pub status:      RouteStatus,
    pub network:     String,   // CIDR, e.g. "10.0.0.0/8"
    pub next_hop:    String,   // IP or "0.0.0.0" for locally originated
    pub metric:      Option<u32>,
    pub local_pref:  Option<u32>,
    pub weight:      u32,
    pub as_path:     Vec<u32>, // empty for iBGP/local routes
    pub origin:      RouteOrigin,
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
    pub router_id:      IpAddr,
    pub local_as:       u32,
    pub table_version:  u64,
    pub peers:          Vec<BgpPeer>,
    pub fetched_at:     DateTime<Utc>,
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
        self.peers.iter().filter(|p| p.state.is_established()).count()
    }

    pub fn total_prefixes(&self) -> u64 {
        self.peers.iter().map(|p| p.prefixes_received).sum()
    }
}

// ─── Cisco/FRR `show ip bgp summary` full parser ─────────────────────────────
//
// Parses router-id and local-AS directly from the header so no prior knowledge
// of the router is required.

pub fn parse_bgp_summary(output: &str) -> BgpSummary {
    // Extract router-id and local-AS from:
    //   "BGP router identifier 1.2.3.4, local AS number 65001"
    let hdr_re = regex::Regex::new(
        r"BGP router identifier\s+(\S+),\s+local AS number\s+(\d+)"
    ).unwrap();

    let (router_id, local_as) = hdr_re
        .captures(output)
        .map(|c| {
            let rid: IpAddr = c[1].parse()
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            let las: u32    = c[2].parse().unwrap_or(0);
            (rid, las)
        })
        .unwrap_or((IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0));

    parse_cisco_bgp_summary(output, router_id, local_as)
}

// ─── Cisco `show ip bgp summary` parser ──────────────────────────────────────

pub fn parse_cisco_bgp_summary(
    output:    &str,
    router_id: IpAddr,
    local_as:  u32,
) -> BgpSummary {
    let mut peers: Vec<BgpPeer> = Vec::new();
    let mut table_version = 0u64;

    // Regex: Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd [PfxSnt] [Desc]
    // The PfxSnt column is present in newer FRR versions.
    let row_re = regex::Regex::new(
        r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+(\d+))?",
    )
    .unwrap();
    let tv_re = regex::Regex::new(r"table version is (\d+)").unwrap();

    for line in output.lines() {
        if let Some(cap) = tv_re.captures(line) {
            table_version = cap[1].parse().unwrap_or(0);
        }
        if let Some(cap) = row_re.captures(line) {
            let neighbor_ip: IpAddr = cap[1]
                .parse()
                .unwrap_or_else(|_| IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            let remote_as: u32 = cap[2].parse().unwrap_or(0);
            let msg_rcvd:  u64 = cap[3].parse().unwrap_or(0);
            let msg_sent:  u64 = cap[4].parse().unwrap_or(0);
            let uptime         = cap[5].to_string();
            let state_pfx      = &cap[6];

            let (state, prefixes_received) = if let Ok(n) = state_pfx.parse::<u64>() {
                (BgpState::Established, n)
            } else {
                (BgpState::from_str(state_pfx), 0)
            };

            let prefixes_advertised: u64 = cap.get(7)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);

            peers.push(BgpPeer {
                neighbor_ip,
                remote_as,
                local_as,
                state,
                uptime: Some(uptime),
                prefixes_received,
                prefixes_advertised,
                description: None,
                update_source: None,
                next_hop_self: false,
                route_reflector_client: false,
                password_configured: false,
                msg_rcvd,
                msg_sent,
                hold_time: 90,
                keepalive: 30,
                communities: vec![],
                route_map_in: None,
                route_map_out: None,
            });
        }
    }

    BgpSummary {
        router_id,
        local_as,
        table_version,
        peers,
        fetched_at: Utc::now(),
    }
}

// ─── Route-map detail ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct RouteMapEntry {
    pub sequence:      u32,
    pub action:        String,        // "permit" | "deny"
    pub match_clauses: Vec<String>,
    pub set_clauses:   Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PrefixListEntry {
    #[allow(dead_code)]
    pub seq:    u32,
    pub action: String,
    pub prefix: String,
}

#[derive(Debug, Clone, Default)]
pub struct RouteMapDetail {
    pub name:            String,
    pub entries:         Vec<RouteMapEntry>,
    /// prefix-list name → entries
    pub prefix_lists:    std::collections::HashMap<String, Vec<PrefixListEntry>>,
    /// community-list name → raw permit/deny lines
    pub community_lists: std::collections::HashMap<String, Vec<String>>,
}
