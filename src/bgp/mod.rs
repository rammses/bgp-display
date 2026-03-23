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

// ─── Cisco/FRR `show ip bgp summary` full parser ─────────────────────────────
//
// Parses router-id and local-AS directly from the header so no prior knowledge
// of the router is required.

pub fn parse_bgp_summary(output: &str) -> BgpSummary {
    // Extract router-id and local-AS from:
    //   "BGP router identifier 1.2.3.4, local AS number 65001"
    let hdr_re =
        regex::Regex::new(r"BGP router identifier\s+(\S+),\s+local AS number\s+(\d+)").unwrap();

    let (router_id, local_as) = hdr_re
        .captures(output)
        .map(|c| {
            let rid: IpAddr = c[1]
                .parse()
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            let las: u32 = c[2].parse().unwrap_or(0);
            (rid, las)
        })
        .unwrap_or((IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0));

    parse_cisco_bgp_summary(output, router_id, local_as)
}

// ─── Cisco `show ip bgp summary` parser ──────────────────────────────────────

pub fn parse_cisco_bgp_summary(output: &str, router_id: IpAddr, local_as: u32) -> BgpSummary {
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
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            let remote_as: u32 = cap[2].parse().unwrap_or(0);
            let msg_rcvd: u64 = cap[3].parse().unwrap_or(0);
            let msg_sent: u64 = cap[4].parse().unwrap_or(0);
            let uptime = cap[5].to_string();
            let state_pfx = &cap[6];

            let (state, prefixes_received) = if let Ok(n) = state_pfx.parse::<u64>() {
                (BgpState::Established, n)
            } else {
                (BgpState::from_str(state_pfx), 0)
            };

            let prefixes_advertised: u64 = cap
                .get(7)
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
                reset_count: 0,
                last_reset_reason: None,
                notifs_sent: 0,
                notifs_rcvd: 0,
                bfd_state: None,
                mtu_probe: None,
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

// ─── Address Family ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressFamily {
    Ipv4Unicast,
    Ipv6Unicast,
}

impl Default for AddressFamily {
    fn default() -> Self {
        AddressFamily::Ipv4Unicast
    }
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressFamily::Ipv4Unicast => write!(f, "IPv4 Unicast"),
            AddressFamily::Ipv6Unicast => write!(f, "IPv6 Unicast"),
        }
    }
}

impl AddressFamily {
    pub fn toggle(&self) -> Self {
        match self {
            AddressFamily::Ipv4Unicast => AddressFamily::Ipv6Unicast,
            AddressFamily::Ipv6Unicast => AddressFamily::Ipv4Unicast,
        }
    }

    pub fn from_ip(ip: &str) -> Self {
        if ip.contains(':') {
            AddressFamily::Ipv6Unicast
        } else {
            AddressFamily::Ipv4Unicast
        }
    }
}

// ─── Neighbor draft (wizard input) ──────────────────────────────────────────────

pub mod naming;

#[derive(Debug, Clone)]
pub struct NeighborDraft {
    pub id: Option<uuid::Uuid>,
    pub router_id: Option<uuid::Uuid>,
    pub neighbor_ip: String,
    pub remote_as: String,
    pub description: String,
    pub update_source: String,
    pub next_hop_self: bool,
    pub route_reflector_client: bool,
    pub hold_time: String,
    pub keepalive: String,
    pub password: String,
    pub bfd: bool,
    pub soft_reconfiguration_inbound: bool,
    pub address_family: AddressFamily,
    pub maximum_prefix: String,
    pub maximum_prefix_warning: bool,
    pub weight: String,
    pub default_local_pref: String,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl Default for NeighborDraft {
    fn default() -> Self {
        Self {
            id: None,
            router_id: None,
            neighbor_ip: String::new(),
            remote_as: String::new(),
            description: String::new(),
            update_source: String::new(),
            next_hop_self: false,
            route_reflector_client: false,
            hold_time: "180".into(),
            keepalive: "60".into(),
            password: String::new(),
            bfd: false,
            soft_reconfiguration_inbound: true,
            address_family: AddressFamily::default(),
            maximum_prefix: String::new(),
            maximum_prefix_warning: true,
            weight: String::new(),
            default_local_pref: String::new(),
            created_at: None,
            updated_at: None,
        }
    }
}

impl NeighborDraft {
    pub const FIELDS: &[&str] = &[
        "Neighbor IP",
        "Remote AS",
        "Description",
        "Update Source",
        "Addr Family",
        "Next-hop-self",
        "RR Client",
        "Hold Time",
        "Keepalive",
        "Password",
        "BFD",
        "Soft-reconfig",
        "Max-Prefix",
        "Max-Pfx Warn",
        "Weight",
        "Local-Pref",
    ];

    pub const NFIELDS: usize = 16;

    pub fn field_value(&self, idx: usize) -> String {
        match idx {
            0 => self.neighbor_ip.clone(),
            1 => self.remote_as.clone(),
            2 => self.description.clone(),
            3 => self.update_source.clone(),
            4 => self.address_family.to_string(),
            5 => if self.next_hop_self { "Yes" } else { "No" }.into(),
            6 => if self.route_reflector_client {
                "Yes"
            } else {
                "No"
            }
            .into(),
            7 => self.hold_time.clone(),
            8 => self.keepalive.clone(),
            9 => "●".repeat(self.password.len()),
            10 => if self.bfd { "Yes" } else { "No" }.into(),
            11 => if self.soft_reconfiguration_inbound {
                "Yes"
            } else {
                "No"
            }
            .into(),
            12 => self.maximum_prefix.clone(),
            13 => if self.maximum_prefix_warning {
                "Yes"
            } else {
                "No"
            }
            .into(),
            14 => self.weight.clone(),
            15 => self.default_local_pref.clone(),
            _ => String::new(),
        }
    }

    pub fn set_field(&mut self, idx: usize, val: &str) {
        match idx {
            0 => {
                self.neighbor_ip = val.to_string();
                self.address_family = AddressFamily::from_ip(val);
            }
            1 => self.remote_as = val.to_string(),
            2 => self.description = val.to_string(),
            3 => self.update_source = val.to_string(),
            7 => self.hold_time = val.to_string(),
            8 => self.keepalive = val.to_string(),
            9 => self.password = val.to_string(),
            12 => self.maximum_prefix = val.to_string(),
            14 => self.weight = val.to_string(),
            15 => self.default_local_pref = val.to_string(),
            _ => {}
        }
    }

    pub fn is_toggle_field(idx: usize) -> bool {
        matches!(idx, 4 | 5 | 6 | 10 | 11 | 13)
    }

    pub fn toggle_field(&mut self, idx: usize) {
        match idx {
            4 => self.address_family = self.address_family.toggle(),
            5 => self.next_hop_self = !self.next_hop_self,
            6 => self.route_reflector_client = !self.route_reflector_client,
            10 => self.bfd = !self.bfd,
            11 => self.soft_reconfiguration_inbound = !self.soft_reconfiguration_inbound,
            13 => self.maximum_prefix_warning = !self.maximum_prefix_warning,
            _ => {}
        }
    }

    pub fn parsed_ip(&self) -> Option<IpAddr> {
        self.neighbor_ip.trim().parse().ok()
    }

    pub fn parsed_as(&self) -> Option<u32> {
        self.remote_as.trim().parse().ok()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.parsed_ip().is_none() {
            return Err("Invalid neighbor IP address (IPv4 or IPv6)".into());
        }
        // Validate address family consistency
        if let Some(ip) = self.parsed_ip() {
            let is_v6 = ip.is_ipv6();
            if is_v6 && self.address_family == AddressFamily::Ipv4Unicast {
                return Err("IPv6 address requires IPv6 Unicast address family".into());
            }
            if !is_v6 && self.address_family == AddressFamily::Ipv6Unicast {
                return Err("IPv4 address requires IPv4 Unicast address family".into());
            }
        }
        match self.parsed_as() {
            None => return Err("Remote AS must be a number".into()),
            Some(0) => return Err("Remote AS cannot be 0".into()),
            _ => {}
        }
        if self.description.trim().is_empty() {
            return Err("Description is required (drives naming convention)".into());
        }
        let hold: u16 = self.hold_time.trim().parse().unwrap_or(0);
        let keep: u16 = self.keepalive.trim().parse().unwrap_or(0);
        if hold > 0 && keep > 0 && hold < keep * 3 {
            return Err("Hold time must be >= 3x keepalive".into());
        }
        Ok(())
    }
}

// ─── Peer Template ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerTemplate {
    pub id: uuid::Uuid,
    pub name: String,
    pub remote_as: Option<String>,
    pub description_prefix: Option<String>,
    pub update_source: String,
    pub next_hop_self: bool,
    pub route_reflector_client: bool,
    pub hold_time: String,
    pub keepalive: String,
    pub bfd: bool,
    pub soft_reconfiguration_inbound: bool,
}

impl Default for PeerTemplate {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            name: String::new(),
            remote_as: None,
            description_prefix: None,
            update_source: String::new(),
            next_hop_self: false,
            route_reflector_client: false,
            hold_time: "180".into(),
            keepalive: "60".into(),
            bfd: false,
            soft_reconfiguration_inbound: true,
        }
    }
}

// ─── Route-map detail ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct RouteMapEntry {
    pub sequence: u32,
    pub action: String, // "permit" | "deny"
    pub match_clauses: Vec<String>,
    pub set_clauses: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PrefixListEntry {
    #[allow(dead_code)]
    pub seq: u32,
    pub action: String,
    pub prefix: String,
}

#[derive(Debug, Clone, Default)]
pub struct CommunityListEntry {
    pub seq: u32,
    pub action: String,
    pub community: String,
}

impl CommunityListEntry {
    pub fn validate(&self) -> Result<(), String> {
        if self.action != "permit" && self.action != "deny" {
            return Err(format!(
                "Action must be 'permit' or 'deny', got '{}'",
                self.action
            ));
        }
        if self.community.trim().is_empty() {
            return Err("Community value is required".into());
        }
        Ok(())
    }
}

impl PrefixListEntry {
    /// Validate a prefix-list entry. Returns Ok(()) or a human-readable error.
    pub fn validate(&self) -> Result<(), String> {
        if self.action != "permit" && self.action != "deny" {
            return Err(format!("Action must be 'permit' or 'deny', got '{}'", self.action));
        }

        let parts: Vec<&str> = self.prefix.split_whitespace().collect();
        if parts.is_empty() {
            return Err("Prefix is required".into());
        }

        let cidr = parts[0];
        let (net, bits) = match cidr.split_once('/') {
            Some((n, b)) => (n, b),
            None => return Err(format!("Invalid CIDR: '{cidr}' (expected x.x.x.x/N)")),
        };

        if net.parse::<std::net::Ipv4Addr>().is_err() && net.parse::<std::net::Ipv6Addr>().is_err()
        {
            return Err(format!("Invalid network address: '{net}'"));
        }

        let prefix_len: u8 = bits
            .parse()
            .map_err(|_| format!("Invalid prefix length: '{bits}'"))?;

        let is_v6 = net.contains(':');
        let max_len = if is_v6 { 128 } else { 32 };
        if prefix_len > max_len {
            return Err(format!(
                "Prefix length {prefix_len} exceeds maximum {max_len}"
            ));
        }

        // Parse optional le/ge modifiers
        let mut ge: Option<u8> = None;
        let mut le: Option<u8> = None;
        let mut i = 1;
        while i + 1 < parts.len() {
            match parts[i] {
                "ge" => {
                    ge = Some(parts[i + 1].parse().map_err(|_| {
                        format!("Invalid ge value: '{}'", parts[i + 1])
                    })?);
                }
                "le" => {
                    le = Some(parts[i + 1].parse().map_err(|_| {
                        format!("Invalid le value: '{}'", parts[i + 1])
                    })?);
                }
                _ => {}
            }
            i += 2;
        }

        if let Some(g) = ge {
            if g < prefix_len {
                return Err(format!("ge ({g}) must be >= prefix length ({prefix_len})"));
            }
            if g > max_len {
                return Err(format!("ge ({g}) exceeds maximum {max_len}"));
            }
        }
        if let Some(l) = le {
            if l > max_len {
                return Err(format!("le ({l}) exceeds maximum {max_len}"));
            }
            if l < prefix_len {
                return Err(format!("le ({l}) must be >= prefix length ({prefix_len})"));
            }
        }
        if let (Some(g), Some(l)) = (ge, le) {
            if g > l {
                return Err(format!("ge ({g}) must be <= le ({l})"));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct RouteMapDetail {
    pub name: String,
    pub entries: Vec<RouteMapEntry>,
    /// prefix-list name → entries
    pub prefix_lists: std::collections::HashMap<String, Vec<PrefixListEntry>>,
    /// community-list name → raw permit/deny lines
    pub community_lists: std::collections::HashMap<String, Vec<String>>,
}
