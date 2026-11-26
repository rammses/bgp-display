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
    /// Explicitly observed as not established, without claiming a specific FSM state.
    NotEstablished,
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
            BgpState::NotEstablished => "Not established",
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
    Filtered,
    Unreachable,
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
            RouteStatus::Filtered => write!(f, "F "),
            RouteStatus::Unreachable => write!(f, "U "),
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

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeerKey {
    Legacy(String),
    RouterOsConnection { instance: String, name: String },
    RouterOsSession { instance: String, id: String },
}

pub fn known_text<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "N/A".into())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BgpPeer {
    #[serde(default)]
    pub key: Option<PeerKey>,
    #[serde(default)]
    pub admin_disabled: Option<bool>,
    #[serde(default)]
    pub native_source: Option<String>,
    /// Neighbor address, or interface name for BGP unnumbered.
    pub neighbor_ip: String,
    pub remote_as: Option<u32>,
    pub local_as: Option<u32>,
    pub state: BgpState,
    pub uptime: Option<String>,
    pub prefixes_received: Option<u64>,
    pub prefixes_advertised: Option<u64>,
    pub description: Option<String>,
    pub update_source: Option<IpAddr>,
    pub next_hop_self: Option<bool>,
    pub route_reflector_client: Option<bool>,
    pub password_configured: Option<bool>,
    pub msg_rcvd: Option<u64>,
    pub msg_sent: Option<u64>,
    pub hold_time: Option<u16>,
    pub keepalive: Option<u16>,
    pub communities: Vec<String>,
    pub route_map_in: Option<String>,
    pub route_map_out: Option<String>,
    // ── Reliability fields (parsed from `show ip bgp neighbors`) ─────────────
    pub reset_count: Option<u32>,
    pub last_reset_reason: Option<String>,
    pub notifs_sent: Option<u32>,
    pub notifs_rcvd: Option<u32>,
    pub bfd_state: Option<String>,
    /// On-demand path-MTU probe result (`m` key in Peers tab).
    pub mtu_probe: Option<MtuProbeState>,
}

impl BgpPeer {
    pub fn identity(&self) -> PeerKey {
        self.key
            .clone()
            .unwrap_or_else(|| PeerKey::Legacy(self.neighbor_ip.clone()))
    }

    pub fn session_type(&self) -> &'static str {
        match (self.remote_as, self.local_as) {
            (Some(remote), Some(local)) if remote == local => "iBGP",
            (Some(_), Some(_)) => "eBGP",
            _ => "Unknown",
        }
    }

    /// Returns `Some((old_state, new_state))` if the state differs from `other`.
    pub fn state_changed_from(&self, other: &BgpPeer) -> Option<(BgpState, BgpState)> {
        if self.identity() == other.identity()
            && !matches!(self.state, BgpState::Unknown(_))
            && !matches!(other.state, BgpState::Unknown(_))
            && self.state != other.state
        {
            Some((other.state.clone(), self.state.clone()))
        } else {
            None
        }
    }
}

// ─── BGP Route ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BgpRoute {
    pub status: Option<RouteStatus>,
    #[serde(default)]
    pub native_flags: Option<String>,
    #[serde(default)]
    pub as_path_raw: Option<String>,
    pub network: String,  // CIDR, e.g. "10.0.0.0/8"
    pub next_hop: String, // IP or "0.0.0.0" for locally originated
    pub metric: Option<u32>,
    pub local_pref: Option<u32>,
    pub weight: Option<u32>,
    pub as_path: Option<Vec<u32>>, // known empty for iBGP/local routes
    pub origin: Option<RouteOrigin>,
    pub communities: Option<Vec<String>>,
}

impl BgpRoute {
    pub fn as_path_str(&self) -> String {
        if let Some(raw) = &self.as_path_raw {
            raw.clone()
        } else if let Some(path) = &self.as_path {
            path.iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            "N/A".into()
        }
    }
}

// ─── BGP Summary ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpSummary {
    pub router_id: Option<IpAddr>,
    pub local_as: Option<u32>,
    pub table_version: Option<u64>,
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

#[cfg(test)]
mod optional_tests {
    use super::*;

    #[test]
    fn mikrotik_final_001_observed_state_serde_preserves_legacy_states_and_producers() {
        let observed: BgpState = serde_json::from_str("\"NotEstablished\"").unwrap();
        assert_eq!(observed.as_str(), "Not established");
        assert!(!observed.is_established());
        assert_eq!(
            serde_json::to_string(&observed).unwrap(),
            "\"NotEstablished\""
        );
        for (state, encoded) in [
            (BgpState::Idle, "\"Idle\""),
            (BgpState::Connect, "\"Connect\""),
            (BgpState::Active, "\"Active\""),
            (BgpState::OpenSent, "\"OpenSent\""),
            (BgpState::OpenConfirm, "\"OpenConfirm\""),
            (BgpState::Established, "\"Established\""),
            (
                BgpState::Unknown("not established (native)".into()),
                "{\"Unknown\":\"not established (native)\"}",
            ),
        ] {
            assert_eq!(serde_json::to_string(&state).unwrap(), encoded);
            assert_eq!(serde_json::from_str::<BgpState>(encoded).unwrap(), state);
        }
        // Only typed native observations produce the new state, not label parsing.
        assert_eq!(
            BgpState::from_str("not established"),
            BgpState::Unknown("not established".into())
        );
        assert_eq!(BgpState::from_str("Active"), BgpState::Active);
    }

    #[test]
    fn mikrotik_unknowns_checked_totals_identity_and_legacy_serde() {
        let mut summary = crate::bgp::parse_bgp_summary("BGP router identifier 192.0.2.1, local AS number 65000\n192.0.2.2 4 65001 10 20 1 0 0 00:01:00 3 5");
        assert_eq!(summary.total_prefixes(), Some(3));
        assert_eq!(summary.peers[0].session_type(), "eBGP");
        assert_eq!(
            summary.peers[0].identity(),
            PeerKey::Legacy("192.0.2.2".into())
        );
        let mut old_json = serde_json::to_value(&summary.peers[0]).unwrap();
        for field in ["key", "admin_disabled", "native_source"] {
            old_json.as_object_mut().unwrap().remove(field);
        }
        let old: BgpPeer = serde_json::from_value(old_json).unwrap();
        assert_eq!(old, summary.peers[0]);
        summary.peers[0].prefixes_received = Some(u64::MAX);
        summary.peers.push(old);
        assert_eq!(summary.total_prefixes(), None);
        summary.peers[0].prefixes_received = None;
        assert_eq!(summary.total_prefixes(), None);
        summary.peers[0].remote_as = None;
        assert_eq!(summary.peers[0].session_type(), "Unknown");
        summary.peers[0].state = BgpState::Unknown("unobserved".into());
        assert!(summary.peers[0]
            .state_changed_from(&summary.peers[1])
            .is_none());
    }
}

impl BgpSummary {
    pub fn established_count(&self) -> usize {
        self.peers
            .iter()
            .filter(|p| p.state.is_established())
            .count()
    }

    pub fn total_prefixes(&self) -> Option<u64> {
        // An empty unversioned native observation is not a measured zero.
        if self.peers.is_empty() && self.table_version.is_none() {
            return None;
        }
        self.peers
            .iter()
            .try_fold(0u64, |sum, peer| sum.checked_add(peer.prefixes_received?))
    }
}
