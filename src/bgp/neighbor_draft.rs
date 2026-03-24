use chrono::{DateTime, Utc};
use std::net::IpAddr;

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
