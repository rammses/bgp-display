use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

pub mod cisco;
pub mod vyos;

// ─── Vendor ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouterVendor {
    Cisco,
    VyOs,
}

impl std::fmt::Display for RouterVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouterVendor::Cisco => write!(f, "Cisco"),
            RouterVendor::VyOs  => write!(f, "VyOs"),
        }
    }
}

// ─── Router Configuration ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    pub id:        Uuid,
    pub name:      String,
    pub hostname:  String,
    pub vendor:    RouterVendor,
    pub ssh_port:  u16,
    pub username:  String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password:  Option<String>,
    pub local_as:  Option<u32>,
    pub router_id: Option<IpAddr>,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            id:        Uuid::new_v4(),
            name:      "New Router".into(),
            hostname:  "192.168.1.1".into(),
            vendor:    RouterVendor::Cisco,
            ssh_port:  22,
            username:  "admin".into(),
            password:  None,
            local_as:  None,
            router_id: None,
        }
    }
}

// ─── Connection Status ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

impl std::fmt::Display for ConnectionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionStatus::Disconnected => write!(f, "Disconnected"),
            ConnectionStatus::Connecting   => write!(f, "Connecting…"),
            ConnectionStatus::Connected    => write!(f, "Connected"),
            ConnectionStatus::Error(e)     => write!(f, "Error: {e}"),
        }
    }
}

// ─── Router Backend Enum ──────────────────────────────────────────────────────
// Dispatch is handled via enum rather than dyn trait to keep async ergonomics
// simple in stable Rust.

pub enum RouterBackend {
    Cisco(cisco::CiscoBackend),
    VyOs(vyos::VyOsBackend),
}

#[allow(dead_code)]
impl RouterBackend {
    pub fn status(&self) -> &ConnectionStatus {
        match self {
            RouterBackend::Cisco(b) => b.status(),
            RouterBackend::VyOs(b)  => b.status(),
        }
    }

    pub async fn connect(&mut self) -> anyhow::Result<()> {
        match self {
            RouterBackend::Cisco(b) => b.connect().await,
            RouterBackend::VyOs(b)  => b.connect().await,
        }
    }

    pub async fn disconnect(&mut self) -> anyhow::Result<()> {
        match self {
            RouterBackend::Cisco(b) => b.disconnect().await,
            RouterBackend::VyOs(b)  => b.disconnect().await,
        }
    }

    pub async fn refresh(&mut self) -> anyhow::Result<crate::bgp::BgpSummary> {
        match self {
            RouterBackend::Cisco(b) => b.refresh().await,
            RouterBackend::VyOs(b)  => b.refresh().await,
        }
    }

    pub async fn get_routes(&mut self) -> anyhow::Result<Vec<crate::bgp::BgpRoute>> {
        match self {
            RouterBackend::Cisco(b) => b.get_routes().await,
            RouterBackend::VyOs(b)  => b.get_routes().await,
        }
    }

    pub async fn apply_config(&mut self, config: &str) -> anyhow::Result<()> {
        match self {
            RouterBackend::Cisco(b) => b.apply_config(config).await,
            RouterBackend::VyOs(b)  => b.apply_config(config).await,
        }
    }
}
