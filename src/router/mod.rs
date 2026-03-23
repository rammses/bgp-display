use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

pub mod cisco;
pub mod citrix;
pub mod commands;
pub mod fortigate;
pub mod pfsense;
pub mod vyos;

// ─── SSH multiplexing ─────────────────────────────────────────────────────────
//
// All backends share a ControlMaster socket so that the first SSH connection
// to a router sets up a persistent master, and every subsequent command
// reuses it without re-authenticating.  The master auto-closes 10 minutes
// after the last client disconnects (ControlPersist=600).
//
// %C is an OpenSSH token that expands to a hash of %l%h%p%r, guaranteeing
// a unique socket path per user@host:port combination.

/// Socket path pattern for SSH ControlMaster (uses OpenSSH %C token).
pub const SSH_MUX_CONTROL_PATH: &str = "/tmp/bgp-lm-%C";

/// Gracefully close all SSH master connections for the given routers.
pub async fn cleanup_ssh_sessions(routers: &[RouterConfig]) {
    let control_path_arg = format!("ControlPath={}", SSH_MUX_CONTROL_PATH);
    for router in routers {
        let target = format!("{}@{}", router.username, router.hostname);
        let port = router.ssh_port.to_string();
        let _ = tokio::process::Command::new("ssh")
            .args(["-O", "exit", "-p", &port, "-o", &control_path_arg, &target])
            .stderr(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .output()
            .await;
    }
}

/// Close the ControlMaster socket for a single user@host:port combination.
///
/// Called automatically when a command fails with a stale-socket error so
/// the next retry gets a fresh master.
pub async fn cleanup_mux_socket(username: &str, hostname: &str, port: u16) {
    let control_path_arg = format!("ControlPath={}", SSH_MUX_CONTROL_PATH);
    let target = format!("{username}@{hostname}");
    let port_str = port.to_string();
    let _ = tokio::process::Command::new("ssh")
        .args([
            "-O",
            "exit",
            "-p",
            &port_str,
            "-o",
            &control_path_arg,
            &target,
        ])
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .output()
        .await;
}

/// Returns true when an SSH error is caused by a stale ControlMaster socket.
///
/// OpenSSH emits "Failed to connect to new control master" when the socket
/// file `/tmp/bgp-lm-…` still exists but the master process is dead.
pub fn is_ssh_mux_error(err: &anyhow::Error) -> bool {
    let s = err.to_string();
    s.contains("control master") || s.contains("ControlSocket")
}

// ─── Vendor ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouterVendor {
    Cisco,
    VyOs,
    CitrixVpx,
    PfSense,
    FortiGate,
}

impl std::fmt::Display for RouterVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouterVendor::Cisco => write!(f, "Cisco"),
            RouterVendor::VyOs => write!(f, "VyOs"),
            RouterVendor::CitrixVpx => write!(f, "CitrixVpx"),
            RouterVendor::PfSense => write!(f, "PfSense"),
            RouterVendor::FortiGate => write!(f, "FortiGate"),
        }
    }
}

// ─── Router Configuration ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    pub id: Uuid,
    pub name: String,
    pub hostname: String,
    pub vendor: RouterVendor,
    pub ssh_port: u16,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub local_as: Option<u32>,
    pub router_id: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vdom: Option<String>,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: "New Router".into(),
            hostname: "192.168.1.1".into(),
            vendor: RouterVendor::Cisco,
            ssh_port: 22,
            username: "admin".into(),
            password: None,
            local_as: None,
            router_id: None,
            vdom: None,
        }
    }
}

// ─── Project ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub router_ids: Vec<Uuid>,
}

impl Project {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            router_ids: vec![],
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
            ConnectionStatus::Connecting => write!(f, "Connecting…"),
            ConnectionStatus::Connected => write!(f, "Connected"),
            ConnectionStatus::Error(e) => write!(f, "Error: {e}"),
        }
    }
}

// ─── Router Backend Enum ──────────────────────────────────────────────────────
// Dispatch is handled via enum rather than dyn trait to keep async ergonomics
// simple in stable Rust.

#[allow(dead_code)]
pub enum RouterBackend {
    Cisco(cisco::CiscoBackend),
    VyOs(vyos::VyOsBackend),
    CitrixVpx(citrix::CitrixVpxBackend),
    PfSense(pfsense::PfSenseBackend),
}

#[allow(dead_code)]
impl RouterBackend {
    pub fn status(&self) -> &ConnectionStatus {
        match self {
            RouterBackend::Cisco(b) => b.status(),
            RouterBackend::VyOs(b) => b.status(),
            RouterBackend::CitrixVpx(b) => b.status(),
            RouterBackend::PfSense(b) => b.status(),
        }
    }

    pub async fn connect(&mut self) -> anyhow::Result<()> {
        match self {
            RouterBackend::Cisco(b) => b.connect().await,
            RouterBackend::VyOs(b) => b.connect().await,
            RouterBackend::CitrixVpx(b) => b.connect().await,
            RouterBackend::PfSense(b) => b.connect().await,
        }
    }

    pub async fn disconnect(&mut self) -> anyhow::Result<()> {
        match self {
            RouterBackend::Cisco(b) => b.disconnect().await,
            RouterBackend::VyOs(b) => b.disconnect().await,
            RouterBackend::CitrixVpx(b) => b.disconnect().await,
            RouterBackend::PfSense(b) => b.disconnect().await,
        }
    }

    pub async fn refresh(&mut self) -> anyhow::Result<crate::bgp::BgpSummary> {
        match self {
            RouterBackend::Cisco(b) => b.refresh().await,
            RouterBackend::VyOs(b) => b.refresh().await,
            RouterBackend::CitrixVpx(b) => b.refresh().await,
            RouterBackend::PfSense(b) => b.refresh().await,
        }
    }

    pub async fn get_routes(&mut self) -> anyhow::Result<Vec<crate::bgp::BgpRoute>> {
        match self {
            RouterBackend::Cisco(b) => b.get_routes().await,
            RouterBackend::VyOs(b) => b.get_routes().await,
            RouterBackend::CitrixVpx(b) => b.get_routes().await,
            RouterBackend::PfSense(b) => b.get_routes().await,
        }
    }

    pub async fn apply_config(&mut self, config: &str) -> anyhow::Result<()> {
        match self {
            RouterBackend::Cisco(b) => b.apply_config(config).await,
            RouterBackend::VyOs(b) => b.apply_config(config).await,
            RouterBackend::CitrixVpx(b) => b.apply_config(config).await,
            RouterBackend::PfSense(b) => b.apply_config(config).await,
        }
    }
}
