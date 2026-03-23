use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ExportData {
    pub version: String,
    pub routers: Vec<ExportRouter>,
    pub projects: Vec<ExportProject>,
    pub neighbors: Vec<ExportNeighbor>,
    pub peer_templates: Vec<crate::bgp::PeerTemplate>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ExportRouter {
    pub name: String,
    pub hostname: String,
    pub vendor: String,
    pub ssh_port: u16,
    pub username: String,
    pub local_as: Option<u32>,
    pub vdom: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ExportProject {
    pub name: String,
    pub router_names: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ExportNeighbor {
    pub router_name: String,
    pub neighbor_ip: String,
    pub remote_as: String,
    pub description: String,
    pub update_source: String,
    pub next_hop_self: bool,
    pub route_reflector_client: bool,
    pub hold_time: String,
    pub keepalive: String,
    pub bfd: bool,
    pub soft_reconfiguration_inbound: bool,
}

pub fn export_json(
    routers: &[ExportRouter],
    projects: &[ExportProject],
    neighbors: &[ExportNeighbor],
    templates: &[crate::bgp::PeerTemplate],
) -> Result<String> {
    let data = ExportData {
        version: env!("CARGO_PKG_VERSION").to_string(),
        routers: routers.to_vec(),
        projects: projects.to_vec(),
        neighbors: neighbors.to_vec(),
        peer_templates: templates.to_vec(),
    };
    serde_json::to_string_pretty(&data).context("failed to serialize export data")
}

pub fn import_json(json: &str) -> Result<ExportData> {
    serde_json::from_str(json).context("failed to parse import JSON")
}
