#![allow(dead_code)]

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
    #[serde(default)]
    pub mikrotik_instance: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::{RouterConfig, RouterVendor};

    #[test]
    fn mikrotik_export_defaults_and_roundtrips_without_credentials() {
        let old = r#"{"name":"old","hostname":"lab.invalid","vendor":"Cisco",
            "ssh_port":22,"username":"tester","local_as":65000,"vdom":null}"#;
        let mut router: ExportRouter = serde_json::from_str(old).unwrap();
        assert_eq!(router.mikrotik_instance, None);
        router.vendor = "MikroTik".into();
        router.mikrotik_instance = Some("blue".into());
        let json = export_json(&[router], &[], &[], &[]).unwrap();
        assert!(!json.contains("password"));
        let imported = import_json(&json).unwrap();
        assert_eq!(
            imported.routers[0].mikrotik_instance.as_deref(),
            Some("blue")
        );
        assert_eq!(
            RouterVendor::from_config_name(&imported.routers[0].vendor),
            Some(RouterVendor::MikroTik)
        );
        let mut config = serde_json::to_value(RouterConfig::default()).unwrap();
        config.as_object_mut().unwrap().remove("mikrotik_instance");
        assert!(serde_json::from_value::<RouterConfig>(config)
            .unwrap()
            .mikrotik_instance
            .is_none());
    }

    #[test]
    fn mikrotik_export_vendor_aliases_keep_all_legacy_spellings() {
        for (name, vendor) in [
            ("cisco", RouterVendor::Cisco),
            ("vYoS", RouterVendor::VyOs),
            ("cumulus", RouterVendor::Cumulus),
            ("citrix", RouterVendor::CitrixVpx),
            ("CitrixVpx", RouterVendor::CitrixVpx),
            ("pfSense", RouterVendor::PfSense),
            ("FortiGate", RouterVendor::FortiGate),
            ("a10", RouterVendor::A10),
            ("mIkRoTiK", RouterVendor::MikroTik),
        ] {
            assert_eq!(RouterVendor::from_config_name(name), Some(vendor.clone()));
            let json = serde_json::to_string(&vendor).unwrap();
            assert_eq!(serde_json::from_str::<RouterVendor>(&json).unwrap(), vendor);
        }
        assert_eq!(RouterVendor::from_config_name("not-a-vendor"), None);
        assert_eq!(RouterVendor::MikroTik.to_string(), "MikroTik");
    }
}
