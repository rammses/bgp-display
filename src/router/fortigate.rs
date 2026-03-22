// FortiGate / FortiOS SSH backend.
//
// SSH transport is delegated to the shared SshSessionManager.
// FortiOS uses its own native CLI (no vtysh). Commands are piped via
// run_piped() with optional VDOM wrapping. FortiOS embeds a forked FRR
// daemon so the output is parsed by cisco.rs parsers.

#![allow(dead_code)]

use crate::{
    bgp::{parse_bgp_summary, BgpRoute, BgpSummary},
    router::cisco::{
        parse_all_neighbor_details, parse_bgp_table, parse_community_list_entries,
        parse_prefix_list_entries, parse_route_map_entries,
    },
    router::{ConnectionStatus, RouterConfig},
    ssh::SshSessionManager,
};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

pub struct FortiGateBackend {
    config: RouterConfig,
    ssh: Arc<SshSessionManager>,
    status: ConnectionStatus,
}

impl FortiGateBackend {
    pub fn new(cfg: &RouterConfig, ssh: Arc<SshSessionManager>) -> Self {
        Self {
            config: cfg.clone(),
            ssh,
            status: ConnectionStatus::Disconnected,
        }
    }

    pub fn status(&self) -> &ConnectionStatus {
        &self.status
    }

    // ── Core SSH helper ───────────────────────────────────────────────────────

    async fn run_cli_pipeline(&self, cmds: &[&str]) -> Result<String> {
        let mut script = String::new();

        if let Some(ref vdom) = self.config.vdom {
            script.push_str("config vdom\n");
            script.push_str(&format!("edit {vdom}\n"));
        }
        for cmd in cmds {
            script.push_str(cmd);
            script.push('\n');
        }
        if self.config.vdom.is_some() {
            script.push_str("end\n");
        }
        script.push_str("exit\n");

        let raw = self.ssh.run_piped(self.config.id, &script).await?;
        Ok(strip_fortigate_noise(&raw))
    }

    // ── connect ───────────────────────────────────────────────────────────────

    pub async fn connect(&mut self) -> Result<()> {
        self.status = ConnectionStatus::Connecting;
        match self.run_cli_pipeline(&["get system status"]).await {
            Ok(_) => {
                self.status = ConnectionStatus::Connected;
                Ok(())
            }
            Err(e) => {
                self.status = ConnectionStatus::Error(e.to_string());
                Err(e)
            }
        }
    }

    // ── disconnect ────────────────────────────────────────────────────────────

    pub async fn disconnect(&mut self) -> Result<()> {
        self.status = ConnectionStatus::Disconnected;
        Ok(())
    }

    // ── refresh ───────────────────────────────────────────────────────────────

    pub async fn refresh(&mut self) -> Result<BgpSummary> {
        let raw = self
            .run_cli_pipeline(&["get router info bgp summary"])
            .await?;

        if !raw.contains("BGP router identifier") {
            bail!(
                "Unexpected output from 'get router info bgp summary':\n{}",
                &raw[..raw.len().min(200)]
            );
        }

        let mut summary = parse_bgp_summary(&raw);
        self.status = ConnectionStatus::Connected;

        let mut detail_map = {
            let mut map = HashMap::new();
            if let Ok(out) = self
                .run_cli_pipeline(&["get router info bgp neighbors"])
                .await
            {
                if out.contains("BGP neighbor is") {
                    map = parse_all_neighbor_details(&out);
                }
            }
            map
        };

        for peer in &mut summary.peers {
            if let Some(d) = detail_map.remove(&peer.neighbor_ip) {
                peer.description = d.description;
                peer.route_map_in = d.route_map_in;
                peer.route_map_out = d.route_map_out;
                peer.next_hop_self = d.next_hop_self;
                peer.route_reflector_client = d.route_reflector_client;
                peer.update_source = d.update_source;
                peer.password_configured = d.password_configured;
                if d.hold_time > 0 {
                    peer.hold_time = d.hold_time;
                }
                if d.keepalive > 0 {
                    peer.keepalive = d.keepalive;
                }
            }
        }

        Ok(summary)
    }

    // ── get_routes ────────────────────────────────────────────────────────────

    pub async fn get_routes(&mut self) -> Result<Vec<BgpRoute>> {
        let raw = self
            .run_cli_pipeline(&["get router info bgp network"])
            .await?;
        Ok(parse_bgp_table(&raw))
    }

    // ── get_peer_routes ───────────────────────────────────────────────────────

    pub async fn get_peer_routes(
        &self,
        ip: IpAddr,
        dir: crate::bgp::PeerRouteDirection,
    ) -> Result<Vec<BgpRoute>> {
        use crate::bgp::PeerRouteDirection;
        let cmd_str = match dir {
            PeerRouteDirection::Received => {
                format!("get router info bgp neighbors {ip} received-routes")
            }
            PeerRouteDirection::Advertised => {
                format!("get router info bgp neighbors {ip} advertised-routes")
            }
        };
        let raw = self.run_cli_pipeline(&[cmd_str.as_str()]).await?;
        Ok(parse_bgp_table(&raw))
    }

    // ── ping_mtu ─────────────────────────────────────────────────────────────

    pub async fn ping_mtu(&self, target: IpAddr) -> Result<u16> {
        for payload in [1472u16, 1402, 548] {
            let size_str = payload.to_string();
            let target_str = target.to_string();
            let cmds = [
                "execute ping-options repeat-count 3",
                &format!("execute ping-options data-size {}", size_str),
                "execute ping-options df-bit yes",
                &format!("execute ping {}", target_str),
            ];
            let out = self.run_cli_pipeline(&cmds).await.unwrap_or_default();
            if out.contains("min/avg/max") || out.contains(" 0% loss") {
                return Ok(payload + 28);
            }
        }
        Ok(0)
    }

    // ── fetch_route_map_detail ────────────────────────────────────────────────

    pub async fn fetch_route_map_detail(
        &self,
        rm_name: &str,
    ) -> Result<crate::bgp::RouteMapDetail> {
        use crate::bgp::{PrefixListEntry, RouteMapDetail};

        let cmd = format!("get router info routepolicy {rm_name}");
        let raw = self.run_cli_pipeline(&[cmd.as_str()]).await?;
        let entries = if raw.contains("route-map") {
            parse_route_map_entries(&raw)
        } else {
            vec![]
        };

        let mut plist_names: Vec<String> = vec![];
        let mut clist_names: Vec<String> = vec![];
        for entry in &entries {
            for clause in &entry.match_clauses {
                if clause.contains("prefix-list") {
                    let part = clause.split_once(':').map(|x| x.1).unwrap_or("").trim();
                    for name in part.split_whitespace() {
                        plist_names.push(name.to_string());
                    }
                }
                if clause.starts_with("community") && clause.contains(':') {
                    let part = clause.split_once(':').map(|x| x.1).unwrap_or("").trim();
                    for name in part.split_whitespace() {
                        clist_names.push(name.to_string());
                    }
                }
            }
        }

        let plist_futs: Vec<_> = plist_names
            .iter()
            .map(|name| {
                let cmd2 = format!("get router info prefix-list {name}");
                let name = name.clone();
                async move { (name, self.run_cli_pipeline(&[cmd2.as_str()]).await) }
            })
            .collect();

        let clist_futs: Vec<_> = clist_names
            .iter()
            .map(|name| {
                let cmd3 = format!("get router info bgp community-list {name}");
                let name = name.clone();
                async move { (name, self.run_cli_pipeline(&[cmd3.as_str()]).await) }
            })
            .collect();

        let (plist_results, clist_results) = futures::future::join(
            futures::future::join_all(plist_futs),
            futures::future::join_all(clist_futs),
        )
        .await;

        let mut prefix_lists: HashMap<String, Vec<PrefixListEntry>> = HashMap::new();
        for (name, result) in plist_results {
            if let Ok(pl_raw) = result {
                prefix_lists.insert(name, parse_prefix_list_entries(&pl_raw));
            }
        }
        let mut community_lists: HashMap<String, Vec<String>> = HashMap::new();
        for (name, result) in clist_results {
            if let Ok(cl_raw) = result {
                community_lists.insert(name, parse_community_list_entries(&cl_raw));
            }
        }

        Ok(RouteMapDetail {
            name: rm_name.to_string(),
            entries,
            prefix_lists,
            community_lists,
        })
    }
}

// ─── Output cleanup ───────────────────────────────────────────────────────────

fn strip_fortigate_noise(raw: &str) -> String {
    raw.lines()
        .map(strip_ansi)
        .filter(|line| {
            let t = line.trim();
            if t.is_empty() {
                return false;
            }
            if t.ends_with(" #") || t.ends_with("# ") {
                return false;
            }
            if !t.starts_with(' ') && !t.starts_with('\t') && t.contains(" # ") {
                return false;
            }
            if t.starts_with("Welcome") || t.starts_with("FortiGate") || t.starts_with("FG") {
                return false;
            }
            true
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn strip_ansi(line: &str) -> String {
    let mut result = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for nc in chars.by_ref() {
                if nc.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}
