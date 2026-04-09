// A10 Networks ADC (ACOS) SSH backend.
//
// SSH transport is delegated to the shared SshSessionManager.
// ACOS does NOT support non-interactive SSH (commands passed as arguments
// produce no output). All commands go through piped stdin via run_piped().
// ACOS BGP summary uses a unique "State/PfxRcd/PfxSent" column format
// with slash-separated values, so a dedicated parser is needed.

#![allow(dead_code)]

use crate::{
    bgp::{parse_a10_bgp_summary, BgpRoute, BgpSummary},
    router::cisco::{
        parse_all_neighbor_details, parse_bgp_table, parse_community_list_entries,
        parse_prefix_list_entries, parse_route_map_entries,
    },
    router::{ConnectionStatus, RouterConfig},
    ssh::SshSessionManager,
};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

pub struct A10Backend {
    config: RouterConfig,
    ssh: Arc<SshSessionManager>,
    status: ConnectionStatus,
}

impl A10Backend {
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

    // ── SSH helper ──────────────────────────────────────────────────────────
    // ACOS ignores commands passed as SSH arguments — must pipe via stdin.

    async fn run_cli(&self, cmd: &str) -> Result<String> {
        let script = format!("{cmd}\nexit\n");
        let raw = self.ssh.run_piped(self.config.id, &script).await?;
        Ok(strip_a10_noise(&raw))
    }

    // ── connect ─────────────────────────────────────────────────────────────

    pub async fn connect(&mut self) -> Result<()> {
        self.status = ConnectionStatus::Connecting;
        match self.run_cli("show version").await {
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

    // ── disconnect ──────────────────────────────────────────────────────────

    pub async fn disconnect(&mut self) -> Result<()> {
        self.status = ConnectionStatus::Disconnected;
        Ok(())
    }

    // ── refresh ─────────────────────────────────────────────────────────────

    pub async fn refresh(&mut self) -> Result<BgpSummary> {
        let raw = self.run_cli("show ip bgp summary").await?;

        if !raw.contains("BGP router identifier") {
            bail!(
                "Unexpected output from 'show ip bgp summary':\n{}",
                &raw[..raw.len().min(200)]
            );
        }

        let mut summary = parse_a10_bgp_summary(&raw);
        self.status = ConnectionStatus::Connected;

        let mut detail_map = {
            let mut map = HashMap::new();
            if let Ok(out) = self.run_cli("show ip bgp neighbors").await {
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

    // ── get_routes ──────────────────────────────────────────────────────────

    pub async fn get_routes(&mut self) -> Result<Vec<BgpRoute>> {
        let raw = self.run_cli("show ip bgp").await?;
        Ok(parse_bgp_table(&raw))
    }

    // ── get_peer_routes ─────────────────────────────────────────────────────

    pub async fn get_peer_routes(
        &self,
        ip: IpAddr,
        dir: crate::bgp::PeerRouteDirection,
    ) -> Result<Vec<BgpRoute>> {
        use crate::bgp::PeerRouteDirection;
        let cmd = match dir {
            PeerRouteDirection::Received => {
                format!("show ip bgp neighbors {ip} received-routes")
            }
            PeerRouteDirection::Advertised => {
                format!("show ip bgp neighbors {ip} advertised-routes")
            }
        };
        let raw = self.run_cli(&cmd).await?;
        Ok(parse_bgp_table(&raw))
    }

    // ── ping_mtu ────────────────────────────────────────────────────────────

    pub async fn ping_mtu(&self, target: IpAddr) -> Result<u16> {
        for payload in [1472u16, 1402, 548] {
            let cmd = format!("ping {target} size {payload} df-bit repeat 3");
            let out = self.run_cli(&cmd).await.unwrap_or_default();
            if out.contains("!") && !out.contains("....") {
                return Ok(payload + 28);
            }
        }
        Ok(0)
    }

    // ── write_config ────────────────────────────────────────────────────────

    pub async fn write_config(&self, commands: &[String]) -> Result<()> {
        let mut script = String::from("configure\n");
        for cmd in commands {
            script.push_str(cmd);
            script.push('\n');
        }
        script.push_str("end\nwrite memory\nexit\n");

        let raw = self
            .ssh
            .run_piped(self.config.id, &script)
            .await
            .context("write_config: A10 CLI pipe failed")?;
        let out = strip_a10_noise(&raw);

        if out.contains("% Invalid") || out.contains("% Unknown command") {
            bail!("Router rejected config: {}", &out[..out.len().min(300)]);
        }
        Ok(())
    }

    pub async fn apply_config(&mut self, _config: &str) -> Result<()> {
        bail!("apply_config not yet implemented for A10 backend");
    }

    // ── fetch_route_map_detail ──────────────────────────────────────────────

    pub async fn fetch_route_map_detail(
        &self,
        rm_name: &str,
    ) -> Result<crate::bgp::RouteMapDetail> {
        use crate::bgp::{PrefixListEntry, RouteMapDetail};

        let cmd = format!("show route-map {rm_name}");
        let raw = self.run_cli(&cmd).await?;
        let entries = parse_route_map_entries(&raw);

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
                let cmd2 = format!("show ip prefix-list {name}");
                let name = name.clone();
                async move { (name, self.run_cli(&cmd2).await) }
            })
            .collect();

        let clist_futs: Vec<_> = clist_names
            .iter()
            .map(|name| {
                let cmd3 = format!("show ip community-list {name}");
                let name = name.clone();
                async move { (name, self.run_cli(&cmd3).await) }
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

fn strip_a10_noise(raw: &str) -> String {
    raw.lines()
        .filter(|line| {
            let t = line.trim();
            if t.is_empty() {
                return false;
            }
            // Filter ACOS prompts: "hostname#", "hostname(config)#", "hostname>"
            if t.ends_with('#') && t.len() < 80 {
                return false;
            }
            if t.ends_with('>') && !t.contains(' ') && t.len() < 60 {
                return false;
            }
            // Filter echoed commands from piped stdin
            if t.starts_with("show ")
                || t == "exit"
                || t == "configure"
                || t == "end"
                || t == "write memory"
            {
                return false;
            }
            if t.starts_with("Last login:") || t.starts_with("Welcome to") {
                return false;
            }
            true
        })
        .collect::<Vec<_>>()
        .join("\n")
}
