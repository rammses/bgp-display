// VyOS 1.5 (Circinus) SSH backend.
//
// SSH transport is delegated to the shared SshSessionManager.
// VyOS runs FRRouting — all commands go through `vtysh -c '...'`.
// Output parsed by cisco.rs parsers (FRR-compatible format).

#![allow(dead_code)]

use crate::{
    bgp::{parse_bgp_summary, BgpRoute, BgpSummary},
    router::cisco::{
        parse_all_neighbor_details, parse_bgp_table, parse_community_list_entries,
        parse_neighbor_detail, parse_prefix_list_entries, parse_route_map_entries,
    },
    router::{ConnectionStatus, RouterConfig},
    ssh::SshSessionManager,
};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

pub struct VyOsBackend {
    config: RouterConfig,
    ssh: Arc<SshSessionManager>,
    status: ConnectionStatus,
}

impl VyOsBackend {
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

    // ── SSH helpers (delegated to session manager) ────────────────────────────

    async fn raw_ssh_run(&self, shell_cmd: &str) -> Result<String> {
        self.ssh.run_cmd(self.config.id, shell_cmd).await
    }

    async fn vtysh_run(&self, frr_cmd: &str) -> Result<String> {
        let escaped = frr_cmd.replace('\'', "'\\''");
        let shell_cmd = format!("vtysh -c '{escaped}'");
        self.ssh.run_cmd(self.config.id, &shell_cmd).await
    }

    // ── connect ───────────────────────────────────────────────────────────────

    pub async fn connect(&mut self) -> Result<()> {
        self.status = ConnectionStatus::Connecting;
        match self.raw_ssh_run("echo ok").await {
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
        let cmds = [
            "show ip bgp summary",
            "show bgp ipv4 unicast summary",
            "show bgp summary",
        ];

        let mut raw = String::new();
        let mut last_err = String::new();
        for cmd in &cmds {
            match self.vtysh_run(cmd).await {
                Ok(out) if out.contains("BGP router identifier") => {
                    raw = out;
                    break;
                }
                Ok(out) => {
                    last_err = format!(
                        "'{cmd}' did not contain BGP header (got {} bytes)",
                        out.len()
                    );
                }
                Err(e) => {
                    last_err = format!("'{cmd}' failed: {e}");
                }
            }
        }

        if raw.is_empty() {
            match self.raw_ssh_run("show ip bgp summary").await {
                Ok(out) if out.contains("BGP router identifier") => {
                    raw = out;
                }
                Ok(_) => {}
                Err(_) => {}
            }
        }

        if raw.is_empty() {
            bail!(
                "Could not retrieve BGP summary from {}: {last_err}",
                self.config.hostname
            );
        }

        let mut summary = parse_bgp_summary(&raw);
        self.status = ConnectionStatus::Connected;

        let mut detail_map = {
            let cmds = ["show ip bgp neighbors", "show bgp neighbors"];
            let mut map = std::collections::HashMap::new();
            'outer: for cmd in &cmds {
                if let Ok(out) = self.vtysh_run(cmd).await {
                    if out.contains("BGP neighbor is") {
                        map = parse_all_neighbor_details(&out);
                        break 'outer;
                    }
                }
            }
            if map.is_empty() {
                if let Ok(out) = self.raw_ssh_run("show ip bgp neighbors").await {
                    if out.contains("BGP neighbor is") {
                        map = parse_all_neighbor_details(&out);
                    }
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
        let cmds = ["show ip bgp", "show bgp ipv4 unicast", "show bgp"];

        for cmd in &cmds {
            if let Ok(out) = self.vtysh_run(cmd).await {
                if out.contains("BGP table version") || out.contains("Status codes") {
                    return Ok(parse_bgp_table(&out));
                }
            }
        }
        if let Ok(out) = self.raw_ssh_run("show ip bgp").await {
            if out.contains("BGP table version") || out.contains("Status codes") {
                return Ok(parse_bgp_table(&out));
            }
        }
        Ok(vec![])
    }

    // ── get_peer_routes ───────────────────────────────────────────────────────

    pub async fn get_peer_routes(
        &self,
        ip: IpAddr,
        dir: crate::bgp::PeerRouteDirection,
    ) -> Result<Vec<BgpRoute>> {
        use crate::bgp::PeerRouteDirection;
        let cmd = match dir {
            PeerRouteDirection::Received => format!("show bgp neighbors {ip} routes"),
            PeerRouteDirection::Advertised => format!("show bgp neighbors {ip} advertised-routes"),
        };
        let raw = self.vtysh_run(&cmd).await?;
        Ok(parse_bgp_table(&raw))
    }

    // ── fetch_neighbor_detail ─────────────────────────────────────────────────

    async fn fetch_neighbor_detail(
        &self,
        ip: IpAddr,
    ) -> Result<crate::router::cisco::NeighborDetail> {
        let cmds = [
            format!("show ip bgp neighbors {ip}"),
            format!("show bgp neighbors {ip}"),
        ];
        for cmd in &cmds {
            if let Ok(out) = self.vtysh_run(cmd).await {
                if out.contains("BGP neighbor is") {
                    return Ok(parse_neighbor_detail(&out));
                }
            }
        }
        if let Ok(out) = self
            .raw_ssh_run(&format!("show ip bgp neighbors {ip}"))
            .await
        {
            if out.contains("BGP neighbor is") {
                return Ok(parse_neighbor_detail(&out));
            }
        }
        bail!("could not fetch neighbor detail for {ip}")
    }

    // ── ping_mtu ─────────────────────────────────────────────────────────────

    pub async fn ping_mtu(&self, target: IpAddr) -> Result<u16> {
        for payload in [1472u16, 1402, 548] {
            let cmd = format!("ping -c 3 -M do -s {} {}", payload, target);
            let out = self.raw_ssh_run(&cmd).await.unwrap_or_default();
            if out.contains(" 0% packet loss") || out.contains("bytes from") {
                return Ok(payload + 28);
            }
        }
        Ok(0)
    }

    // ── write_config ─────────────────────────────────────────────────────────

    pub async fn write_config(&self, commands: &[String]) -> Result<()> {
        let mut stdin = String::from("configure\n");
        for cmd in commands {
            stdin.push_str(cmd);
            stdin.push('\n');
        }
        stdin.push_str("commit\nsave\nexit\nexit\n");

        let vtysh_stdin = format!("vtysh\n{stdin}");
        let out = self
            .ssh
            .run_piped(self.config.id, &vtysh_stdin)
            .await
            .context("write_config: SSH pipe to vtysh failed")?;

        if out.contains("% Invalid") || out.contains("% Unknown command") {
            bail!("Router rejected config: {}", &out[..out.len().min(300)]);
        }
        Ok(())
    }

    pub async fn apply_config(&mut self, _config: &str) -> anyhow::Result<()> {
        bail!("apply_config not yet implemented for VyOS backend");
    }

    // ── fetch_route_map_detail ────────────────────────────────────────────────

    pub async fn fetch_route_map_detail(
        &self,
        rm_name: &str,
    ) -> Result<crate::bgp::RouteMapDetail> {
        use crate::bgp::{PrefixListEntry, RouteMapDetail};

        let cmd = format!("show route-map {rm_name}");
        let raw = self.vtysh_run(&cmd).await?;
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
                async move {
                    let result = self.vtysh_run(&cmd2).await;
                    (name, result)
                }
            })
            .collect();

        let clist_futs: Vec<_> = clist_names
            .iter()
            .map(|name| {
                let cmd3 = format!("show ip community-list {name}");
                let name = name.clone();
                async move {
                    let result = self.vtysh_run(&cmd3).await;
                    (name, result)
                }
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
