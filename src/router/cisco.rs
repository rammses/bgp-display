// Cisco IOS / IOS-XE / FRRouting SSH backend.
//
// SSH transport is delegated to the shared SshSessionManager.
// This module retains all vendor-specific command construction and parsing.

#![allow(dead_code)]

use crate::{
    bgp::{parse_bgp_summary, BgpRoute, BgpSummary},
    router::{ConnectionStatus, RouterConfig},
    ssh::SshSessionManager,
};
pub(crate) use crate::router::cisco_parsers::{
    parse_all_neighbor_details, parse_bgp_table, parse_community_list_entries,
    parse_neighbor_detail, parse_prefix_list_entries, parse_route_map_entries, NeighborDetail,
};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

pub struct PolicyStanza {
    pub text: String,
    pub prefix_lists: HashMap<String, Vec<crate::bgp::PrefixListEntry>>,
    pub community_lists: HashMap<String, Vec<crate::bgp::CommunityListEntry>>,
}

pub struct CiscoBackend {
    config: RouterConfig,
    ssh: Arc<SshSessionManager>,
    status: ConnectionStatus,
}

impl CiscoBackend {
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

    async fn ssh_run(&self, cmd: &str) -> Result<String> {
        self.ssh.run_cmd(self.config.id, cmd).await
    }

    async fn ssh_run_or_vtysh(&self, cmd: &str, marker: &str) -> Result<String> {
        let raw = self.ssh_run(cmd).await?;
        if raw.contains(marker) {
            return Ok(raw);
        }
        let vtysh_cmd = format!("vtysh -c '{cmd}'");
        self.ssh_run(&vtysh_cmd).await
    }

    // ── connect ───────────────────────────────────────────────────────────────

    pub async fn connect(&mut self) -> Result<()> {
        self.status = ConnectionStatus::Connecting;
        match self.ssh_run("echo ok").await {
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
            .ssh_run_or_vtysh("show ip bgp summary", "BGP router identifier")
            .await?;

        if !raw.contains("BGP router identifier") {
            bail!(
                "Unexpected output from show ip bgp summary:\n{}",
                &raw[..raw.len().min(200)]
            );
        }

        let mut summary = parse_bgp_summary(&raw);
        self.status = ConnectionStatus::Connected;

        let mut detail_map = {
            let cmds = [
                ("show ip bgp neighbors", "BGP neighbor is"),
                ("show bgp neighbors", "BGP neighbor is"),
            ];
            let mut map = HashMap::new();
            'outer: for (cmd, marker) in &cmds {
                if let Ok(raw) = self.ssh_run_or_vtysh(cmd, marker).await {
                    if raw.contains(marker) {
                        map = parse_all_neighbor_details(&raw);
                        break 'outer;
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
                peer.reset_count = d.reset_count;
                peer.last_reset_reason = d.last_reset_reason;
                peer.notifs_sent = d.notifs_sent;
                peer.notifs_rcvd = d.notifs_rcvd;
                if d.bfd_state.is_some() {
                    peer.bfd_state = d.bfd_state;
                }
            }
        }

        Ok(summary)
    }

    // ── get_routes ────────────────────────────────────────────────────────────

    pub async fn get_routes(&mut self) -> Result<Vec<BgpRoute>> {
        let raw = self
            .ssh_run_or_vtysh("show ip bgp", "BGP table version")
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
        let cmd = match dir {
            PeerRouteDirection::Received => format!("show ip bgp neighbors {ip} routes"),
            PeerRouteDirection::Advertised => {
                format!("show ip bgp neighbors {ip} advertised-routes")
            }
        };
        let raw = self.ssh_run_or_vtysh(&cmd, "Network").await?;
        Ok(parse_bgp_table(&raw))
    }

    // ── fetch_neighbor_detail ─────────────────────────────────────────────────

    async fn fetch_neighbor_detail(&self, ip: IpAddr) -> Result<NeighborDetail> {
        let cmd = format!("show ip bgp neighbors {ip}");
        let raw = self.ssh_run_or_vtysh(&cmd, "BGP neighbor is").await?;
        Ok(parse_neighbor_detail(&raw))
    }

    // ── ping_mtu ─────────────────────────────────────────────────────────────

    pub async fn ping_mtu(&self, target: IpAddr) -> Result<u16> {
        for payload in [1472u16, 1402, 548] {
            let cmd = format!("ping {} repeat 3 df-bit size {}", target, payload);
            let out = self.ssh_run(&cmd).await.unwrap_or_default();
            if out.contains('!') {
                return Ok(payload + 28);
            }
        }
        Ok(0)
    }

    // ── write_config ─────────────────────────────────────────────────────────

    pub async fn write_config(&self, commands: &[String]) -> Result<()> {
        let mut stdin = String::from("configure terminal\n");
        for cmd in commands {
            stdin.push_str(cmd);
            stdin.push('\n');
        }
        stdin.push_str("end\nwrite memory\nexit\n");

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

    pub async fn apply_config(&mut self, _config: &str) -> Result<()> {
        bail!("apply_config not yet implemented for system-SSH backend");
    }

    // ── fetch_route_map_detail ────────────────────────────────────────────────

    pub async fn fetch_route_map_detail(
        &self,
        rm_name: &str,
    ) -> Result<crate::bgp::RouteMapDetail> {
        use crate::bgp::{PrefixListEntry, RouteMapDetail};
        use std::collections::HashMap;

        let cmd = format!("show route-map {rm_name}");
        let raw = self.ssh_run_or_vtysh(&cmd, "route-map").await?;
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
                    let result = self.ssh_run_or_vtysh(&cmd2, "prefix-list").await;
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
                    let result = self.ssh_run_or_vtysh(&cmd3, "community-list").await;
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

    // ── render_bgp_stanza ─────────────────────────────────────────────────────

    pub fn render_bgp_stanza(summary: &BgpSummary) -> String {
        let mut lines = vec![format!("router bgp {}", summary.local_as)];
        lines.push(format!(" bgp router-id {}", summary.router_id));
        lines.push(" bgp log-neighbor-changes".into());

        for peer in &summary.peers {
            lines.push(format!(
                " neighbor {} remote-as {}",
                peer.neighbor_ip, peer.remote_as
            ));
            if let Some(desc) = &peer.description {
                lines.push(format!(
                    " neighbor {} description {}",
                    peer.neighbor_ip, desc
                ));
            }
            if peer.next_hop_self {
                lines.push(format!(" neighbor {} next-hop-self", peer.neighbor_ip));
            }
            if let Some(src) = peer.update_source {
                lines.push(format!(
                    " neighbor {} update-source {}",
                    peer.neighbor_ip, src
                ));
            }
            if peer.password_configured {
                lines.push(format!(
                    " neighbor {} password <configured>",
                    peer.neighbor_ip
                ));
            }
            if let Some(rm) = &peer.route_map_in {
                lines.push(format!(
                    " neighbor {} route-map {} in",
                    peer.neighbor_ip, rm
                ));
            }
            if let Some(rm) = &peer.route_map_out {
                lines.push(format!(
                    " neighbor {} route-map {} out",
                    peer.neighbor_ip, rm
                ));
            }
        }
        lines.push("!".into());
        lines.join("\n")
    }

    // ── fetch_policy_stanza ──────────────────────────────────────────────────
    // Fetches prefix-lists and community-lists from the router and returns
    // both the rendered text for config_lines AND structured parsed data
    // for the prefix_list_cache / community_list_cache.

    pub async fn fetch_policy_stanza(&self) -> PolicyStanza {
        let mut text = String::new();
        let mut prefix_lists: HashMap<String, Vec<crate::bgp::PrefixListEntry>> = HashMap::new();
        let mut community_lists: HashMap<String, Vec<crate::bgp::CommunityListEntry>> =
            HashMap::new();

        if let Ok(raw) = self
            .ssh_run_or_vtysh("show ip prefix-list", "prefix-list")
            .await
        {
            let mut name_blocks: Vec<(String, String)> = vec![];
            let mut seen_names = std::collections::HashSet::new();
            for line in raw.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("ip prefix-list") {
                    let name = trimmed
                        .strip_prefix("ip prefix-list ")
                        .and_then(|s| s.split_whitespace().next())
                        .map(|n| n.trim_end_matches(':').to_string());
                    if let Some(name) = name {
                        if seen_names.insert(name.clone()) {
                            if !text.is_empty() {
                                text.push_str("!\n");
                            }
                            name_blocks.push((name, String::new()));
                        }
                    }
                    text.push(' ');
                    text.push_str(trimmed);
                    text.push('\n');
                    if let Some((_, block)) = name_blocks.last_mut() {
                        block.push_str(trimmed);
                        block.push('\n');
                    }
                } else if trimmed.starts_with("seq ") || trimmed.contains(" seq ") {
                    if let Some((_, block)) = name_blocks.last_mut() {
                        block.push_str(trimmed);
                        block.push('\n');
                    }
                }
            }
            for (name, block) in name_blocks {
                let entries = parse_prefix_list_entries(&block);
                if !entries.is_empty() {
                    prefix_lists.insert(name, entries);
                }
            }
        }

        if !text.is_empty() {
            text.push_str("!\n");
        }

        if let Ok(raw) = self
            .ssh_run_or_vtysh("show ip community-list", "community-list")
            .await
        {
            let mut cl_seq: u32 = 0;
            for line in raw.lines() {
                let t = line.trim();
                if t.is_empty()
                    || t.starts_with("Named Community")
                    || t.starts_with("ip community-list")
                {
                    continue;
                }
                if t.contains("permit") || t.contains("deny") {
                    cl_seq += 10;
                    let parts: Vec<&str> = t.splitn(2, char::is_whitespace).collect();
                    let (action, community) = if parts.len() == 2 {
                        (parts[0].to_string(), parts[1].trim().to_string())
                    } else {
                        ("permit".to_string(), t.to_string())
                    };
                    text.push_str(" ip community-list ");
                    text.push_str(t);
                    text.push('\n');
                    community_lists
                        .entry("default".to_string())
                        .or_default()
                        .push(crate::bgp::CommunityListEntry {
                            seq: cl_seq,
                            action,
                            community,
                        });
                }
            }
        }

        PolicyStanza {
            text,
            prefix_lists,
            community_lists,
        }
    }
}
