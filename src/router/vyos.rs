// VyOS 1.5 (Circinus) SSH backend.
//
// VyOS 1.5 runs FRRouting (FRR 10.x).  SSH gives a restricted VyOS shell
// (`/bin/vbash`).  All FRR commands are issued via `vtysh -c '...'` which
// works for users in the `frrvty` group (the default `vyos` user qualifies).
//
// FRR command differences vs Cisco IOS style:
//   Cisco/IOS                  FRR/VyOS
//   show ip bgp summary    →   show bgp summary
//   show ip bgp            →   show bgp
//   show ip bgp neighbors  →   show bgp neighbors
//   show ip prefix-list    →   show bgp prefix-list  (also accepts show ip …)
//   show route-map         →   show route-map        (same)
//   show ip community-list →   show bgp community-list (also accepts show ip …)
//
// The output format is identical to FRR – the same parsers from cisco.rs are
// reused directly (they already handle FRR output).

#![allow(dead_code)]

use crate::{
    bgp::{parse_bgp_summary, BgpRoute, BgpSummary},
    router::{ConnectionStatus, RouterConfig},
    router::cisco::{
        parse_bgp_table, parse_neighbor_detail, parse_prefix_list_entries,
        parse_route_map_entries, parse_community_list_entries,
    },
};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio::process::Command;

pub struct VyOsBackend {
    pub hostname:  String,
    pub port:      u16,
    pub username:  String,
    pub password:  Option<String>,
    pub router_id: IpAddr,
    pub local_as:  u32,
    status:        ConnectionStatus,
}

impl VyOsBackend {
    pub fn new(cfg: &RouterConfig) -> Self {
        Self {
            hostname:  cfg.hostname.clone(),
            port:      cfg.ssh_port,
            username:  cfg.username.clone(),
            password:  cfg.password.clone(),
            router_id: cfg.router_id.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            local_as:  cfg.local_as.unwrap_or(0),
            status:    ConnectionStatus::Disconnected,
        }
    }

    pub fn status(&self) -> &ConnectionStatus {
        &self.status
    }

    // ── Raw SSH helper ────────────────────────────────────────────────────────
    //
    // Runs:  ssh [opts] user@host "<shell_cmd>"
    // The caller is responsible for wrapping daemons commands in vtysh_run().

    async fn raw_ssh_run(&self, shell_cmd: &str) -> Result<String> {
        let target = format!("{}@{}", self.username, self.hostname);
        let output = tokio::time::timeout(
            Duration::from_secs(15),
            Command::new("ssh")
                .args([
                    "-p", &self.port.to_string(),
                    "-o", "ConnectTimeout=5",
                    "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "LogLevel=ERROR",
                    &target,
                    shell_cmd,
                ])
                .output(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("SSH timed out connecting to {}", self.hostname))??;

        if !output.status.success() && output.stdout.is_empty() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            bail!("SSH error: {}", err.trim());
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    // ── vtysh helper ──────────────────────────────────────────────────────────
    //
    // Wraps an FRR operational command in `vtysh -c '...'`.
    // Single-quotes inside the command are escaped as '\'' (shell quoting trick).

    async fn vtysh_run(&self, frr_cmd: &str) -> Result<String> {
        let escaped = frr_cmd.replace('\'', "'\\''");
        let shell_cmd = format!("vtysh -c '{escaped}'");
        self.raw_ssh_run(&shell_cmd).await
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
    //
    // VyOS FRR produces `show bgp summary` output with the same FRR format
    // that parse_bgp_summary() already handles.

    pub async fn refresh(&mut self) -> Result<BgpSummary> {
        // Try progressively broader FRR commands until one succeeds
        let raw = {
            let r1 = self.vtysh_run("show bgp ipv4 unicast summary").await;
            if r1.as_ref().is_ok_and(|s| s.contains("BGP router identifier")) {
                r1?
            } else {
                let r2 = self.vtysh_run("show bgp summary").await;
                if r2.as_ref().is_ok_and(|s| s.contains("BGP router identifier")) {
                    r2?
                } else {
                    self.vtysh_run("show ip bgp summary").await?
                }
            }
        };

        if !raw.contains("BGP router identifier") {
            bail!("Unexpected output from show bgp summary:\n{}", &raw[..raw.len().min(200)]);
        }

        let mut summary = parse_bgp_summary(&raw);
        self.router_id = summary.router_id;
        self.local_as  = summary.local_as;
        self.status    = ConnectionStatus::Connected;

        // Fetch per-neighbour detail (description, route-maps)
        let ips: Vec<IpAddr> = summary.peers.iter().map(|p| p.neighbor_ip).collect();
        let mut detail_map = HashMap::new();
        for ip in &ips {
            if let Ok(detail) = self.fetch_neighbor_detail(*ip).await {
                detail_map.insert(*ip, detail);
            }
        }

        for peer in &mut summary.peers {
            if let Some(d) = detail_map.remove(&peer.neighbor_ip) {
                peer.description          = d.description;
                peer.route_map_in         = d.route_map_in;
                peer.route_map_out        = d.route_map_out;
                peer.next_hop_self        = d.next_hop_self;
                peer.route_reflector_client = d.route_reflector_client;
                peer.update_source        = d.update_source;
                peer.password_configured  = d.password_configured;
                if d.hold_time > 0 { peer.hold_time = d.hold_time; }
                if d.keepalive  > 0 { peer.keepalive  = d.keepalive;  }
            }
        }

        Ok(summary)
    }

    // ── get_routes ────────────────────────────────────────────────────────────

    pub async fn get_routes(&mut self) -> Result<Vec<BgpRoute>> {
        let raw = {
            let r1 = self.vtysh_run("show bgp ipv4 unicast").await;
            if r1.as_ref().is_ok_and(|s| s.contains("BGP table version") || s.contains("Status codes")) {
                r1?
            } else {
                let r2 = self.vtysh_run("show bgp").await;
                if r2.as_ref().is_ok_and(|s| s.contains("BGP table version") || s.contains("Status codes")) {
                    r2?
                } else {
                    self.vtysh_run("show ip bgp").await?
                }
            }
        };
        Ok(parse_bgp_table(&raw))
    }

    // ── fetch_neighbor_detail ─────────────────────────────────────────────────

    async fn fetch_neighbor_detail(&self, ip: IpAddr) -> Result<crate::router::cisco::NeighborDetail> {
        let cmd = format!("show bgp neighbors {ip}");
        let r1 = self.vtysh_run(&cmd).await;
        let raw = if r1.as_ref().is_ok_and(|s| s.contains("BGP neighbor is")) {
            r1?
        } else {
            let cmd2 = format!("show ip bgp neighbors {ip}");
            self.vtysh_run(&cmd2).await?
        };
        Ok(parse_neighbor_detail(&raw))
    }

    // ── apply_config ──────────────────────────────────────────────────────────

    pub async fn apply_config(&mut self, _config: &str) -> anyhow::Result<()> {
        bail!("apply_config not yet implemented for VyOS backend");
    }

    // ── fetch_route_map_detail ────────────────────────────────────────────────

    pub async fn fetch_route_map_detail(&self, rm_name: &str) -> Result<crate::bgp::RouteMapDetail> {
        use crate::bgp::{PrefixListEntry, RouteMapDetail};

        let cmd = format!("show route-map {rm_name}");
        let raw = self.vtysh_run(&cmd).await?;
        let entries = parse_route_map_entries(&raw);

        let mut plist_names: Vec<String> = vec![];
        let mut clist_names: Vec<String> = vec![];
        for entry in &entries {
            for clause in &entry.match_clauses {
                if clause.contains("prefix-list") {
                    let part = clause.splitn(2, ':').nth(1).unwrap_or("").trim();
                    for name in part.split_whitespace() { plist_names.push(name.to_string()); }
                }
                if clause.starts_with("community") && clause.contains(':') {
                    let part = clause.splitn(2, ':').nth(1).unwrap_or("").trim();
                    for name in part.split_whitespace() { clist_names.push(name.to_string()); }
                }
            }
        }

        let mut prefix_lists: HashMap<String, Vec<PrefixListEntry>> = HashMap::new();
        for name in &plist_names {
            // VyOS FRR: `show bgp prefix-list <name>` OR `show ip prefix-list <name>`
            let cmd2 = format!("show ip prefix-list {name}");
            if let Ok(pl_raw) = self.vtysh_run(&cmd2).await {
                prefix_lists.insert(name.clone(), parse_prefix_list_entries(&pl_raw));
            }
        }

        let mut community_lists: HashMap<String, Vec<String>> = HashMap::new();
        for name in &clist_names {
            let cmd3 = format!("show ip community-list {name}");
            if let Ok(cl_raw) = self.vtysh_run(&cmd3).await {
                community_lists.insert(name.clone(), parse_community_list_entries(&cl_raw));
            }
        }

        Ok(RouteMapDetail { name: rm_name.to_string(), entries, prefix_lists, community_lists })
    }
}
