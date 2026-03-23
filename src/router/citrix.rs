// Citrix ADC / VPX SSH backend.
//
// SSH transport is delegated to the shared SshSessionManager.
// Citrix ADC NS14.x runs FRRouting — `vtysh -c` is NOT supported,
// so interactive pipe patterns are used via run_shell_pipe().
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

pub struct CitrixVpxBackend {
    config: RouterConfig,
    ssh: Arc<SshSessionManager>,
    status: ConnectionStatus,
}

impl CitrixVpxBackend {
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

    fn ssh_cmd_str(&self) -> String {
        SshSessionManager::build_ssh_cmd_str(&self.config)
    }

    async fn raw_ssh_run(&self, shell_cmd: &str) -> Result<String> {
        let ssh_part = self.ssh_cmd_str();
        let escaped_cmd = shell_cmd.replace('\'', "'\\''");
        let script = format!(
            "{{ printf 'shell\\n'; sleep 1; printf '{}\\nexit\\nexit\\n'; }} | {}",
            escaped_cmd, ssh_part
        );
        let raw = self.ssh.run_shell_pipe(self.config.id, &script).await?;
        Ok(Self::strip_citrix_noise(&raw))
    }

    async fn vtysh_run(&self, frr_cmd: &str) -> Result<String> {
        let ssh_part = self.ssh_cmd_str();
        let escaped_cmd = frr_cmd.replace('\'', "'\\''");
        let script = format!(
            "{{ printf 'vtysh\\n'; sleep 1; printf '{}\\nexit\\nexit\\n'; }} | {}",
            escaped_cmd, ssh_part
        );
        let raw = self.ssh.run_shell_pipe(self.config.id, &script).await?;
        Ok(Self::strip_citrix_noise(&raw))
    }

    // ── Strip Citrix ADC banner / warning / shell noise ──────────────────────

    fn strip_citrix_noise(raw: &str) -> String {
        let mut lines: Vec<&str> = Vec::new();
        let mut in_warning_block = false;

        for line in raw.lines() {
            let t = line.trim();

            if t.starts_with("Warning:") && t.contains('[') {
                in_warning_block = true;
                continue;
            }

            if in_warning_block {
                if t.contains(']') {
                    in_warning_block = false;
                }
                continue;
            }

            if t == "Done" || t == "Done." {
                continue;
            }
            if t == "Bye!" {
                continue;
            }
            if t.starts_with("###")
                || t.starts_with("WARNING:")
                || t.starts_with("Disconnect IMMEDIATELY")
                || (t.starts_with('#') && t.ends_with('#'))
            {
                continue;
            }
            if t.starts_with("> ") || t == ">" {
                continue;
            }
            if t.contains('@') && t.contains('#') && t.len() < 80 && !t.contains("BGP") {
                continue;
            }
            if t == "shell" || t == "exit" || t == "vtysh" {
                continue;
            }
            if t.starts_with("Hello, this is") || t.starts_with("FRRouting") {
                continue;
            }
            if (t.ends_with('#') || t.ends_with('>')) && !t.contains(' ') && t.len() < 60 {
                continue;
            }

            lines.push(line);
        }

        lines.join("\n")
    }

    // ── connect ───────────────────────────────────────────────────────────────

    pub async fn connect(&mut self) -> Result<()> {
        self.status = ConnectionStatus::Connecting;
        match self.raw_ssh_run("echo ok").await {
            Ok(out) => {
                if out.contains("ok") || out.contains("Done") || !out.is_empty() {
                    self.status = ConnectionStatus::Connected;
                    Ok(())
                } else {
                    let msg = "SSH connected but got no output".to_string();
                    self.status = ConnectionStatus::Error(msg.clone());
                    bail!("{}", msg);
                }
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
        let raw = {
            let r1 = self.vtysh_run("show bgp summary").await;
            if r1
                .as_ref()
                .is_ok_and(|s| s.contains("BGP router identifier"))
            {
                r1?
            } else {
                let r2 = self.vtysh_run("show bgp ipv4 unicast summary").await;
                if r2
                    .as_ref()
                    .is_ok_and(|s| s.contains("BGP router identifier"))
                {
                    r2?
                } else {
                    self.vtysh_run("show ip bgp summary").await?
                }
            }
        };

        if !raw.contains("BGP router identifier") {
            bail!(
                "Unexpected output from show bgp summary:\n{}",
                &raw[..raw.len().min(200)]
            );
        }

        let mut summary = parse_bgp_summary(&raw);
        self.status = ConnectionStatus::Connected;

        let mut detail_map = {
            let cmds = ["show bgp neighbors", "show ip bgp neighbors"];
            let mut map = std::collections::HashMap::new();
            'outer: for cmd in &cmds {
                if let Ok(out) = self.vtysh_run(cmd).await {
                    if out.contains("BGP neighbor is") {
                        map = parse_all_neighbor_details(&out);
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
            }
        }

        Ok(summary)
    }

    // ── get_routes ────────────────────────────────────────────────────────────

    pub async fn get_routes(&mut self) -> Result<Vec<BgpRoute>> {
        let raw = {
            let r1 = self.vtysh_run("show bgp ipv4 unicast").await;
            if r1
                .as_ref()
                .is_ok_and(|s| s.contains("BGP table version") || s.contains("Status codes"))
            {
                r1?
            } else {
                let r2 = self.vtysh_run("show bgp").await;
                if r2
                    .as_ref()
                    .is_ok_and(|s| s.contains("BGP table version") || s.contains("Status codes"))
                {
                    r2?
                } else {
                    self.vtysh_run("show ip bgp").await?
                }
            }
        };
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
        let ssh_part = self.ssh_cmd_str();
        let mut vtysh_cmds = String::from("configure terminal\\n");
        for cmd in commands {
            let escaped = cmd.replace('\'', "'\\''").replace('\n', "\\n");
            vtysh_cmds.push_str(&escaped);
            vtysh_cmds.push_str("\\n");
        }
        vtysh_cmds.push_str("end\\nwrite memory\\nexit\\n");

        let script =
            format!("{{ printf 'vtysh\\n'; sleep 1; printf '{vtysh_cmds}exit\\n'; }} | {ssh_part}");
        let raw = self
            .ssh
            .run_shell_pipe(self.config.id, &script)
            .await
            .context("write_config: SSH shell pipe failed")?;
        let out = Self::strip_citrix_noise(&raw);

        if out.contains("% Invalid") || out.contains("% Unknown command") {
            bail!("Router rejected config: {}", &out[..out.len().min(300)]);
        }
        Ok(())
    }

    pub async fn apply_config(&mut self, _config: &str) -> Result<()> {
        bail!("apply_config not yet implemented for Citrix VPX backend");
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

        let mut prefix_lists: HashMap<String, Vec<PrefixListEntry>> = HashMap::new();
        let mut community_lists: HashMap<String, Vec<String>> = HashMap::new();

        let plist_futs: Vec<_> = plist_names
            .iter()
            .map(|name| {
                let cmd2 = format!("show ip prefix-list {name}");
                let name = name.clone();
                async move { (name, self.vtysh_run(&cmd2).await) }
            })
            .collect();

        let clist_futs: Vec<_> = clist_names
            .iter()
            .map(|name| {
                let cmd3 = format!("show ip community-list {name}");
                let name = name.clone();
                async move { (name, self.vtysh_run(&cmd3).await) }
            })
            .collect();

        let (plist_results, clist_results) = futures::future::join(
            futures::future::join_all(plist_futs),
            futures::future::join_all(clist_futs),
        )
        .await;

        for (name, result) in plist_results {
            if let Ok(pl_raw) = result {
                prefix_lists.insert(name, parse_prefix_list_entries(&pl_raw));
            }
        }

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
