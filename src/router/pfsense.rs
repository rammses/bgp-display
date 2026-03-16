// pfSense 2.8 SSH backend.
//
// pfSense 2.8 runs FRRouting (FRR) for BGP.  SSH drops into the pfSense
// console menu (`/etc/rc.initial`) rather than a regular shell.
//
// Menu bypass strategy:
//   SSH is invoked with `-T` (no PTY) and piped stdin.  We send "8\n"
//   (option 8 = Shell) followed by the actual command and "exit\n".
//   The menu noise is stripped from stdout before returning.
//
// FRR commands follow standard vtysh syntax — the same parsers from
// cisco.rs are reused directly.

#![allow(dead_code)]

use crate::{
    bgp::{parse_bgp_summary, BgpRoute, BgpSummary},
    router::{ConnectionStatus, RouterConfig},
    router::cisco::{
        parse_all_neighbor_details, parse_bgp_table, parse_neighbor_detail, parse_prefix_list_entries,
        parse_route_map_entries, parse_community_list_entries,
    },
};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub struct PfSenseBackend {
    pub hostname:  String,
    pub port:      u16,
    pub username:  String,
    pub password:  Option<String>,
    pub router_id: IpAddr,
    pub local_as:  u32,
    status:        ConnectionStatus,
}

impl PfSenseBackend {
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

    // ── Raw SSH helper (menu bypass) ──────────────────────────────────────────
    //
    // pfSense SSH drops into the console menu.  We pipe stdin to:
    //   1. send "8\n" to select Shell
    //   2. send the actual command
    //   3. send "exit\n" to leave the shell
    //
    // `-T` disables PTY allocation so we get clean pipe I/O.
    // Stdout is post-processed to strip menu banners.

    async fn raw_ssh_run_inner(&self, shell_cmd: &str) -> Result<String> {
        let target = format!("{}@{}", self.username, self.hostname);
        let port_str = self.port.to_string();
        let control_path_arg = format!("ControlPath={}", crate::router::SSH_MUX_CONTROL_PATH);

        let mut cmd;
        let mut ssh_args: Vec<&str> = vec![
            "-p", &port_str,
            "-T",
            "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "LogLevel=ERROR",
            "-o", "ControlMaster=auto",
            "-o", &control_path_arg,
            "-o", "ControlPersist=600",
        ];

        if let Some(ref pw) = self.password {
            cmd = Command::new("sshpass");
            cmd.env("SSHPASS", pw);
            cmd.arg("-e").arg("ssh");
            ssh_args.push("-o");
            ssh_args.push("PreferredAuthentications=password,keyboard-interactive");
        } else {
            cmd = Command::new("ssh");
            ssh_args.push("-o");
            ssh_args.push("BatchMode=yes");
        }

        cmd.args(&ssh_args).arg(&target);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn SSH: {e}"))?;

        // Feed the menu: option 8 → shell → command → exit
        let stdin_data = format!("8\n{shell_cmd}\nexit\n");
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(stdin_data.as_bytes()).await?;
            drop(stdin);
        }

        let output = tokio::time::timeout(
            Duration::from_secs(15),
            child.wait_with_output(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("SSH timed out connecting to {}", self.hostname))??;

        if !output.status.success() && output.stdout.is_empty() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            bail!("SSH error: {}", err.trim());
        }

        let raw = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(Self::strip_menu_noise(&raw))
    }

    async fn raw_ssh_run(&self, shell_cmd: &str) -> Result<String> {
        match self.raw_ssh_run_inner(shell_cmd).await {
            Err(e) if crate::router::is_ssh_mux_error(&e) => {
                crate::router::cleanup_mux_socket(&self.username, &self.hostname, self.port).await;
                self.raw_ssh_run_inner(shell_cmd).await
            }
            other => other,
        }
    }

    // ── Strip pfSense console menu noise ──────────────────────────────────────
    //
    // Removes the banner, menu items (lines like "0) Logout", "8) Shell"),
    // "Enter an option:" prompts, shell prompts, and the trailing "exit".

    fn strip_menu_noise(raw: &str) -> String {
        let mut lines: Vec<&str> = Vec::new();
        let mut past_menu = false;

        for line in raw.lines() {
            let t = line.trim();

            if !past_menu {
                // Skip blank lines, banners, menu entries, prompts
                if t.is_empty()
                    || t.starts_with("***")
                    || t.starts_with("pfSense")
                    || t.starts_with("Enter an option")
                    || t.contains("WAN (")
                    || t.contains("LAN (")
                    || t.contains("OPT")
                    // Menu items: digit(s) followed by ")"
                    || t.chars().next().map_or(false, |c| c.is_ascii_digit())
                       && t.contains(')')
                    // Shell prompt: [version][user@host]/path:
                    || (t.starts_with('[') && t.contains("]/"))
                {
                    continue;
                }
                past_menu = true;
            }

            // Once past the menu, still skip shell prompts / exit
            let t = line.trim();
            if (t.starts_with('[') && t.contains("]/"))
                || t == "exit"
            {
                continue;
            }

            lines.push(line);
        }

        lines.join("\n")
    }

    // ── vtysh helper ──────────────────────────────────────────────────────────

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

    pub async fn refresh(&mut self) -> Result<BgpSummary> {
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
            bail!(
                "Unexpected output from show bgp summary:\n{}",
                &raw[..raw.len().min(200)]
            );
        }

        let mut summary = parse_bgp_summary(&raw);
        self.router_id = summary.router_id;
        self.local_as  = summary.local_as;
        self.status    = ConnectionStatus::Connected;

        // Fetch all neighbour details in a SINGLE SSH call.
        let this = &*self;
        let mut detail_map = {
            let cmds = ["show bgp neighbors", "show ip bgp neighbors"];
            let mut map = std::collections::HashMap::new();
            'outer: for cmd in &cmds {
                if let Ok(out) = this.vtysh_run(cmd).await {
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
                peer.description             = d.description;
                peer.route_map_in            = d.route_map_in;
                peer.route_map_out           = d.route_map_out;
                peer.next_hop_self           = d.next_hop_self;
                peer.route_reflector_client  = d.route_reflector_client;
                peer.update_source           = d.update_source;
                peer.password_configured     = d.password_configured;
                if d.hold_time > 0 { peer.hold_time = d.hold_time; }
                if d.keepalive  > 0 { peer.keepalive  = d.keepalive; }
            }
        }

        Ok(summary)
    }

    // ── get_routes ────────────────────────────────────────────────────────────

    pub async fn get_routes(&mut self) -> Result<Vec<BgpRoute>> {
        let raw = {
            let r1 = self.vtysh_run("show bgp ipv4 unicast").await;
            if r1.as_ref().is_ok_and(|s| {
                s.contains("BGP table version") || s.contains("Status codes")
            }) {
                r1?
            } else {
                let r2 = self.vtysh_run("show bgp").await;
                if r2.as_ref().is_ok_and(|s| {
                    s.contains("BGP table version") || s.contains("Status codes")
                }) {
                    r2?
                } else {
                    self.vtysh_run("show ip bgp").await?
                }
            }
        };
        Ok(parse_bgp_table(&raw))
    }
    // ── get_peer_routes ───────────────────────────────────────────────────────────────────

    pub async fn get_peer_routes(&self, ip: IpAddr, dir: crate::bgp::PeerRouteDirection) -> Result<Vec<BgpRoute>> {
        use crate::bgp::PeerRouteDirection;
        let cmd = match dir {
            PeerRouteDirection::Received   => format!("show bgp neighbors {ip} routes"),
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
    // ── ping_mtu ─────────────────────────────────────────────────────────────────

    /// FreeBSD DF-bit ping (`-D`): tries 1500-byte then 1430-byte frame.
    /// Returns IP-total frame size that succeeded, or 0 if all failed.
    pub async fn ping_mtu(&self, target: IpAddr) -> Result<u16> {
        for payload in [1472u16, 1402, 548] {
            // BSD ping: -D sets DF bit, -c count, -s payload size
            let cmd = format!("ping -D -c 3 -s {} {}", payload, target);
            let out = self.raw_ssh_run(&cmd).await.unwrap_or_default();
            if out.contains(" 0% packet loss") || out.contains("bytes from") {
                return Ok(payload + 28);
            }
        }
        Ok(0)
    }
    // ── apply_config ──────────────────────────────────────────────────────────

    pub async fn apply_config(&mut self, _config: &str) -> Result<()> {
        bail!("apply_config not yet implemented for pfSense backend");
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
                    let part = clause.splitn(2, ':').nth(1).unwrap_or("").trim();
                    for name in part.split_whitespace() {
                        plist_names.push(name.to_string());
                    }
                }
                if clause.starts_with("community") && clause.contains(':') {
                    let part = clause.splitn(2, ':').nth(1).unwrap_or("").trim();
                    for name in part.split_whitespace() {
                        clist_names.push(name.to_string());
                    }
                }
            }
        }

        let mut prefix_lists: HashMap<String, Vec<PrefixListEntry>> = HashMap::new();
        let mut community_lists: HashMap<String, Vec<String>> = HashMap::new();

        // Fetch all prefix-lists and community-lists in parallel
        let plist_futs: Vec<_> = plist_names.iter().map(|name| {
            let cmd2 = format!("show ip prefix-list {name}");
            let name = name.clone();
            async move {
                let result = self.vtysh_run(&cmd2).await;
                (name, result)
            }
        }).collect();

        let clist_futs: Vec<_> = clist_names.iter().map(|name| {
            let cmd3 = format!("show ip community-list {name}");
            let name = name.clone();
            async move {
                let result = self.vtysh_run(&cmd3).await;
                (name, result)
            }
        }).collect();

        let (plist_results, clist_results) = futures::future::join(
            futures::future::join_all(plist_futs),
            futures::future::join_all(clist_futs),
        ).await;

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
