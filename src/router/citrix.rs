// Citrix ADC / VPX SSH backend.
//
// Citrix ADC (formerly NetScaler) NS14.x runs FRRouting (FRR) for BGP.
// SSH drops into the NetScaler CLI ("> " prompt).  `vtysh` is invoked
// directly from the NetScaler CLI (NOT via `shell`) — it opens an
// interactive FRR/Cisco-style CLI.  `vtysh -c` is NOT supported on this
// version.
//
// Session flow:
//   SSH login  →  NetScaler CLI ("> ")  →  vtysh  →  router# prompt
//   run IOS-style commands (show ip bgp summary, etc.)
//   exit  →  back to NetScaler CLI  →  exit
//
// FRR commands use FRR style (show bgp ...) rather than IOS style
// (show ip bgp ...) — the IOS variants do not work on Citrix's vtysh.
// The same parsers from cisco.rs are reused for output parsing.

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

pub struct CitrixVpxBackend {
    pub hostname:  String,
    pub port:      u16,
    pub username:  String,
    pub password:  Option<String>,
    pub router_id: IpAddr,
    pub local_as:  u32,
    status:        ConnectionStatus,
}

impl CitrixVpxBackend {
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

    // ── SSH argument builder ─────────────────────────────────────────────────
    //
    // Returns the ssh command string portion (including sshpass if password
    // is set) for embedding in shell pipelines.

    fn ssh_cmd_str(&self) -> String {
        let target = format!("{}@{}", self.username, self.hostname);
        let base_args = format!(
            "-p {} -T -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR \
             -o ControlMaster=auto -o ControlPath={} -o ControlPersist=600",
            self.port, crate::router::SSH_MUX_CONTROL_PATH
        );
        if self.password.is_some() {
            format!(
                "sshpass -e ssh {} -o PreferredAuthentications=password,keyboard-interactive {}",
                base_args, target
            )
        } else {
            format!("ssh {} -o BatchMode=yes {}", base_args, target)
        }
    }

    // ── Raw SSH helper ────────────────────────────────────────────────────────
    //
    // Runs a FreeBSD shell command on Citrix ADC.  Uses a shell pipeline
    // with a built-in `sleep` to ensure the `shell` sub-command is processed
    // before the actual command is sent.

    async fn raw_ssh_run(&self, shell_cmd: &str) -> Result<String> {
        let ssh_part = self.ssh_cmd_str();
        // Escape single quotes in the command for safe shell embedding
        let escaped_cmd = shell_cmd.replace('\'', "'\\''");
        let script = format!(
            "{{ printf 'shell\\n'; sleep 1; printf '{}\\nexit\\nexit\\n'; }} | {}",
            escaped_cmd, ssh_part
        );

        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(&script);
        if let Some(ref pw) = self.password {
            cmd.env("SSHPASS", pw);
        }

        let output = tokio::time::timeout(
            Duration::from_secs(15),
            cmd.output(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("SSH timed out connecting to {}", self.hostname))??;

        if !output.status.success() && output.stdout.is_empty() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            bail!("SSH error: {}", err.trim());
        }

        let raw = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(Self::strip_citrix_noise(&raw))
    }

    // ── Strip Citrix ADC banner / warning / shell noise ──────────────────────
    //
    // Removes:
    //   • SSH login banner (### lines, WARNING, Disconnect IMMEDIATELY)
    //   • Warning: [ ... ] blocks (RPC default password warnings)
    //   • " Done" lines following warnings
    //   • NetScaler CLI prompts (lines starting with "> ")
    //   • Shell prompts (root@ns# ...)
    //   • The "shell" and "exit" echo lines

    fn strip_citrix_noise(raw: &str) -> String {
        let mut lines: Vec<&str> = Vec::new();
        let mut in_warning_block = false;

        for line in raw.lines() {
            let t = line.trim();

            // Skip the "Warning: [" opener (possibly with text after it)
            if t.starts_with("Warning:") && t.contains('[') {
                in_warning_block = true;
                continue;
            }

            // Inside a Warning block, skip until the closing "]"
            if in_warning_block {
                if t.contains(']') {
                    in_warning_block = false;
                }
                continue;
            }

            // Skip standalone " Done" line that follows the warning block
            if t == "Done" || t == "Done." {
                continue;
            }

            // Skip "Bye!" logout message
            if t == "Bye!" {
                continue;
            }

            // Skip SSH banner lines
            if t.starts_with("###")
                || t.starts_with("WARNING:")
                || t.starts_with("Disconnect IMMEDIATELY")
                || (t.starts_with('#') && t.ends_with('#'))
            {
                continue;
            }

            // Skip NetScaler CLI prompt lines
            if t.starts_with("> ") || t == ">" {
                continue;
            }

            // Skip shell prompts (root@ns# or similar)
            if t.contains('@') && t.contains('#') && t.len() < 80
                && !t.contains("BGP")
            {
                continue;
            }

            // Skip our own piped commands echoed back
            if t == "shell" || t == "exit" || t == "vtysh" {
                continue;
            }

            // Skip vtysh banner ("Hello, this is FRRouting" etc.)
            if t.starts_with("Hello, this is") || t.starts_with("FRRouting") {
                continue;
            }

            // Skip vtysh/Cisco-style prompts (e.g. "ns#", "router#", "ns>")
            if (t.ends_with('#') || t.ends_with('>')) && !t.contains(' ') && t.len() < 60 {
                continue;
            }

            lines.push(line);
        }

        lines.join("\n")
    }

    // ── vtysh helper ──────────────────────────────────────────────────────────
    //
    // Citrix ADC NS14.x: `vtysh` is invoked directly from the NetScaler CLI.
    // `vtysh -c` is NOT supported — we must enter vtysh interactively, run
    // the IOS-style command, then exit.
    //
    // We use a shell pipeline with a built-in `sleep` between writing `vtysh`
    // and the FRR command so the NetScaler CLI has time to hand off stdin to
    // the vtysh process:
    //   { printf 'vtysh\n'; sleep 1; printf '<cmd>\nexit\nexit\n'; } | ssh ...

    async fn vtysh_run(&self, frr_cmd: &str) -> Result<String> {
        let ssh_part = self.ssh_cmd_str();
        // Escape single quotes in the FRR command for safe shell embedding
        let escaped_cmd = frr_cmd.replace('\'', "'\\''");
        let script = format!(
            "{{ printf 'vtysh\\n'; sleep 1; printf '{}\\nexit\\nexit\\n'; }} | {}",
            escaped_cmd, ssh_part
        );

        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(&script);
        if let Some(ref pw) = self.password {
            cmd.env("SSHPASS", pw);
        }

        let output = tokio::time::timeout(
            Duration::from_secs(15),
            cmd.output(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("SSH timed out connecting to {}", self.hostname))??;

        if !output.status.success() && output.stdout.is_empty() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            bail!("SSH error: {}", err.trim());
        }

        let raw = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(Self::strip_citrix_noise(&raw))
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
    //
    // Citrix ADC NS14.x vtysh uses FRR-style commands.
    // Try `show bgp summary` first (FRR style), then fall back to alternatives.

    pub async fn refresh(&mut self) -> Result<BgpSummary> {
        let raw = {
            let r1 = self.vtysh_run("show bgp summary").await;
            if r1.as_ref().is_ok_and(|s| s.contains("BGP router identifier")) {
                r1?
            } else {
                let r2 = self.vtysh_run("show bgp ipv4 unicast summary").await;
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

        // Fetch per-neighbour detail (description, route-maps) in parallel
        let ips: Vec<IpAddr> = summary.peers.iter().map(|p| p.neighbor_ip).collect();
        let this = &*self; // shared ref for parallel fetches
        let detail_futs: Vec<_> = ips.iter().map(|&ip| {
            async move {
                let cmd = format!("show bgp neighbors {ip}");
                let r1 = this.vtysh_run(&cmd).await;
                let raw = if r1.as_ref().is_ok_and(|s| s.contains("BGP neighbor is")) {
                    r1
                } else {
                    let cmd2 = format!("show ip bgp neighbors {ip}");
                    this.vtysh_run(&cmd2).await
                };
                (ip, raw)
            }
        }).collect();
        let detail_results = futures::future::join_all(detail_futs).await;
        let mut detail_map = HashMap::new();
        for (ip, result) in detail_results {
            if let Ok(raw) = result {
                detail_map.insert(ip, parse_neighbor_detail(&raw));
            }
        }

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

    // ── apply_config ──────────────────────────────────────────────────────────

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
