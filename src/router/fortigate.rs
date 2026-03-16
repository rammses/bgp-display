// FortiGate / FortiOS SSH backend.
//
// FortiOS uses its own native CLI — there is no vtysh wrapper.  Commands are
// issued via a piped stdin script over SSH with `-T` (no PTY), the same
// approach as the pfSense backend.
//
// BGP inspection commands (FortiOS 6.x / 7.x):
//   get router info bgp summary                               — peer table
//   get router info bgp network                               — global BGP RIB
//   get router info bgp neighbors <ip>                        — neighbor detail
//   get router info bgp neighbors <ip> received-routes        — received RIB
//   get router info bgp neighbors <ip> advertised-routes      — advertised RIB
//
// The output format is identical to FRR (FortiOS embeds a forked FRR daemon),
// so the existing parse_bgp_summary / parse_bgp_table / parse_neighbor_detail
// helpers from cisco.rs are reused directly.
//
// VDOM support:
//   If the router is configured with a VDOM name, every command script is
//   wrapped in:
//       config vdom
//       edit <vdom>
//       <commands...>
//       end
//
//   If no VDOM is set FortiOS runs in single-VDOM mode and commands go to the
//   global context (the root / mgmt VDOM depending on firmware version).

#![allow(dead_code)]

use crate::{
    bgp::{parse_bgp_summary, BgpRoute, BgpSummary},
    router::{ConnectionStatus, RouterConfig},
    router::cisco::{
        parse_all_neighbor_details, parse_bgp_table, parse_prefix_list_entries,
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

pub struct FortiGateBackend {
    pub hostname:  String,
    pub port:      u16,
    pub username:  String,
    pub password:  Option<String>,
    pub router_id: IpAddr,
    pub local_as:  u32,
    pub vdom:      Option<String>,
    status:        ConnectionStatus,
}

impl FortiGateBackend {
    pub fn new(cfg: &RouterConfig) -> Self {
        Self {
            hostname:  cfg.hostname.clone(),
            port:      cfg.ssh_port,
            username:  cfg.username.clone(),
            password:  cfg.password.clone(),
            router_id: cfg.router_id.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            local_as:  cfg.local_as.unwrap_or(0),
            vdom:      cfg.vdom.clone(),
            status:    ConnectionStatus::Disconnected,
        }
    }

    pub fn status(&self) -> &ConnectionStatus {
        &self.status
    }

    // ── Core SSH helper ───────────────────────────────────────────────────────
    //
    // Builds a CLI script from `cmds`, optionally wrapped in VDOM context,
    // pipes it to `ssh -T`, strips FortiOS prompt noise from stdout, and
    // returns clean output ready for the BGP parsers.

    async fn run_cli_pipeline_inner(&self, cmds: &[&str]) -> Result<String> {
        let mut script = String::new();

        if let Some(ref vdom) = self.vdom {
            script.push_str("config vdom\n");
            script.push_str(&format!("edit {vdom}\n"));
        }
        for cmd in cmds {
            script.push_str(cmd);
            script.push('\n');
        }
        if self.vdom.is_some() {
            script.push_str("end\n");
        }
        script.push_str("exit\n");

        let target = format!("{}@{}", self.username, self.hostname);
        let port_str = self.port.to_string();
        let control_path_arg = format!("ControlPath={}", crate::router::SSH_MUX_CONTROL_PATH);

        let mut cmd_builder;
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
            cmd_builder = Command::new("sshpass");
            cmd_builder.env("SSHPASS", pw);
            cmd_builder.arg("-e").arg("ssh");
            ssh_args.push("-o");
            ssh_args.push("PreferredAuthentications=password,keyboard-interactive");
        } else {
            cmd_builder = Command::new("ssh");
            ssh_args.push("-o");
            ssh_args.push("BatchMode=yes");
        }

        cmd_builder.args(&ssh_args).arg(&target);
        cmd_builder.stdin(Stdio::piped());
        cmd_builder.stdout(Stdio::piped());
        cmd_builder.stderr(Stdio::piped());

        let mut child = cmd_builder
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn SSH: {e}"))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(script.as_bytes()).await?;
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
        Ok(strip_fortigate_noise(&raw))
    }

    async fn run_cli_pipeline(&self, cmds: &[&str]) -> Result<String> {
        match self.run_cli_pipeline_inner(cmds).await {
            Err(e) if crate::router::is_ssh_mux_error(&e) => {
                crate::router::cleanup_mux_socket(&self.username, &self.hostname, self.port).await;
                self.run_cli_pipeline_inner(cmds).await
            }
            other => other,
        }
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
        self.router_id = summary.router_id;
        self.local_as  = summary.local_as;
        self.status    = ConnectionStatus::Connected;

        // Fetch all neighbour details in a SINGLE CLI call.
        let this = &*self;
        let mut detail_map = {
            let mut map = HashMap::new();
            if let Ok(out) = this.run_cli_pipeline(&["get router info bgp neighbors"]).await {
                if out.contains("BGP neighbor is") {
                    map = parse_all_neighbor_details(&out);
                }
            }
            map
        };

        for peer in &mut summary.peers {
            if let Some(d) = detail_map.remove(&peer.neighbor_ip) {
                peer.description            = d.description;
                peer.route_map_in           = d.route_map_in;
                peer.route_map_out          = d.route_map_out;
                peer.next_hop_self          = d.next_hop_self;
                peer.route_reflector_client = d.route_reflector_client;
                peer.update_source          = d.update_source;
                peer.password_configured    = d.password_configured;
                if d.hold_time > 0 { peer.hold_time = d.hold_time; }
                if d.keepalive  > 0 { peer.keepalive  = d.keepalive;  }
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
    //
    // FortiOS uses `received-routes` (all NLRIs received before policy) rather
    // than `routes` (post-policy active routes).  This matches the intent of
    // the Received direction in the drill-down view.

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
    // ── ping_mtu ─────────────────────────────────────────────────────────────────

    /// FortiOS `execute ping` with DF-bit option.
    /// Returns IP-total frame size that succeeded, or 0 if all failed.
    pub async fn ping_mtu(&self, target: IpAddr) -> Result<u16> {
        for payload in [1472u16, 1402, 548] {
            // FortiOS: set options then execute ping
            let size_str  = payload.to_string();
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

        // FortiOS exposes route-map definitions via `get router info routepolicy`
        let cmd = format!("get router info routepolicy {rm_name}");
        let raw = self.run_cli_pipeline(&[cmd.as_str()]).await?;
        let entries = if raw.contains("route-map") {
            parse_route_map_entries(&raw)
        } else {
            vec![]
        };

        // Collect referenced prefix-list and community-list names
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

/// Strip FortiOS CLI prompt lines and ANSI escape sequences from command output.
///
/// When commands are piped over SSH, stdout can contain prompt echoes such as
///   "FGT60F3G19000001 # "
///   "FGT60F3G19000001 (root) # "
/// as well as ANSI colour codes.  This function removes those artefacts so the
/// BGP parsers receive clean, line-oriented data.
fn strip_fortigate_noise(raw: &str) -> String {
    raw.lines()
        .map(|line| strip_ansi(line))
        .filter(|line| {
            let t = line.trim();
            if t.is_empty() {
                return false;
            }
            // Prompt lines: end with " #" (with or without trailing space)
            if t.ends_with(" #") || t.ends_with("# ") {
                return false;
            }
            // Inline prompt: "hostname (context) # " appearing mid-output
            // Heuristic: non-indented line that contains " # " and no BGP keywords
            if !t.starts_with(' ') && !t.starts_with('\t') && t.contains(" # ") {
                return false;
            }
            // FortiOS session banner lines
            if t.starts_with("Welcome") || t.starts_with("FortiGate") || t.starts_with("FG") {
                return false;
            }
            true
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Remove ANSI escape sequences (e.g. `\x1b[1;32m`) from a single line.
fn strip_ansi(line: &str) -> String {
    let mut result = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip ESC [ ... <letter>
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
