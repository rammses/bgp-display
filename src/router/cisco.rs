// Cisco IOS / IOS-XE / FRRouting SSH backend.
//
// Uses the system `ssh` binary (tokio::process::Command) — no libssh2 needed.
// Key-based auth must be working (SSH agent or ~/.ssh/id_*).

#![allow(dead_code)]

use crate::{
    bgp::{parse_bgp_summary, BgpRoute, BgpSummary, RouteOrigin, RouteStatus},
    router::{ConnectionStatus, RouterConfig},
};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio::process::Command;

pub struct CiscoBackend {
    pub hostname:  String,
    pub port:      u16,
    pub username:  String,
    pub password:  Option<String>,
    pub router_id: IpAddr,
    pub local_as:  u32,
    status:        ConnectionStatus,
}

impl CiscoBackend {
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

    // ── SSH helper ────────────────────────────────────────────────────────────
    //
    // Runs:  ssh [opts] user@host "<cmd>"
    //
    // Common shared SSH flags:
    //   -o ConnectTimeout=5          – don't hang forever
    //   -o BatchMode=yes             – never prompt; fail fast if key auth absent
    //   -o StrictHostKeyChecking=accept-new  – auto-accept on first connect
    //   -o LogLevel=ERROR            – suppress "Warning: Permanently added…"

    async fn ssh_run_inner(&self, cmd: &str) -> Result<String> {
        let target = format!("{}@{}", self.username, self.hostname);
        let port_str = self.port.to_string();
        let control_path_arg = format!("ControlPath={}", crate::router::SSH_MUX_CONTROL_PATH);
        let output = tokio::time::timeout(
            Duration::from_secs(15),
            Command::new("ssh")
                .args([
                    "-p", &port_str,
                    "-o", "ConnectTimeout=5",
                    "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "LogLevel=ERROR",
                    "-o", "ControlMaster=auto",
                    "-o", &control_path_arg,
                    "-o", "ControlPersist=600",
                    &target,
                    cmd,
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

    async fn ssh_run(&self, cmd: &str) -> Result<String> {
        match self.ssh_run_inner(cmd).await {
            Err(e) if crate::router::is_ssh_mux_error(&e) => {
                crate::router::cleanup_mux_socket(&self.username, &self.hostname, self.port).await;
                self.ssh_run_inner(cmd).await
            }
            other => other,
        }
    }

    /// Run a command, falling back to `vtysh -c '<cmd>'` if the plain output
    /// doesn't contain the expected marker string.
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
            bail!("Unexpected output from show ip bgp summary:\n{}", &raw[..raw.len().min(200)]);
        }

        let mut summary = parse_bgp_summary(&raw);

        // Update cached values from the parsed summary
        self.router_id = summary.router_id;
        self.local_as  = summary.local_as;
        self.status    = ConnectionStatus::Connected;

        // Fetch all neighbour details in a SINGLE SSH call.
        //
        // `show ip bgp neighbors` (no IP) prints all neighbours concatenated.
        // One SSH round-trip replaces N parallel ones — critical when peers are
        // reachable over high-latency links such as IPSec tunnels.
        let this = &*self;
        let mut detail_map = {
            let cmds = [
                ("show ip bgp neighbors", "BGP neighbor is"),
                ("show bgp neighbors",    "BGP neighbor is"),
            ];
            let mut map = HashMap::new();
            'outer: for (cmd, marker) in &cmds {
                if let Ok(raw) = this.ssh_run_or_vtysh(cmd, marker).await {
                    if raw.contains(marker) {
                        map = parse_all_neighbor_details(&raw);
                        break 'outer;
                    }
                }
            }
            map
        };

        // Merge details back into peers
        for peer in &mut summary.peers {
            if let Some(d) = detail_map.remove(&peer.neighbor_ip) {
                peer.description          = d.description;
                peer.route_map_in         = d.route_map_in;
                peer.route_map_out        = d.route_map_out;
                peer.next_hop_self        = d.next_hop_self;
                peer.route_reflector_client = d.route_reflector_client;
                peer.update_source        = d.update_source;
                peer.password_configured  = d.password_configured;
                if d.hold_time  > 0 { peer.hold_time  = d.hold_time;  }
                if d.keepalive  > 0 { peer.keepalive   = d.keepalive;  }
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
    // ── get_peer_routes ───────────────────────────────────────────────────────────────────
    //
    // Runs `show ip bgp neighbors <ip> routes`  (received)
    // or   `show ip bgp neighbors <ip> advertised-routes`  (advertised)

    pub async fn get_peer_routes(&self, ip: IpAddr, dir: crate::bgp::PeerRouteDirection) -> Result<Vec<BgpRoute>> {
        use crate::bgp::PeerRouteDirection;
        let cmd = match dir {
            PeerRouteDirection::Received   => format!("show ip bgp neighbors {ip} routes"),
            PeerRouteDirection::Advertised => format!("show ip bgp neighbors {ip} advertised-routes"),
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

    // ── apply_config ──────────────────────────────────────────────────────────

    pub async fn apply_config(&mut self, _config: &str) -> Result<()> {
        bail!("apply_config not yet implemented for system-SSH backend");
    }

    // ── fetch_route_map_detail ────────────────────────────────────────────────
    //
    // Runs `show route-map <name>`, then expands every referenced prefix-list
    // and community-list with additional SSH calls.

    pub async fn fetch_route_map_detail(&self, rm_name: &str) -> Result<crate::bgp::RouteMapDetail> {
        use crate::bgp::{PrefixListEntry, RouteMapDetail};
        use std::collections::HashMap;

        let cmd = format!("show route-map {rm_name}");
        let raw = self.ssh_run_or_vtysh(&cmd, "route-map").await?;
        let entries = parse_route_map_entries(&raw);

        // Collect referenced prefix-list / community-list names
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

        // Fetch all prefix-lists and community-lists in parallel
        let plist_futs: Vec<_> = plist_names.iter().map(|name| {
            let cmd2 = format!("show ip prefix-list {name}");
            let name = name.clone();
            async move {
                let result = self.ssh_run_or_vtysh(&cmd2, "prefix-list").await;
                (name, result)
            }
        }).collect();

        let clist_futs: Vec<_> = clist_names.iter().map(|name| {
            let cmd3 = format!("show ip community-list {name}");
            let name = name.clone();
            async move {
                let result = self.ssh_run_or_vtysh(&cmd3, "community-list").await;
                (name, result)
            }
        }).collect();

        let (plist_results, clist_results) = futures::future::join(
            futures::future::join_all(plist_futs),
            futures::future::join_all(clist_futs),
        ).await;

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

        Ok(RouteMapDetail { name: rm_name.to_string(), entries, prefix_lists, community_lists })
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
                lines.push(format!(" neighbor {} description {}", peer.neighbor_ip, desc));
            }
            if peer.next_hop_self {
                lines.push(format!(" neighbor {} next-hop-self", peer.neighbor_ip));
            }
            if let Some(src) = peer.update_source {
                lines.push(format!(" neighbor {} update-source {}", peer.neighbor_ip, src));
            }
            if peer.password_configured {
                lines.push(format!(
                    " neighbor {} password <configured>",
                    peer.neighbor_ip
                ));
            }
            if let Some(rm) = &peer.route_map_in {
                lines.push(format!(" neighbor {} route-map {} in", peer.neighbor_ip, rm));
            }
            if let Some(rm) = &peer.route_map_out {
                lines.push(format!(" neighbor {} route-map {} out", peer.neighbor_ip, rm));
            }
        }
        lines.push("!".into());
        lines.join("\n")
    }
}

// ─── Neighbor detail (parsed from `show ip bgp neighbors <ip>`) ───────────────

#[derive(Default)]
pub(crate) struct NeighborDetail {
    pub(crate) description:            Option<String>,
    pub(crate) route_map_in:           Option<String>,
    pub(crate) route_map_out:          Option<String>,
    pub(crate) next_hop_self:          bool,
    pub(crate) route_reflector_client: bool,
    pub(crate) update_source:          Option<IpAddr>,
    pub(crate) password_configured:    bool,
    pub(crate) hold_time:              u16,
    pub(crate) keepalive:              u16,
}

pub(crate) fn parse_neighbor_detail(output: &str) -> NeighborDetail {
    let mut d = NeighborDetail::default();
    for line in output.lines() {
        let trimmed = line.trim();
        // Description:  BGP neighbor is <ip>, ... Description: foo
        if let Some(rest) = trimmed.strip_prefix("Description:") {
            d.description = Some(rest.trim().to_string());
        }
        // Route map for incoming advertisements is DENY-ALL (applied)
        // Route map for outgoing advertisements is RM-EXPORT (applied)
        if trimmed.contains("Route map for incoming") {
            if let Some(name) = extract_route_map_name(trimmed) {
                d.route_map_in = Some(name);
            }
        }
        if trimmed.contains("Route map for outgoing") {
            if let Some(name) = extract_route_map_name(trimmed) {
                d.route_map_out = Some(name);
            }
        }
        // FRR style:  Inbound route-map is RM-IN
        if trimmed.starts_with("Inbound route-map is") {
            if let Some(name) = trimmed.split_whitespace().last() {
                d.route_map_in = Some(name.trim_end_matches(',').to_string());
            }
        }
        if trimmed.starts_with("Outbound route-map is") {
            if let Some(name) = trimmed.split_whitespace().last() {
                d.route_map_out = Some(name.trim_end_matches(',').to_string());
            }
        }
        // Next-hop-self
        if trimmed.contains("NEXT_HOP is always this router") || trimmed.contains("next-hop-self") {
            d.next_hop_self = true;
        }
        // Route-reflector-client
        if trimmed.contains("route-reflector-client") {
            d.route_reflector_client = true;
        }
        // Update source
        if trimmed.starts_with("Update source is") {
            if let Some(ip_str) = trimmed.split_whitespace().last() {
                d.update_source = ip_str.parse().ok();
            }
        }
        // Password
        if trimmed.contains("MD5 password configured") || trimmed.contains("Peer Authentication Enabled") {
            d.password_configured = true;
        }
        // Hold/keepalive: "Hold time is 90, keepalive interval is 30 seconds"
        if trimmed.starts_with("Hold time is") {
            let nums: Vec<u16> = trimmed
                .split(|c: char| !c.is_ascii_digit())
                .filter(|s| !s.is_empty())
                .filter_map(|s| s.parse().ok())
                .collect();
            if nums.len() >= 2 {
                d.hold_time = nums[0];
                d.keepalive = nums[1];
            }
        }
    }
    d
}

pub(crate) fn extract_route_map_name(line: &str) -> Option<String> {
    // "Route map for incoming advertisements is RM-NAME (applied)"
    // Look for " is <NAME>" pattern
    if let Some(pos) = line.find(" is ") {
        let rest = &line[pos + 4..];
        let name = rest.split_whitespace().next()?.trim_end_matches(',');
        if name != "(none)" && !name.is_empty() {
            return Some(name.to_string());
        }
    }
    None
}

/// Parse the bulk output of `show ip bgp neighbors` (all peers in one shot).
///
/// The output is split on "BGP neighbor is <ip>" lines.  Each block is
/// parsed by `parse_neighbor_detail` and keyed by the peer IP address.
pub(crate) fn parse_all_neighbor_details(output: &str) -> HashMap<IpAddr, NeighborDetail> {
    let mut map = HashMap::new();
    // Each neighbour block starts with a line like:
    //   "BGP neighbor is 10.0.0.1, remote AS 65001, ..."
    let mut current_ip: Option<IpAddr> = None;
    let mut block = String::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("BGP neighbor is ") {
            // Flush the previous block
            if let Some(ip) = current_ip.take() {
                map.insert(ip, parse_neighbor_detail(&block));
                block.clear();
            }
            // Extract IP from "BGP neighbor is <ip>,"
            let rest = &trimmed["BGP neighbor is ".len()..];
            let ip_str = rest.split(&[',', ' ']).next().unwrap_or("");
            current_ip = ip_str.parse().ok();
        }
        block.push_str(line);
        block.push('\n');
    }
    // Flush the last block
    if let Some(ip) = current_ip {
        map.insert(ip, parse_neighbor_detail(&block));
    }
    map
}

// ─── BGP table parser (`show ip bgp`) ────────────────────────────────────────
//
// Typical FRR/Cisco line format:
//   *> 10.0.0.0/8       192.168.1.1      100      0 65001 i
//   * i10.0.1.0/24      192.168.1.2      100      0       ?
//   Network column may be on a header line "Network  Next Hop ..."
//   Status codes: * valid,  > best, i – internal, s suppressed, h history
//   Origin codes:  i – IGP, e – EGP, ? – incomplete

pub(crate) fn parse_bgp_table(output: &str) -> Vec<BgpRoute> {
    let mut routes = Vec::new();
    let mut prev_network: Option<String> = None;

    for line in output.lines() {
        // Skip header and empty lines
        if line.trim().is_empty()
            || line.contains("Network")
            || line.starts_with("BGP")
            || line.starts_with("Total")
        {
            continue;
        }

        // Status codes are in first 1-4 chars; prefix may start right after or be blank (continuation)
        let chars: Vec<char> = line.chars().collect();
        if chars.is_empty() {
            continue;
        }

        // Parse status flags from the first few characters
        let (status, rest_start) = parse_status_flags(&chars);

        // Skip lines that don't look like route entries (require at least one IP in rest)
        let rest = &line[rest_start..];
        let rest_trimmed = rest.trim();
        if rest_trimmed.is_empty() {
            continue;
        }

        // The rest splits into: [network] next-hop metric local-pref weight as-path origin
        // Network may carry address on same line or be on a standalone line
        let tokens: Vec<&str> = rest_trimmed
            .split_whitespace()
            .collect();

        if tokens.is_empty() {
            continue;
        }

        // Determine if the first token looks like a network prefix
        let (network, tok_start) = if looks_like_prefix(tokens[0]) {
            prev_network = Some(tokens[0].to_string());
            (tokens[0].to_string(), 1)
        } else if let Some(n) = &prev_network {
            // Continuation line – reuse previous network
            (n.clone(), 0)
        } else {
            continue;
        };

        let remaining = &tokens[tok_start..];
        if remaining.is_empty() {
            continue;
        }

        // next-hop  metric  local-pref  weight  [AS path tokens...]  origin
        let next_hop = remaining.first().copied().unwrap_or("0.0.0.0").to_string();
        let mut idx = 1usize;

        let metric = remaining.get(idx).and_then(|s| s.parse::<u32>().ok());
        if metric.is_some() { idx += 1; }

        let local_pref = remaining.get(idx).and_then(|s| s.parse::<u32>().ok());
        if local_pref.is_some() { idx += 1; }

        let weight = remaining.get(idx).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
        if remaining.get(idx).and_then(|s| s.parse::<u32>().ok()).is_some() { idx += 1; }

        // Remaining tokens before origin code: AS path
        let origin_token = remaining.last().copied().unwrap_or("?");
        let origin = match origin_token {
            "i" => RouteOrigin::Igp,
            "e" => RouteOrigin::Egp,
            _   => RouteOrigin::Incomplete,
        };

        let as_path_end = remaining.len().saturating_sub(1);
        let as_path: Vec<u32> = remaining[idx..as_path_end]
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        routes.push(BgpRoute {
            status,
            network,
            next_hop,
            metric,
            local_pref,
            weight,
            as_path,
            origin,
            communities: vec![],
        });
    }

    routes
}

fn parse_status_flags(chars: &[char]) -> (RouteStatus, usize) {
    // Up to 4 status characters before the network/address
    let flags: String = chars.iter().take(4).collect();
    let status = if flags.contains('*') && flags.contains('>') {
        RouteStatus::BestExternal
    } else if flags.contains('>') {
        RouteStatus::Best
    } else if flags.contains('*') {
        RouteStatus::Valid
    } else if flags.contains('s') {
        RouteStatus::Suppressed
    } else if flags.contains('h') {
        RouteStatus::History
    } else {
        RouteStatus::Internal
    };
    // Skip past the flag characters (non-alphanumeric / non-period block at start)
    let skip = chars.iter().take(4)
        .take_while(|&&c| !c.is_alphanumeric() || c == '>')
        .count();
    (status, skip)
}

fn looks_like_prefix(s: &str) -> bool {
    // Accept "10.0.0.0/8" or "10.0.0.0" style (IPv4)
    let base = s.split('/').next().unwrap_or("");
    base.split('.').count() == 4 && base.split('.').all(|o| o.parse::<u8>().is_ok())
}

// ─── Route-map / prefix-list / community-list parsers ─────────────────────────

/// Parse `show route-map <name>` output into entries.
///
/// FRR format:
///   route-map RM-NAME, permit, sequence 10
///     Match clauses:
///       ip address prefix-lists: PLIST1
///     Set clauses:
///       local-preference 100
pub(crate) fn parse_route_map_entries(output: &str) -> Vec<crate::bgp::RouteMapEntry> {
    use crate::bgp::RouteMapEntry;
    let mut entries: Vec<RouteMapEntry> = vec![];
    let mut current: Option<RouteMapEntry> = None;
    let mut in_match = false;
    let mut in_set   = false;

    for line in output.lines() {
        let trimmed = line.trim();
        // Header line: "route-map NAME, permit, sequence N"
        if trimmed.starts_with("route-map ") && trimmed.contains("sequence") {
            if let Some(e) = current.take() { entries.push(e); }
            let parts: Vec<&str> = trimmed.splitn(4, ',').collect();
            let action = parts.get(1).unwrap_or(&" permit").trim().to_string();
            let seq: u32 = parts.get(2)
                .and_then(|p| p.trim().strip_prefix("sequence "))
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            current  = Some(RouteMapEntry { sequence: seq, action, ..Default::default() });
            in_match = false;
            in_set   = false;
            continue;
        }
        if current.is_none() { continue; }
        if trimmed == "Match clauses:" { in_match = true;  in_set   = false; continue; }
        if trimmed == "Set clauses:"   { in_set   = true;  in_match = false; continue; }
        if trimmed == "Call clause:"   { in_match = false; in_set   = false; continue; }
        if trimmed.is_empty() || trimmed == "INACTIVE" { continue; }
        if let Some(ref mut e) = current {
            if      in_match { e.match_clauses.push(trimmed.to_string()); }
            else if in_set   { e.set_clauses.push(trimmed.to_string()); }
        }
    }
    if let Some(e) = current { entries.push(e); }
    entries
}

/// Parse `show ip prefix-list <name>` output.
pub(crate) fn parse_prefix_list_entries(output: &str) -> Vec<crate::bgp::PrefixListEntry> {
    use crate::bgp::PrefixListEntry;
    let mut entries = vec![];
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Find "seq N permit|deny PREFIX [le|ge N]"
        if let Some(seq_pos) = parts.iter().position(|&p| p == "seq") {
            if let (Some(&seq_s), Some(&action), Some(&prefix)) = (
                parts.get(seq_pos + 1),
                parts.get(seq_pos + 2),
                parts.get(seq_pos + 3),
            ) {
                if action == "permit" || action == "deny" {
                    let mut pfx = prefix.to_string();
                    if let (Some(&qual), Some(&num)) = (parts.get(seq_pos + 4), parts.get(seq_pos + 5)) {
                        if qual == "le" || qual == "ge" {
                            pfx = format!("{pfx} {qual} {num}");
                        }
                    }
                    entries.push(PrefixListEntry {
                        seq:    seq_s.parse().unwrap_or(0),
                        action: action.to_string(),
                        prefix: pfx,
                    });
                }
            }
        }
    }
    entries
}

/// Parse `show ip community-list <name>` output — just collect the permit/deny lines.
pub(crate) fn parse_community_list_entries(output: &str) -> Vec<String> {
    output.lines()
        .filter(|l| l.contains("permit") || l.contains("deny"))
        .map(|l| l.trim().to_string())
        .collect()
}