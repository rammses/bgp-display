// Cisco IOS / IOS-XE / FRRouting SSH backend.
//
// SSH transport is delegated to the shared SshSessionManager.
// This module retains all vendor-specific command construction and parsing.

#![allow(dead_code)]

use crate::{
    bgp::{parse_bgp_summary, BgpRoute, BgpSummary, RouteOrigin, RouteStatus},
    router::{ConnectionStatus, RouterConfig},
    ssh::SshSessionManager,
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

    pub async fn fetch_policy_stanza(
        &self,
    ) -> PolicyStanza {
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

// ─── Neighbor detail (parsed from `show ip bgp neighbors <ip>`) ───────────────

#[derive(Default)]
pub(crate) struct NeighborDetail {
    pub(crate) description: Option<String>,
    pub(crate) route_map_in: Option<String>,
    pub(crate) route_map_out: Option<String>,
    pub(crate) next_hop_self: bool,
    pub(crate) route_reflector_client: bool,
    pub(crate) update_source: Option<IpAddr>,
    pub(crate) password_configured: bool,
    pub(crate) hold_time: u16,
    pub(crate) keepalive: u16,
    pub(crate) reset_count: u32,
    pub(crate) last_reset_reason: Option<String>,
    pub(crate) notifs_sent: u32,
    pub(crate) notifs_rcvd: u32,
    pub(crate) bfd_state: Option<String>,
}

pub(crate) fn parse_neighbor_detail(output: &str) -> NeighborDetail {
    let mut d = NeighborDetail::default();
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Description:") {
            d.description = Some(rest.trim().to_string());
        }
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
        if trimmed.contains("NEXT_HOP is always this router") || trimmed.contains("next-hop-self") {
            d.next_hop_self = true;
        }
        if trimmed.contains("route-reflector-client") {
            d.route_reflector_client = true;
        }
        if trimmed.starts_with("Update source is") {
            if let Some(ip_str) = trimmed.split_whitespace().last() {
                d.update_source = ip_str.parse().ok();
            }
        }
        if trimmed.contains("MD5 password configured")
            || trimmed.contains("Peer Authentication Enabled")
        {
            d.password_configured = true;
        }
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
        if trimmed.starts_with("Connections established") {
            if let Some(pos) = trimmed.find("dropped ") {
                d.reset_count = trimmed[pos + 8..]
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }
        if trimmed.starts_with("Last reset") {
            if let Some(pos) = trimmed.find("due to ") {
                d.last_reset_reason = Some(trimmed[pos + 7..].trim().to_string());
            }
        }
        if trimmed.contains("BGP notifications sent") || trimmed.contains("notifications sent") {
            let nums: Vec<u32> = trimmed
                .split(|c: char| !c.is_ascii_digit())
                .filter(|s| !s.is_empty())
                .filter_map(|s| s.parse().ok())
                .collect();
            if nums.len() >= 2 {
                d.notifs_sent = nums[0];
                d.notifs_rcvd = nums[1];
            }
        }
        if trimmed.starts_with("BFD") {
            let lower = trimmed.to_lowercase();
            if let Some(pos) = lower.find("state") {
                let rest = trimmed[pos + 5..].trim_start_matches([':', ' ']);
                if let Some(word) = rest.split_whitespace().next() {
                    let s = word.trim_end_matches(',');
                    if !s.is_empty() {
                        d.bfd_state = Some(s.to_string());
                    }
                }
            }
        }
    }
    d
}

pub(crate) fn extract_route_map_name(line: &str) -> Option<String> {
    if let Some(pos) = line.find(" is ") {
        let rest = &line[pos + 4..];
        let name = rest.split_whitespace().next()?.trim_end_matches(',');
        if name != "(none)" && !name.is_empty() {
            return Some(name.to_string());
        }
    }
    None
}

pub(crate) fn parse_all_neighbor_details(output: &str) -> HashMap<IpAddr, NeighborDetail> {
    let mut map = HashMap::new();
    let mut current_ip: Option<IpAddr> = None;
    let mut block = String::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("BGP neighbor is ") {
            if let Some(ip) = current_ip.take() {
                map.insert(ip, parse_neighbor_detail(&block));
                block.clear();
            }
            let ip_str = rest.split(&[',', ' ']).next().unwrap_or("");
            current_ip = ip_str.parse().ok();
        }
        block.push_str(line);
        block.push('\n');
    }
    if let Some(ip) = current_ip {
        map.insert(ip, parse_neighbor_detail(&block));
    }
    map
}

// ─── BGP table parser (`show ip bgp`) ────────────────────────────────────────

pub(crate) fn parse_bgp_table(output: &str) -> Vec<BgpRoute> {
    let mut routes = Vec::new();
    let mut prev_network: Option<String> = None;

    for line in output.lines() {
        if line.trim().is_empty()
            || line.contains("Network")
            || line.starts_with("BGP")
            || line.starts_with("Total")
        {
            continue;
        }

        let chars: Vec<char> = line.chars().collect();
        if chars.is_empty() {
            continue;
        }

        let (status, rest_start) = parse_status_flags(&chars);

        let rest = &line[rest_start..];
        let rest_trimmed = rest.trim();
        if rest_trimmed.is_empty() {
            continue;
        }

        let tokens: Vec<&str> = rest_trimmed.split_whitespace().collect();

        if tokens.is_empty() {
            continue;
        }

        let (network, tok_start) = if looks_like_prefix(tokens[0]) {
            prev_network = Some(tokens[0].to_string());
            (tokens[0].to_string(), 1)
        } else if let Some(n) = &prev_network {
            (n.clone(), 0)
        } else {
            continue;
        };

        let remaining = &tokens[tok_start..];
        if remaining.is_empty() {
            continue;
        }

        let next_hop = remaining.first().copied().unwrap_or("0.0.0.0").to_string();
        let mut idx = 1usize;

        let metric = remaining.get(idx).and_then(|s| s.parse::<u32>().ok());
        if metric.is_some() {
            idx += 1;
        }

        let local_pref = remaining.get(idx).and_then(|s| s.parse::<u32>().ok());
        if local_pref.is_some() {
            idx += 1;
        }

        let weight = remaining
            .get(idx)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        if remaining
            .get(idx)
            .and_then(|s| s.parse::<u32>().ok())
            .is_some()
        {
            idx += 1;
        }

        let origin_token = remaining.last().copied().unwrap_or("?");
        let origin = match origin_token {
            "i" => RouteOrigin::Igp,
            "e" => RouteOrigin::Egp,
            _ => RouteOrigin::Incomplete,
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
    let skip = chars
        .iter()
        .take(4)
        .take_while(|&&c| !c.is_alphanumeric() || c == '>')
        .count();
    (status, skip)
}

fn looks_like_prefix(s: &str) -> bool {
    let base = s.split('/').next().unwrap_or("");
    base.split('.').count() == 4 && base.split('.').all(|o| o.parse::<u8>().is_ok())
}

// ─── Route-map / prefix-list / community-list parsers ─────────────────────────

pub(crate) fn parse_route_map_entries(output: &str) -> Vec<crate::bgp::RouteMapEntry> {
    use crate::bgp::RouteMapEntry;
    let mut entries: Vec<RouteMapEntry> = vec![];
    let mut current: Option<RouteMapEntry> = None;
    let mut in_match = false;
    let mut in_set = false;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("route-map ") && trimmed.contains("sequence") {
            if let Some(e) = current.take() {
                entries.push(e);
            }
            let parts: Vec<&str> = trimmed.splitn(4, ',').collect();
            let action = parts.get(1).unwrap_or(&" permit").trim().to_string();
            let seq: u32 = parts
                .get(2)
                .and_then(|p| p.trim().strip_prefix("sequence "))
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            current = Some(RouteMapEntry {
                sequence: seq,
                action,
                ..Default::default()
            });
            in_match = false;
            in_set = false;
            continue;
        }
        if current.is_none() {
            continue;
        }
        if trimmed == "Match clauses:" {
            in_match = true;
            in_set = false;
            continue;
        }
        if trimmed == "Set clauses:" {
            in_set = true;
            in_match = false;
            continue;
        }
        if trimmed == "Call clause:" {
            in_match = false;
            in_set = false;
            continue;
        }
        if trimmed.is_empty() || trimmed == "INACTIVE" {
            continue;
        }
        if let Some(ref mut e) = current {
            if in_match {
                e.match_clauses.push(trimmed.to_string());
            } else if in_set {
                e.set_clauses.push(trimmed.to_string());
            }
        }
    }
    if let Some(e) = current {
        entries.push(e);
    }
    entries
}

pub(crate) fn parse_prefix_list_entries(output: &str) -> Vec<crate::bgp::PrefixListEntry> {
    use crate::bgp::PrefixListEntry;
    let mut entries = vec![];
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(seq_pos) = parts.iter().position(|&p| p == "seq") {
            if let (Some(&seq_s), Some(&action), Some(&prefix)) = (
                parts.get(seq_pos + 1),
                parts.get(seq_pos + 2),
                parts.get(seq_pos + 3),
            ) {
                if action == "permit" || action == "deny" {
                    let mut pfx = prefix.to_string();
                    if let (Some(&qual), Some(&num)) =
                        (parts.get(seq_pos + 4), parts.get(seq_pos + 5))
                    {
                        if qual == "le" || qual == "ge" {
                            pfx = format!("{pfx} {qual} {num}");
                        }
                    }
                    entries.push(PrefixListEntry {
                        seq: seq_s.parse().unwrap_or(0),
                        action: action.to_string(),
                        prefix: pfx,
                    });
                }
            }
        }
    }
    entries
}

pub(crate) fn parse_community_list_entries(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|l| l.contains("permit") || l.contains("deny"))
        .map(|l| l.trim().to_string())
        .collect()
}
