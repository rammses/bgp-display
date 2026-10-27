//! Cumulus Linux 5.x backend.  FRR is queried through `vtysh`; configuration
//! changes use NVUE so they survive later `nv config apply` operations.

use crate::bgp::{BgpRoute, BgpSummary, PeerRouteDirection};
use crate::router::cisco::{
    parse_bgp_table, parse_community_list_entries, parse_neighbor_detail,
    parse_prefix_list_entries, parse_route_map_entries,
};
use crate::router::{ConnectionStatus, RouterConfig};
use crate::ssh::SshSessionManager;
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

pub struct CumulusBackend {
    config: RouterConfig,
    ssh: Arc<SshSessionManager>,
    status: ConnectionStatus,
}

impl CumulusBackend {
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

    async fn vtysh_run(&self, frr_cmd: &str) -> Result<String> {
        let quoted = shell_quote(frr_cmd);
        let direct = format!("vtysh -c {quoted}");
        match self.ssh.run_cmd(self.config.id, &direct).await {
            Ok(out) if !frr_error(&out) => Ok(out),
            _ => {
                let sudo = format!("sudo -n vtysh -c {quoted}");
                let out = self.ssh.run_cmd(self.config.id, &sudo).await?;
                if frr_error(&out) {
                    bail!("FRR rejected command: {frr_cmd}");
                }
                Ok(out)
            }
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        self.status = ConnectionStatus::Connecting;
        match self.ssh.run_cmd(self.config.id, "echo ok").await {
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

    pub async fn disconnect(&mut self) -> Result<()> {
        self.status = ConnectionStatus::Disconnected;
        Ok(())
    }

    pub async fn refresh(&mut self) -> Result<BgpSummary> {
        let mut summary: Option<BgpSummary> = None;
        for command in [
            "show ip bgp summary",
            "show bgp ipv4 unicast summary",
            "show bgp ipv6 unicast summary",
        ] {
            if let Ok(out) = self.vtysh_run(command).await {
                if out.contains("BGP router identifier") {
                    let parsed = crate::bgp::parse_bgp_summary(&out);
                    if let Some(existing) = &mut summary {
                        existing.table_version = existing.table_version.max(parsed.table_version);
                        for peer in parsed.peers {
                            if !existing
                                .peers
                                .iter()
                                .any(|p| p.neighbor_ip == peer.neighbor_ip)
                            {
                                existing.peers.push(peer);
                            }
                        }
                    } else {
                        summary = Some(parsed);
                    }
                }
            }
        }
        let mut summary = summary.context("Cumulus FRR did not return a BGP summary")?;

        if let Ok(details) = self.vtysh_run("show ip bgp neighbors").await {
            let detail_map = parse_details(&details);
            for peer in &mut summary.peers {
                if let Some(detail) = detail_map.get(&peer.neighbor_ip) {
                    peer.description = detail.description.clone();
                    peer.route_map_in = detail.route_map_in.clone();
                    peer.route_map_out = detail.route_map_out.clone();
                    peer.next_hop_self = detail.next_hop_self;
                    peer.route_reflector_client = detail.route_reflector_client;
                    peer.update_source = detail.update_source;
                    peer.password_configured = detail.password_configured;
                    if detail.hold_time > 0 {
                        peer.hold_time = detail.hold_time;
                    }
                    if detail.keepalive > 0 {
                        peer.keepalive = detail.keepalive;
                    }
                }
            }
        }
        self.status = ConnectionStatus::Connected;
        Ok(summary)
    }

    pub async fn get_routes(&mut self) -> Result<Vec<BgpRoute>> {
        let mut routes = Vec::new();
        for command in ["show bgp ipv4 unicast", "show bgp ipv6 unicast"] {
            if let Ok(out) = self.vtysh_run(command).await {
                if out.contains("BGP table version") || out.contains("Status codes") {
                    routes.extend(parse_bgp_table(&out));
                }
            }
        }
        Ok(routes)
    }

    pub async fn get_peer_routes(
        &self,
        peer_id: &str,
        direction: PeerRouteDirection,
    ) -> Result<Vec<BgpRoute>> {
        if !valid_neighbor_id(peer_id) {
            bail!("invalid Cumulus neighbor identifier");
        }
        let suffix = match direction {
            PeerRouteDirection::Received => "routes",
            PeerRouteDirection::Advertised => "advertised-routes",
        };
        let mut succeeded = false;
        let mut last_error = None;
        let mut all_routes = Vec::new();
        for family in ["ipv4", "ipv6"] {
            let command = format!("show bgp {family} unicast neighbors {peer_id} {suffix}");
            match self.vtysh_run(&command).await {
                Ok(out) => {
                    succeeded = true;
                    all_routes.extend(parse_bgp_table(&out));
                }
                Err(error) => last_error = Some(error),
            }
        }
        if succeeded {
            Ok(all_routes)
        } else {
            Err(last_error.context("Cumulus peer route commands failed")?)
        }
    }

    pub async fn ping_mtu(&self, target: IpAddr) -> Result<u16> {
        for payload in [1472u16, 1402, 548] {
            let command = format!("ping -c 3 -M do -s {payload} {target}");
            if let Ok(out) = self.ssh.run_cmd(self.config.id, &command).await {
                if out.contains(" 0% packet loss") || out.contains("bytes from") {
                    return Ok(payload + 28);
                }
            }
        }
        Ok(0)
    }

    /// Execute a batch through stdin so credentials in NVUE commands never
    /// appear in the SSH command log.  The success marker compensates for the
    /// transport's behavior of returning stdout from failed shell scripts.
    pub async fn write_config(&self, commands: &[String]) -> Result<()> {
        if commands.is_empty() {
            bail!("Cumulus action is unsupported or has no NVUE commands");
        }
        for command in commands {
            if !(command.starts_with("nv set ") || command.starts_with("nv unset "))
                || command.contains(['\n', '\r'])
            {
                bail!("Cumulus requires NVUE configuration commands");
            }
        }

        let pending = self
            .ssh
            .run_cmd(self.config.id, "nv config diff applied pending -o commands")
            .await
            .context("checking Cumulus pending NVUE changes")?;
        let pending = pending.trim();
        if !pending.is_empty() && !matches!(pending, "[]" | "{}" | "null" | "No differences") {
            bail!("Cumulus has pending NVUE changes; apply or discard them before this operation");
        }

        let legacy = self.is_legacy_5x().await?;
        let marker = format!("__BGP_LM_NVUE_OK_{}__", uuid::Uuid::new_v4().simple());
        let mut script = String::from("set -e\n");
        for command in commands {
            let adjusted = if legacy {
                command
                    .replace(" shutdown enabled", " shutdown on")
                    .replace(" shutdown disabled", " shutdown off")
                    .replace(
                        " route-reflector-client enabled",
                        " route-reflector-client on",
                    )
                    .replace(" soft-reconfiguration enabled", " soft-reconfiguration on")
                    .replace(" warning-only enabled", " warning-only on")
                    .replace(" state enabled", " enable on")
                    .replace(" state disabled", " enable off")
            } else {
                command.clone()
            };
            script.push_str(&adjusted);
            script.push('\n');
        }
        script.push_str("nv config apply --y\nnv config save\n");
        script.push_str(&format!("printf '%s\\n' '{marker}'\n"));
        let output = self
            .ssh
            .run_piped_with_timeout(self.config.id, &script, std::time::Duration::from_secs(120))
            .await
            .context("Cumulus NVUE command batch failed")?;
        if !output.lines().any(|line| line.trim() == marker) {
            bail!("Cumulus NVUE did not confirm configuration apply");
        }
        Ok(())
    }

    async fn is_legacy_5x(&self) -> Result<bool> {
        let out = self
            .ssh
            .run_cmd(self.config.id, "cat /etc/os-release")
            .await
            .context("reading Cumulus version")?;
        let version = out.lines().find_map(|line| {
            line.strip_prefix("VERSION_ID=")
                .map(|value| value.trim_matches('"'))
        });
        let version = version.context("Cumulus VERSION_ID is missing")?;
        let mut parts = version.split('.');
        if parts.next() != Some("5") {
            bail!("Cumulus backend requires Linux version 5.x, found {version}");
        }
        let minor = parts
            .next()
            .context("Cumulus minor version is missing")?
            .parse::<u32>()
            .context("invalid Cumulus minor version")?;
        Ok(minor <= 14)
    }

    pub async fn apply_config(&mut self, _config: &str) -> Result<()> {
        bail!("free-form configuration is unsupported for Cumulus NVUE")
    }

    pub async fn fetch_route_map_detail(&self, name: &str) -> Result<crate::bgp::RouteMapDetail> {
        use crate::bgp::{PrefixListEntry, RouteMapDetail};
        if !valid_policy_name(name) {
            bail!("invalid route-map name");
        }
        let raw = self.vtysh_run(&format!("show route-map {name}")).await?;
        let entries = parse_route_map_entries(&raw);
        let mut prefix_lists: HashMap<String, Vec<PrefixListEntry>> = HashMap::new();
        let mut community_lists: HashMap<String, Vec<String>> = HashMap::new();
        for entry in &entries {
            for clause in &entry.match_clauses {
                if clause.contains("prefix-list") {
                    if let Some((_, value)) = clause.split_once(':') {
                        for list_name in value.split_whitespace().filter(|s| valid_policy_name(s)) {
                            let out = self
                                .vtysh_run(&format!("show ip prefix-list {list_name}"))
                                .await?;
                            prefix_lists
                                .insert(list_name.to_string(), parse_prefix_list_entries(&out));
                        }
                    }
                }
                if clause.starts_with("community") {
                    if let Some((_, value)) = clause.split_once(':') {
                        for list_name in value.split_whitespace().filter(|s| valid_policy_name(s)) {
                            let out = self
                                .vtysh_run(&format!("show ip community-list {list_name}"))
                                .await?;
                            community_lists
                                .insert(list_name.to_string(), parse_community_list_entries(&out));
                        }
                    }
                }
            }
        }
        Ok(RouteMapDetail {
            name: name.to_string(),
            entries,
            prefix_lists,
            community_lists,
        })
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn frr_error(output: &str) -> bool {
    output.lines().any(|line| {
        let line = line.trim();
        line.starts_with("% Unknown command")
            || line.starts_with("% Command incomplete")
            || line.starts_with("% Invalid")
            || line.starts_with("% No such")
    })
}

fn valid_neighbor_id(id: &str) -> bool {
    if id.parse::<IpAddr>().is_ok() {
        return true;
    }
    let mut chars = id.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn valid_policy_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn summary_neighbor_id(token: &str) -> Option<String> {
    let token = token.trim_end_matches(',');
    let id = token
        .rfind('(')
        .and_then(|open| {
            token
                .strip_suffix(')')
                .map(|_| &token[open + 1..token.len() - 1])
        })
        .unwrap_or(token);
    valid_neighbor_id(id).then(|| id.to_string())
}

fn parse_details(output: &str) -> HashMap<String, crate::router::cisco::NeighborDetail> {
    let mut details = HashMap::new();
    let mut current = None;
    let mut block = String::new();
    for line in output.lines() {
        if let Some(rest) = line.trim().strip_prefix("BGP neighbor is ") {
            if let Some(id) = current.take() {
                details.insert(id, parse_neighbor_detail(&block));
                block.clear();
            }
            current = rest.split([',', ' ']).next().and_then(summary_neighbor_id);
        }
        block.push_str(line);
        block.push('\n');
    }
    if let Some(id) = current {
        details.insert(id, parse_neighbor_detail(&block));
    }
    details
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_blocks_use_interface_neighbor_key() {
        let output = "BGP neighbor is spine01(swp51), remote AS 65199\n  Description: SPINE01\nBGP neighbor is 10.0.0.2, remote AS 65200\n  Description: TRANSIT\n";
        let details = parse_details(output);
        assert_eq!(
            details.get("swp51").and_then(|d| d.description.as_deref()),
            Some("SPINE01")
        );
        assert_eq!(
            details
                .get("10.0.0.2")
                .and_then(|d| d.description.as_deref()),
            Some("TRANSIT")
        );
    }

    #[test]
    fn frr_ipv6_route_table_parses_prefixes() {
        let output = "BGP table version is 4, local router ID is 10.0.0.1\n\
Status codes: * valid, > best\n\
   Network          Next Hop            Metric LocPrf Weight Path\n\
*> 2001:db8::/64    fe80::1                  0    100      0 65199 i\n";
        let routes = parse_bgp_table(output);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].network, "2001:db8::/64");
    }
}
