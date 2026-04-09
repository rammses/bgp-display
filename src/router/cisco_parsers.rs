// Cisco / FRRouting BGP output parsers.
//
// Standalone parser functions extracted from cisco.rs.
// These parse `show ip bgp neighbors`, `show ip bgp`, route-map,
// prefix-list, and community-list output.

#![allow(dead_code)]

use crate::bgp::{BgpRoute, PrefixListEntry, RouteMapEntry, RouteOrigin, RouteStatus};
use std::collections::HashMap;
use std::net::IpAddr;

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
        let as_path: Vec<u32> = if idx < as_path_end {
            remaining[idx..as_path_end]
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect()
        } else {
            vec![]
        };

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

pub(crate) fn parse_route_map_entries(output: &str) -> Vec<RouteMapEntry> {
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

pub(crate) fn parse_prefix_list_entries(output: &str) -> Vec<PrefixListEntry> {
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
