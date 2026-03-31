use crate::bgp::naming::PolicyNames;
use crate::bgp::{CommunityListEntry, NeighborDraft, PrefixListEntry, RouteMapEntry};

/// A10 ACOS uses a Cisco-like CLI for BGP configuration.
/// `configure` enters config mode; `router bgp <asn>` enters BGP context.
pub(super) fn a10_create(draft: &NeighborDraft, local_as: u32, names: &PolicyNames) -> Vec<String> {
    let ip = &draft.neighbor_ip;
    let mut cmds = vec![
        format!("router bgp {local_as}"),
        format!(" neighbor {ip} remote-as {}", draft.remote_as),
        format!(" neighbor {ip} description {}", draft.description),
    ];

    if !draft.update_source.is_empty() {
        cmds.push(format!(
            " neighbor {ip} update-source {}",
            draft.update_source
        ));
    }
    if draft.next_hop_self {
        cmds.push(format!(" neighbor {ip} next-hop-self"));
    }
    if draft.route_reflector_client {
        cmds.push(format!(" neighbor {ip} route-reflector-client"));
    }

    let hold: u16 = draft.hold_time.parse().unwrap_or(180);
    let keep: u16 = draft.keepalive.parse().unwrap_or(60);
    cmds.push(format!(" neighbor {ip} timers {keep} {hold}"));

    if !draft.password.is_empty() {
        cmds.push(format!(" neighbor {ip} password {}", draft.password));
    }
    if draft.bfd {
        cmds.push(format!(" neighbor {ip} bfd"));
    }
    if draft.soft_reconfiguration_inbound {
        cmds.push(format!(" neighbor {ip} soft-reconfiguration inbound"));
    }

    let max_pfx: Option<u32> = draft.maximum_prefix.trim().parse().ok();
    if let Some(n) = max_pfx {
        cmds.push(format!(" neighbor {ip} maximum-prefix {n}"));
    }

    let weight_val: Option<u32> = draft.weight.trim().parse().ok();
    if let Some(w) = weight_val {
        cmds.push(format!(" neighbor {ip} weight {w}"));
    }

    cmds.push(format!(" neighbor {ip} route-map {} in", names.rm_in));
    cmds.push(format!(" neighbor {ip} route-map {} out", names.rm_out));
    cmds.push("exit".into());

    // Default deny-all route-maps
    cmds.push(format!("route-map {} deny 10", names.rm_in));
    cmds.push("exit".into());
    cmds.push(format!("route-map {} deny 10", names.rm_out));
    cmds.push("exit".into());

    // Default deny-all prefix-lists
    cmds.push(format!(
        "ip prefix-list {} seq 10 deny 0.0.0.0/0 le 32",
        names.pl_in
    ));
    cmds.push(format!(
        "ip prefix-list {} seq 10 deny 0.0.0.0/0 le 32",
        names.pl_out
    ));

    cmds
}

pub(super) fn a10_routemap_save(name: &str, entries: &[RouteMapEntry]) -> Vec<String> {
    let mut cmds: Vec<String> = vec![format!("no route-map {name}")];
    for e in entries {
        cmds.push(format!("route-map {name} {} {}", e.action, e.sequence));
        for m in &e.match_clauses {
            cmds.push(format!(" match {m}"));
        }
        for s in &e.set_clauses {
            cmds.push(format!(" set {s}"));
        }
        cmds.push("exit".into());
    }
    cmds
}

pub(super) fn a10_prefixlist_save(name: &str, entries: &[PrefixListEntry]) -> Vec<String> {
    let mut cmds: Vec<String> = vec![format!("no ip prefix-list {name}")];
    for e in entries {
        let mut line = format!(
            "ip prefix-list {name} seq {} {} {}",
            e.seq, e.action, e.prefix
        );
        if let Some(ge) = extract_modifier(&e.prefix, "ge") {
            line.push_str(&format!(" ge {ge}"));
        }
        if let Some(le) = extract_modifier(&e.prefix, "le") {
            line.push_str(&format!(" le {le}"));
        }
        cmds.push(line);
    }
    cmds
}

pub(super) fn a10_communitylist_save(name: &str, entries: &[CommunityListEntry]) -> Vec<String> {
    let mut cmds: Vec<String> = vec![format!("no ip community-list standard {name}")];
    for e in entries {
        cmds.push(format!(
            "ip community-list standard {name} {} {}",
            e.action, e.community
        ));
    }
    cmds
}

fn extract_modifier(prefix_str: &str, keyword: &str) -> Option<String> {
    let parts: Vec<&str> = prefix_str.split_whitespace().collect();
    for chunk in parts.windows(2) {
        if chunk[0] == keyword {
            return Some(chunk[1].to_string());
        }
    }
    None
}
