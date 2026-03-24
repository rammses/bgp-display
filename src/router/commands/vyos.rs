use crate::bgp::naming::PolicyNames;
use crate::bgp::{AddressFamily, CommunityListEntry, NeighborDraft, PrefixListEntry, RouteMapEntry};

pub(super) fn vyos_create(draft: &NeighborDraft, _local_as: u32, names: &PolicyNames) -> Vec<String> {
    let ip = &draft.neighbor_ip;
    let is_v6 = draft.address_family == AddressFamily::Ipv6Unicast;
    let af = if is_v6 {
        "ipv6-unicast"
    } else {
        "ipv4-unicast"
    };
    let base = format!("set protocols bgp neighbor {ip}");
    let mut cmds = vec![
        format!("{base} remote-as {}", draft.remote_as),
        format!("{base} description '{}'", draft.description),
    ];

    if !draft.update_source.is_empty() {
        cmds.push(format!("{base} update-source {}", draft.update_source));
    }
    if draft.next_hop_self {
        cmds.push(format!("{base} address-family {af} nexthop-self"));
    }
    if draft.route_reflector_client {
        cmds.push(format!("{base} address-family {af} route-reflector-client"));
    }

    let hold: u16 = draft.hold_time.parse().unwrap_or(180);
    let keep: u16 = draft.keepalive.parse().unwrap_or(60);
    if hold != 180 || keep != 60 {
        cmds.push(format!("{base} timers holdtime {hold}"));
        cmds.push(format!("{base} timers keepalive {keep}"));
    }
    if !draft.password.is_empty() {
        cmds.push(format!("{base} password '{}'", draft.password));
    }
    if draft.bfd {
        cmds.push(format!("{base} bfd"));
    }
    if draft.soft_reconfiguration_inbound {
        cmds.push(format!(
            "{base} address-family {af} soft-reconfiguration inbound"
        ));
    }

    let max_pfx: Option<u32> = draft.maximum_prefix.trim().parse().ok();
    if let Some(n) = max_pfx {
        cmds.push(format!("{base} address-family {af} maximum-prefix {n}"));
    }

    let weight_val: Option<u32> = draft.weight.trim().parse().ok();
    if let Some(w) = weight_val {
        cmds.push(format!("{base} address-family {af} weight {w}"));
    }

    let lp_val: Option<u32> = draft.default_local_pref.trim().parse().ok();
    if let Some(lp) = lp_val {
        cmds.push(format!(
            "{base} address-family {af} default-local-pref {lp}"
        ));
    }

    cmds.push(format!(
        "{base} address-family {af} route-map import {}",
        names.rm_in
    ));
    cmds.push(format!(
        "{base} address-family {af} route-map export {}",
        names.rm_out
    ));

    cmds.push(format!(
        "set policy route-map {} rule 10 action deny",
        names.rm_in
    ));
    cmds.push(format!(
        "set policy route-map {} rule 10 action deny",
        names.rm_out
    ));

    let pl_type = if is_v6 { "prefix-list6" } else { "prefix-list" };
    let deny_pfx = if is_v6 { "::/0" } else { "0.0.0.0/0" };
    let deny_le = if is_v6 { "128" } else { "32" };
    cmds.push(format!(
        "set policy {pl_type} {} rule 10 action deny",
        names.pl_in
    ));
    cmds.push(format!(
        "set policy {pl_type} {} rule 10 prefix {deny_pfx}",
        names.pl_in
    ));
    cmds.push(format!(
        "set policy {pl_type} {} rule 10 le {deny_le}",
        names.pl_in
    ));
    cmds.push(format!(
        "set policy {pl_type} {} rule 10 action deny",
        names.pl_out
    ));
    cmds.push(format!(
        "set policy {pl_type} {} rule 10 prefix {deny_pfx}",
        names.pl_out
    ));
    cmds.push(format!(
        "set policy {pl_type} {} rule 10 le {deny_le}",
        names.pl_out
    ));

    cmds
}

pub(super) fn vyos_routemap_save(name: &str, entries: &[RouteMapEntry]) -> Vec<String> {
    let mut cmds = vec![format!("delete policy route-map {name}")];
    for e in entries {
        let base = format!("set policy route-map {name} rule {}", e.sequence);
        cmds.push(format!("{base} action {}", e.action));
        for m in &e.match_clauses {
            cmds.push(format!("{base} match {m}"));
        }
        for s in &e.set_clauses {
            cmds.push(format!("{base} set {s}"));
        }
    }
    cmds
}

pub(super) fn vyos_prefixlist_save(name: &str, entries: &[PrefixListEntry]) -> Vec<String> {
    let mut cmds = vec![format!("delete policy prefix-list {name}")];
    for e in entries {
        let base = format!("set policy prefix-list {name} rule {}", e.seq);
        cmds.push(format!("{base} action {}", e.action));
        let parts: Vec<&str> = e.prefix.split_whitespace().collect();
        if let Some(pfx) = parts.first() {
            cmds.push(format!("{base} prefix {pfx}"));
        }
        for chunk in parts.chunks(2) {
            if chunk.len() == 2 && (chunk[0] == "le" || chunk[0] == "ge") {
                cmds.push(format!("{base} {} {}", chunk[0], chunk[1]));
            }
        }
    }
    cmds
}

pub(super) fn vyos_communitylist_save(name: &str, entries: &[CommunityListEntry]) -> Vec<String> {
    let mut cmds = vec![format!("delete policy community-list {name}")];
    for e in entries {
        let base = format!("set policy community-list {name} rule {}", e.seq);
        cmds.push(format!("{base} action {}", e.action));
        cmds.push(format!("{base} regex '{}'", e.community));
    }
    cmds
}
