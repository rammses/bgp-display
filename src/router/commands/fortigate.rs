use crate::bgp::naming::PolicyNames;
use crate::bgp::{CommunityListEntry, NeighborDraft, PrefixListEntry, RouteMapEntry};

pub(super) fn fortigate_create(draft: &NeighborDraft, names: &PolicyNames) -> Vec<String> {
    let ip = &draft.neighbor_ip;
    let mut cmds = vec![
        "config router bgp".into(),
        "config neighbor".into(),
        format!("edit {ip}"),
        format!("set remote-as {}", draft.remote_as),
        format!("set description \"{}\"", draft.description),
    ];

    if !draft.update_source.is_empty() {
        cmds.push(format!("set update-source {}", draft.update_source));
    }
    if draft.next_hop_self {
        cmds.push("set next-hop-self enable".into());
    }
    if draft.route_reflector_client {
        cmds.push("set route-reflector-client enable".into());
    }

    let hold: u16 = draft.hold_time.parse().unwrap_or(180);
    let keep: u16 = draft.keepalive.parse().unwrap_or(60);
    cmds.push(format!("set holdtime-timer {hold}"));
    cmds.push(format!("set keep-alive-timer {keep}"));

    if !draft.password.is_empty() {
        cmds.push(format!("set password \"{}\"", draft.password));
    }
    if draft.bfd {
        cmds.push("set bfd enable".into());
    }
    if draft.soft_reconfiguration_inbound {
        cmds.push("set soft-reconfiguration enable".into());
    }

    let max_pfx: Option<u32> = draft.maximum_prefix.trim().parse().ok();
    if let Some(n) = max_pfx {
        cmds.push(format!("set prefix-list-in-max {n}"));
    }

    let weight_val: Option<u32> = draft.weight.trim().parse().ok();
    if let Some(w) = weight_val {
        cmds.push(format!("set weight {w}"));
    }

    cmds.push(format!("set route-map-in {}", names.rm_in));
    cmds.push(format!("set route-map-out {}", names.rm_out));
    cmds.push("next".into());
    cmds.push("end".into());
    cmds.push("end".into());

    cmds.push("config router route-map".into());
    cmds.push(format!("edit {}", names.rm_in));
    cmds.push("config rule".into());
    cmds.push("edit 10".into());
    cmds.push("set action deny".into());
    cmds.push("next".into());
    cmds.push("end".into());
    cmds.push("next".into());
    cmds.push("end".into());

    cmds.push("config router route-map".into());
    cmds.push(format!("edit {}", names.rm_out));
    cmds.push("config rule".into());
    cmds.push("edit 10".into());
    cmds.push("set action deny".into());
    cmds.push("next".into());
    cmds.push("end".into());
    cmds.push("next".into());
    cmds.push("end".into());

    cmds.push("config router prefix-list".into());
    cmds.push(format!("edit {}", names.pl_in));
    cmds.push("config rule".into());
    cmds.push("edit 10".into());
    cmds.push("set action deny".into());
    cmds.push("set prefix 0.0.0.0 0.0.0.0".into());
    cmds.push("set le 32".into());
    cmds.push("next".into());
    cmds.push("end".into());
    cmds.push("next".into());
    cmds.push("end".into());

    cmds.push("config router prefix-list".into());
    cmds.push(format!("edit {}", names.pl_out));
    cmds.push("config rule".into());
    cmds.push("edit 10".into());
    cmds.push("set action deny".into());
    cmds.push("set prefix 0.0.0.0 0.0.0.0".into());
    cmds.push("set le 32".into());
    cmds.push("next".into());
    cmds.push("end".into());
    cmds.push("next".into());
    cmds.push("end".into());

    cmds
}

pub(super) fn fortigate_routemap_save(name: &str, entries: &[RouteMapEntry]) -> Vec<String> {
    let mut cmds = vec![
        "config router route-map".into(),
        format!("edit {name}"),
        "config rule".into(),
        "purge".into(),
    ];
    for e in entries {
        cmds.push(format!("edit {}", e.sequence));
        cmds.push(format!("set action {}", e.action));
        for m in &e.match_clauses {
            cmds.push(format!("set match-{m}"));
        }
        for s in &e.set_clauses {
            cmds.push(format!("set set-{s}"));
        }
        cmds.push("next".into());
    }
    cmds.push("end".into());
    cmds.push("next".into());
    cmds.push("end".into());
    cmds
}

pub(super) fn fortigate_prefixlist_save(name: &str, entries: &[PrefixListEntry]) -> Vec<String> {
    let mut cmds = vec![
        "config router prefix-list".into(),
        format!("edit {name}"),
        "config rule".into(),
        "purge".into(),
    ];
    for e in entries {
        cmds.push(format!("edit {}", e.seq));
        cmds.push(format!("set action {}", e.action));
        let parts: Vec<&str> = e.prefix.split_whitespace().collect();
        if let Some(pfx) = parts.first() {
            if let Some((net, mask)) = pfx.split_once('/') {
                let bits: u8 = mask.parse().unwrap_or(0);
                let netmask = prefix_to_netmask(bits);
                cmds.push(format!("set prefix {net} {netmask}"));
            }
        }
        for chunk in parts.chunks(2) {
            if chunk.len() == 2 && chunk[0] == "le" {
                cmds.push(format!("set le {}", chunk[1]));
            }
            if chunk.len() == 2 && chunk[0] == "ge" {
                cmds.push(format!("set ge {}", chunk[1]));
            }
        }
        cmds.push("next".into());
    }
    cmds.push("end".into());
    cmds.push("next".into());
    cmds.push("end".into());
    cmds
}

pub(super) fn fortigate_communitylist_save(
    name: &str,
    entries: &[CommunityListEntry],
) -> Vec<String> {
    let mut cmds = vec![
        "config router community-list".into(),
        format!("edit {name}"),
        "config rule".into(),
        "purge".into(),
    ];
    for e in entries {
        cmds.push(format!("edit {}", e.seq));
        cmds.push(format!("set action {}", e.action));
        cmds.push(format!("set match '{}'", e.community));
        cmds.push("next".into());
    }
    cmds.push("end".into());
    cmds.push("next".into());
    cmds.push("end".into());
    cmds
}

fn prefix_to_netmask(bits: u8) -> String {
    if bits > 32 {
        return "255.255.255.255".to_string();
    }
    let mask: u32 = if bits == 0 { 0 } else { !0u32 << (32 - bits) };
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF,
    )
}
