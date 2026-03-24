use crate::bgp::naming::PolicyNames;
use crate::bgp::{
    AddressFamily, CommunityListEntry, NeighborDraft, PrefixListEntry, RouteMapEntry,
};

pub(super) fn cisco_create(
    draft: &NeighborDraft,
    local_as: u32,
    names: &PolicyNames,
) -> Vec<String> {
    let ip = &draft.neighbor_ip;
    let is_v6 = draft.address_family == AddressFamily::Ipv6Unicast;
    let mut cmds = vec![format!("router bgp {local_as}")];

    cmds.push(format!(" neighbor {ip} remote-as {}", draft.remote_as));
    cmds.push(format!(" neighbor {ip} description {}", draft.description));

    if !draft.update_source.is_empty() {
        cmds.push(format!(
            " neighbor {ip} update-source {}",
            draft.update_source
        ));
    }

    let hold: u16 = draft.hold_time.parse().unwrap_or(180);
    let keep: u16 = draft.keepalive.parse().unwrap_or(60);
    if hold != 180 || keep != 60 {
        cmds.push(format!(" neighbor {ip} timers {keep} {hold}"));
    }
    if !draft.password.is_empty() {
        cmds.push(format!(" neighbor {ip} password {}", draft.password));
    }
    if draft.bfd {
        cmds.push(format!(" neighbor {ip} bfd"));
    }

    if is_v6 {
        cmds.push(" address-family ipv6 unicast".to_string());
        cmds.push(format!("  neighbor {ip} activate"));
    }
    if draft.next_hop_self {
        if is_v6 {
            cmds.push(format!("  neighbor {ip} next-hop-self"));
        } else {
            cmds.push(format!(" neighbor {ip} next-hop-self"));
        }
    }
    if draft.route_reflector_client {
        if is_v6 {
            cmds.push(format!("  neighbor {ip} route-reflector-client"));
        } else {
            cmds.push(format!(" neighbor {ip} route-reflector-client"));
        }
    }
    if draft.soft_reconfiguration_inbound {
        if is_v6 {
            cmds.push(format!("  neighbor {ip} soft-reconfiguration inbound"));
        } else {
            cmds.push(format!(" neighbor {ip} soft-reconfiguration inbound"));
        }
    }

    let max_pfx: Option<u32> = draft.maximum_prefix.trim().parse().ok();
    if let Some(n) = max_pfx {
        let warn = if draft.maximum_prefix_warning {
            " warning-only"
        } else {
            ""
        };
        if is_v6 {
            cmds.push(format!("  neighbor {ip} maximum-prefix {n}{warn}"));
        } else {
            cmds.push(format!(" neighbor {ip} maximum-prefix {n}{warn}"));
        }
    }

    let weight_val: Option<u32> = draft.weight.trim().parse().ok();
    if let Some(w) = weight_val {
        if is_v6 {
            cmds.push(format!("  neighbor {ip} weight {w}"));
        } else {
            cmds.push(format!(" neighbor {ip} weight {w}"));
        }
    }

    if is_v6 {
        cmds.push(format!("  neighbor {ip} route-map {} in", names.rm_in));
        cmds.push(format!("  neighbor {ip} route-map {} out", names.rm_out));
        cmds.push(" exit-address-family".into());
    } else {
        cmds.push(format!(" neighbor {ip} route-map {} in", names.rm_in));
        cmds.push(format!(" neighbor {ip} route-map {} out", names.rm_out));
    }
    cmds.push("exit".into());

    cmds.push(format!("route-map {} deny 10", names.rm_in));
    let lp_val: Option<u32> = draft.default_local_pref.trim().parse().ok();
    if let Some(lp) = lp_val {
        cmds.push(format!(" set local-preference {lp}"));
    }
    cmds.push("exit".into());
    cmds.push(format!("route-map {} deny 10", names.rm_out));
    cmds.push("exit".into());

    let pl_cmd = if is_v6 {
        "ipv6 prefix-list"
    } else {
        "ip prefix-list"
    };
    let deny_prefix = if is_v6 {
        "::/0 le 128"
    } else {
        "0.0.0.0/0 le 32"
    };
    cmds.push(format!("{pl_cmd} {} deny {deny_prefix}", names.pl_in));
    cmds.push(format!("{pl_cmd} {} deny {deny_prefix}", names.pl_out));

    cmds
}

pub(super) fn cisco_routemap_save(name: &str, entries: &[RouteMapEntry]) -> Vec<String> {
    let mut cmds = vec![format!("no route-map {name}")];
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

pub(super) fn cisco_prefixlist_save(name: &str, entries: &[PrefixListEntry]) -> Vec<String> {
    let mut cmds = vec![format!("no ip prefix-list {name}")];
    for e in entries {
        cmds.push(format!(
            "ip prefix-list {name} seq {} {} {}",
            e.seq, e.action, e.prefix
        ));
    }
    cmds
}

pub(super) fn cisco_communitylist_save(name: &str, entries: &[CommunityListEntry]) -> Vec<String> {
    let mut cmds = vec![format!("no ip community-list standard {name}")];
    for e in entries {
        cmds.push(format!(
            "ip community-list standard {name} {} {}",
            e.action, e.community
        ));
    }
    cmds
}
