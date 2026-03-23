use crate::bgp::naming::{generate_policy_names, PolicyNames};
use crate::bgp::{AddressFamily, CommunityListEntry, NeighborDraft, PrefixListEntry, RouteMapEntry};
use crate::router::RouterVendor;
use std::net::IpAddr;

// ─── Create neighbor ─────────────────────────────────────────────────────────

pub fn create_neighbor_commands(
    vendor: &RouterVendor,
    draft: &NeighborDraft,
    local_as: u32,
) -> Vec<String> {
    let names = generate_policy_names(&draft.description);
    match vendor {
        RouterVendor::Cisco | RouterVendor::PfSense | RouterVendor::CitrixVpx => {
            cisco_create(draft, local_as, &names)
        }
        RouterVendor::VyOs => vyos_create(draft, local_as, &names),
        RouterVendor::FortiGate => fortigate_create(draft, &names),
    }
}

fn cisco_create(draft: &NeighborDraft, local_as: u32, names: &PolicyNames) -> Vec<String> {
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
        cmds.push(format!(" address-family ipv6 unicast"));
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

    // deny-all route-maps
    cmds.push(format!("route-map {} deny 10", names.rm_in));
    let lp_val: Option<u32> = draft.default_local_pref.trim().parse().ok();
    if let Some(lp) = lp_val {
        cmds.push(format!(" set local-preference {lp}"));
    }
    cmds.push("exit".into());
    cmds.push(format!("route-map {} deny 10", names.rm_out));
    cmds.push("exit".into());

    // deny-all prefix-lists
    let pl_cmd = if is_v6 { "ipv6 prefix-list" } else { "ip prefix-list" };
    let deny_prefix = if is_v6 { "::/0 le 128" } else { "0.0.0.0/0 le 32" };
    cmds.push(format!("{pl_cmd} {} deny {deny_prefix}", names.pl_in));
    cmds.push(format!("{pl_cmd} {} deny {deny_prefix}", names.pl_out));

    cmds
}

fn vyos_create(draft: &NeighborDraft, _local_as: u32, names: &PolicyNames) -> Vec<String> {
    let ip = &draft.neighbor_ip;
    let is_v6 = draft.address_family == AddressFamily::Ipv6Unicast;
    let af = if is_v6 { "ipv6-unicast" } else { "ipv4-unicast" };
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
        cmds.push(format!(
            "{base} address-family {af} route-reflector-client"
        ));
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

    // deny-all route-maps
    cmds.push(format!(
        "set policy route-map {} rule 10 action deny",
        names.rm_in
    ));
    cmds.push(format!(
        "set policy route-map {} rule 10 action deny",
        names.rm_out
    ));

    // deny-all prefix-lists
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

fn fortigate_create(draft: &NeighborDraft, names: &PolicyNames) -> Vec<String> {
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

    // deny-all route-maps via FortiGate route-map config
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

    // deny-all prefix-lists
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

// ─── Delete neighbor ─────────────────────────────────────────────────────────

pub fn delete_neighbor_commands(
    vendor: &RouterVendor,
    neighbor_ip: IpAddr,
    local_as: u32,
    description: &str,
) -> Vec<String> {
    let names = generate_policy_names(description);
    let ip = neighbor_ip.to_string();

    match vendor {
        RouterVendor::Cisco | RouterVendor::PfSense | RouterVendor::CitrixVpx => {
            vec![
                format!("router bgp {local_as}"),
                format!(" no neighbor {ip}"),
                "exit".into(),
                format!("no route-map {}", names.rm_in),
                format!("no route-map {}", names.rm_out),
                format!("no ip prefix-list {}", names.pl_in),
                format!("no ip prefix-list {}", names.pl_out),
            ]
        }
        RouterVendor::VyOs => {
            vec![
                format!("delete protocols bgp neighbor {ip}"),
                format!("delete policy route-map {}", names.rm_in),
                format!("delete policy route-map {}", names.rm_out),
                format!("delete policy prefix-list {}", names.pl_in),
                format!("delete policy prefix-list {}", names.pl_out),
            ]
        }
        RouterVendor::FortiGate => {
            vec![
                "config router bgp".into(),
                "config neighbor".into(),
                format!("delete {ip}"),
                "end".into(),
                "end".into(),
                "config router route-map".into(),
                format!("delete {}", names.rm_in),
                "end".into(),
                "config router route-map".into(),
                format!("delete {}", names.rm_out),
                "end".into(),
                "config router prefix-list".into(),
                format!("delete {}", names.pl_in),
                "end".into(),
                "config router prefix-list".into(),
                format!("delete {}", names.pl_out),
                "end".into(),
            ]
        }
    }
}

// ─── Route-map save (replace) ───────────────────────────────────────────────

pub fn routemap_save_commands(
    vendor: &RouterVendor,
    name: &str,
    entries: &[RouteMapEntry],
) -> Vec<String> {
    match vendor {
        RouterVendor::Cisco | RouterVendor::PfSense | RouterVendor::CitrixVpx => {
            cisco_routemap_save(name, entries)
        }
        RouterVendor::VyOs => vyos_routemap_save(name, entries),
        RouterVendor::FortiGate => fortigate_routemap_save(name, entries),
    }
}

fn cisco_routemap_save(name: &str, entries: &[RouteMapEntry]) -> Vec<String> {
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

fn vyos_routemap_save(name: &str, entries: &[RouteMapEntry]) -> Vec<String> {
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

fn fortigate_routemap_save(name: &str, entries: &[RouteMapEntry]) -> Vec<String> {
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

// ─── Prefix-list save (replace) ─────────────────────────────────────────────

pub fn prefixlist_save_commands(
    vendor: &RouterVendor,
    name: &str,
    entries: &[PrefixListEntry],
) -> Vec<String> {
    match vendor {
        RouterVendor::Cisco | RouterVendor::PfSense | RouterVendor::CitrixVpx => {
            cisco_prefixlist_save(name, entries)
        }
        RouterVendor::VyOs => vyos_prefixlist_save(name, entries),
        RouterVendor::FortiGate => fortigate_prefixlist_save(name, entries),
    }
}

fn cisco_prefixlist_save(name: &str, entries: &[PrefixListEntry]) -> Vec<String> {
    let mut cmds = vec![format!("no ip prefix-list {name}")];
    for e in entries {
        cmds.push(format!(
            "ip prefix-list {name} seq {} {} {}",
            e.seq, e.action, e.prefix
        ));
    }
    cmds
}

fn vyos_prefixlist_save(name: &str, entries: &[PrefixListEntry]) -> Vec<String> {
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

fn fortigate_prefixlist_save(name: &str, entries: &[PrefixListEntry]) -> Vec<String> {
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

// ─── Community-list save (replace) ───────────────────────────────────────────

pub fn communitylist_save_commands(
    vendor: &RouterVendor,
    name: &str,
    entries: &[CommunityListEntry],
) -> Vec<String> {
    match vendor {
        RouterVendor::Cisco | RouterVendor::PfSense | RouterVendor::CitrixVpx => {
            cisco_communitylist_save(name, entries)
        }
        RouterVendor::VyOs => vyos_communitylist_save(name, entries),
        RouterVendor::FortiGate => fortigate_communitylist_save(name, entries),
    }
}

fn cisco_communitylist_save(name: &str, entries: &[CommunityListEntry]) -> Vec<String> {
    let mut cmds = vec![format!("no ip community-list standard {name}")];
    for e in entries {
        cmds.push(format!(
            "ip community-list standard {name} {} {}",
            e.action, e.community
        ));
    }
    cmds
}

fn vyos_communitylist_save(name: &str, entries: &[CommunityListEntry]) -> Vec<String> {
    let mut cmds = vec![format!("delete policy community-list {name}")];
    for e in entries {
        let base = format!("set policy community-list {name} rule {}", e.seq);
        cmds.push(format!("{base} action {}", e.action));
        cmds.push(format!("{base} regex '{}'", e.community));
    }
    cmds
}

fn fortigate_communitylist_save(name: &str, entries: &[CommunityListEntry]) -> Vec<String> {
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

// ─── Neighbor shutdown toggle ────────────────────────────────────────────────

pub fn shutdown_neighbor_commands(
    vendor: &RouterVendor,
    ip: IpAddr,
    local_as: u32,
) -> Vec<String> {
    let ip = ip.to_string();
    match vendor {
        RouterVendor::Cisco | RouterVendor::PfSense | RouterVendor::CitrixVpx => {
            vec![
                format!("router bgp {local_as}"),
                format!(" neighbor {ip} shutdown"),
                "exit".into(),
            ]
        }
        RouterVendor::VyOs => {
            vec![format!("set protocols bgp neighbor {ip} shutdown")]
        }
        RouterVendor::FortiGate => {
            vec![
                "config router bgp".into(),
                "config neighbor".into(),
                format!("edit {ip}"),
                "set shutdown enable".into(),
                "next".into(),
                "end".into(),
                "end".into(),
            ]
        }
    }
}

pub fn no_shutdown_neighbor_commands(
    vendor: &RouterVendor,
    ip: IpAddr,
    local_as: u32,
) -> Vec<String> {
    let ip = ip.to_string();
    match vendor {
        RouterVendor::Cisco | RouterVendor::PfSense | RouterVendor::CitrixVpx => {
            vec![
                format!("router bgp {local_as}"),
                format!(" no neighbor {ip} shutdown"),
                "exit".into(),
            ]
        }
        RouterVendor::VyOs => {
            vec![format!("delete protocols bgp neighbor {ip} shutdown")]
        }
        RouterVendor::FortiGate => {
            vec![
                "config router bgp".into(),
                "config neighbor".into(),
                format!("edit {ip}"),
                "set shutdown disable".into(),
                "next".into(),
                "end".into(),
                "end".into(),
            ]
        }
    }
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
