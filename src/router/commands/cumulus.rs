//! NVUE commands for Cumulus Linux 5.x neighbors.
//!
//! A neighbor identifier is either an IP address or an interface name.  NVUE
//! writes are deliberately kept separate from FRR's read-only `vtysh` calls.

use crate::bgp::naming::PolicyNames;
use crate::bgp::{
    AddressFamily, CommunityListEntry, NeighborDraft, PrefixListEntry, RouteMapEntry,
};
use std::net::IpAddr;

/// Restrict identifiers to one shell word and to characters used in Cumulus
/// interface names.  This also protects commands assembled from live FRR output.
pub(crate) fn valid_neighbor_id(id: &str) -> bool {
    if id.parse::<IpAddr>().is_ok() {
        return true;
    }
    let mut chars = id.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub(super) fn cumulus_create(draft: &NeighborDraft, names: &PolicyNames) -> Vec<String> {
    let id = draft.neighbor_ip.trim();
    let remote_as = match draft.remote_as.trim().to_ascii_lowercase().as_str() {
        "external" => "external".to_string(),
        "internal" => "internal".to_string(),
        value => match value.parse::<u32>() {
            Ok(n) if n > 0 => n.to_string(),
            _ => return Vec::new(),
        },
    };
    if !valid_neighbor_id(id) {
        return Vec::new();
    }
    if draft.bfd || !draft.default_local_pref.trim().is_empty() {
        return Vec::new();
    }

    let af = match draft.address_family {
        AddressFamily::Ipv4Unicast => "ipv4-unicast",
        AddressFamily::Ipv6Unicast => "ipv6-unicast",
    };
    let base = format!("nv set vrf default router bgp neighbor {id}");
    let mut cmds = vec![
        format!(
            "nv set router policy route-map {} rule 10 action deny",
            names.rm_in
        ),
        format!(
            "nv set router policy route-map {} rule 10 action deny",
            names.rm_out
        ),
        format!(
            "{base} address-family {af} policy inbound route-map {}",
            names.rm_in
        ),
        format!(
            "{base} address-family {af} policy outbound route-map {}",
            names.rm_out
        ),
        format!("{base} remote-as {remote_as}"),
    ];
    if id.parse::<IpAddr>().is_err() {
        cmds.push(format!("{base} type unnumbered"));
    }
    if af == "ipv6-unicast" {
        cmds.push(format!("{base} address-family {af} state enabled"));
        cmds.push(format!("{base} address-family ipv4-unicast state disabled"));
    }
    if !draft.description.trim().is_empty() {
        cmds.push(format!(
            "{base} description {}",
            shell_quote(draft.description.trim())
        ));
    }
    if !draft.update_source.trim().is_empty() {
        let source = draft.update_source.trim();
        if !valid_neighbor_id(source) {
            return Vec::new();
        }
        cmds.push(format!("{base} update-source {source}"));
    }
    if !draft.password.is_empty() {
        cmds.push(format!("{base} password {}", shell_quote(&draft.password)));
    }
    let hold = draft.hold_time.trim().parse::<u16>().unwrap_or(180);
    let keepalive = draft.keepalive.trim().parse::<u16>().unwrap_or(60);
    cmds.push(format!("{base} timers hold {hold}"));
    cmds.push(format!("{base} timers keepalive {keepalive}"));
    if draft.next_hop_self {
        cmds.push(format!("{base} address-family {af} nexthop-setting self"));
    }
    if draft.route_reflector_client {
        cmds.push(format!(
            "{base} address-family {af} route-reflector-client enabled"
        ));
    }
    if draft.soft_reconfiguration_inbound {
        cmds.push(format!(
            "{base} address-family {af} soft-reconfiguration enabled"
        ));
    }
    if !draft.maximum_prefix.trim().is_empty() {
        let Ok(limit) = draft.maximum_prefix.trim().parse::<u32>() else {
            return Vec::new();
        };
        cmds.push(format!(
            "{base} address-family {af} prefix-limits inbound maximum {limit}"
        ));
        if draft.maximum_prefix_warning {
            cmds.push(format!(
                "{base} address-family {af} prefix-limits inbound warning-only enabled"
            ));
        }
    }
    if !draft.weight.trim().is_empty() {
        let Ok(weight) = draft.weight.trim().parse::<u16>() else {
            return Vec::new();
        };
        cmds.push(format!("{base} address-family {af} weight {weight}"));
    }
    cmds
}

pub(super) fn cumulus_delete(id: &str, description: &str) -> Vec<String> {
    if !valid_neighbor_id(id) {
        return Vec::new();
    }
    let mut commands = vec![format!("nv unset vrf default router bgp neighbor {id}")];
    if !description.trim().is_empty() {
        let names = crate::bgp::naming::generate_cumulus_policy_names(description, id);
        commands.push(format!("nv unset router policy route-map {}", names.rm_in));
        commands.push(format!("nv unset router policy route-map {}", names.rm_out));
    }
    commands
}

pub(super) fn cumulus_shutdown(id: &str) -> Vec<String> {
    if !valid_neighbor_id(id) {
        return Vec::new();
    }
    vec![format!(
        "nv set vrf default router bgp neighbor {id} shutdown enabled"
    )]
}

pub(super) fn cumulus_no_shutdown(id: &str) -> Vec<String> {
    if !valid_neighbor_id(id) {
        return Vec::new();
    }
    vec![format!(
        "nv set vrf default router bgp neighbor {id} shutdown disabled"
    )]
}

fn valid_policy_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

pub(super) fn cumulus_routemap_save(name: &str, entries: &[RouteMapEntry]) -> Vec<String> {
    if !valid_policy_name(name) || entries.is_empty() {
        return Vec::new();
    }
    let mut commands = vec![format!("nv unset router policy route-map {name}")];
    for entry in entries {
        if !matches!(entry.action.as_str(), "permit" | "deny") {
            return Vec::new();
        }
        let base = format!(
            "nv set router policy route-map {name} rule {}",
            entry.sequence
        );
        commands.push(format!("{base} action {}", entry.action));
        for clause in &entry.match_clauses {
            let parts: Vec<&str> = clause.split_whitespace().collect();
            let mapped = match parts.as_slice() {
                ["ip" | "ipv6", "address", "prefix-list", list] if valid_policy_name(list) => {
                    format!("ip-prefix-list {list}")
                }
                ["community", list] if valid_policy_name(list) => format!("community-list {list}"),
                ["as-path", list] if valid_policy_name(list) => format!("as-path-list {list}"),
                _ => return Vec::new(),
            };
            commands.push(format!("{base} match {mapped}"));
        }
        for clause in &entry.set_clauses {
            let parts: Vec<&str> = clause.split_whitespace().collect();
            let mapped = match parts.as_slice() {
                ["local-preference" | "metric", value] if value.parse::<u32>().is_ok() => {
                    clause.as_str()
                }
                _ => return Vec::new(),
            };
            commands.push(format!("{base} set {mapped}"));
        }
    }
    commands
}

pub(super) fn cumulus_prefixlist_save(name: &str, entries: &[PrefixListEntry]) -> Vec<String> {
    if !valid_policy_name(name) || entries.is_empty() {
        return Vec::new();
    }
    let mut commands = vec![format!("nv unset router policy prefix-list {name}")];
    let mut list_type = None;
    for entry in entries {
        if entry.validate().is_err() {
            return Vec::new();
        }
        let mut tokens = entry.prefix.split_whitespace();
        let Some(prefix) = tokens.next() else {
            return Vec::new();
        };
        let current_type = if prefix.contains(':') { "ipv6" } else { "ipv4" };
        if list_type.is_some_and(|kind| kind != current_type) {
            return Vec::new();
        }
        list_type = Some(current_type);
        let base = format!("nv set router policy prefix-list {name} rule {}", entry.seq);
        commands.push(format!("{base} action {}", entry.action));
        commands.push(format!("{base} match {prefix}"));
        while let Some(option) = tokens.next() {
            let Some(value) = tokens.next() else {
                return Vec::new();
            };
            let mapped = match option {
                "le" => "max-prefix-len",
                "ge" => "min-prefix-len",
                _ => return Vec::new(),
            };
            if value.parse::<u8>().is_err() {
                return Vec::new();
            }
            commands.push(format!("{base} match {prefix} {mapped} {value}"));
        }
    }
    if list_type == Some("ipv6") {
        commands.insert(
            1,
            format!("nv set router policy prefix-list {name} type ipv6"),
        );
    }
    commands
}

pub(super) fn cumulus_communitylist_save(
    name: &str,
    entries: &[CommunityListEntry],
) -> Vec<String> {
    if !valid_policy_name(name) || entries.is_empty() {
        return Vec::new();
    }
    let mut commands = vec![format!("nv unset router policy community-list {name}")];
    for entry in entries {
        if entry.validate().is_err()
            || !entry
                .community
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == ':')
        {
            return Vec::new();
        }
        let base = format!(
            "nv set router policy community-list {name} rule {}",
            entry.seq
        );
        commands.push(format!("{base} action {}", entry.action));
        commands.push(format!("{base} community {}", entry.community));
    }
    commands
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::naming::generate_cumulus_policy_names;

    #[test]
    fn interface_ids_are_safe_shell_words() {
        assert!(valid_neighbor_id("swp51"));
        assert!(valid_neighbor_id("peerlink.4094"));
        assert!(valid_neighbor_id("2001:db8::1"));
        assert!(!valid_neighbor_id("swp51;reboot"));
        assert!(!valid_neighbor_id("$(reboot)"));
        assert!(!valid_neighbor_id(""));
    }

    #[test]
    fn shutdown_accepts_interface_and_rejects_shell_syntax() {
        assert_eq!(
            cumulus_shutdown("swp51"),
            vec!["nv set vrf default router bgp neighbor swp51 shutdown enabled"]
        );
        assert!(cumulus_shutdown("swp51;reboot").is_empty());
    }

    #[test]
    fn create_unnumbered_neighbor_with_external_as() {
        let draft = NeighborDraft {
            neighbor_ip: "swp51".into(),
            remote_as: "external".into(),
            description: "Spine one's uplink".into(),
            ..Default::default()
        };
        let names = generate_cumulus_policy_names(&draft.description, &draft.neighbor_ip);
        let commands = cumulus_create(&draft, &names);
        assert!(commands
            .iter()
            .any(|c| c == "nv set vrf default router bgp neighbor swp51 remote-as external"));
        assert!(commands
            .iter()
            .any(|c| c == "nv set vrf default router bgp neighbor swp51 type unnumbered"));
        assert!(commands.iter().any(|c| c
            == &format!(
                "nv set router policy route-map {} rule 10 action deny",
                names.rm_in
            )));
        assert!(commands.iter().any(|c| c == &format!("nv set vrf default router bgp neighbor swp51 address-family ipv4-unicast policy outbound route-map {}", names.rm_out)));
        assert!(commands.iter().any(|c| c.ends_with("timers hold 180")));
        assert!(commands
            .iter()
            .any(|c| c.contains("'Spine one'\\''s uplink'")));
    }

    #[test]
    fn route_map_can_permit_only_a_prefix_list() {
        let entry = RouteMapEntry {
            sequence: 5,
            action: "permit".into(),
            match_clauses: vec!["ip address prefix-list PL-SPINE-IN".into()],
            set_clauses: vec!["local-preference 200".into()],
        };
        let commands = cumulus_routemap_save("RM-SPINE-IN", &[entry]);
        assert!(commands
            .iter()
            .any(|c| c.ends_with("match ip-prefix-list PL-SPINE-IN")));
        assert!(commands
            .iter()
            .any(|c| c.ends_with("set local-preference 200")));
    }

    #[test]
    fn delete_removes_only_its_neighbor_policy_maps() {
        let names = generate_cumulus_policy_names("Spine", "swp51");
        let commands = cumulus_delete("swp51", "Spine");
        assert_eq!(
            commands[0],
            "nv unset vrf default router bgp neighbor swp51"
        );
        assert!(commands.contains(&format!("nv unset router policy route-map {}", names.rm_in)));
        assert!(commands.contains(&format!(
            "nv unset router policy route-map {}",
            names.rm_out
        )));
    }

    #[test]
    fn ipv6_unnumbered_create_disables_unguarded_ipv4_family() {
        let draft = NeighborDraft {
            neighbor_ip: "swp52".into(),
            remote_as: "external".into(),
            description: "Spine02".into(),
            address_family: AddressFamily::Ipv6Unicast,
            ..Default::default()
        };
        let commands = cumulus_create(
            &draft,
            &generate_cumulus_policy_names(&draft.description, &draft.neighbor_ip),
        );
        assert!(commands
            .iter()
            .any(|c| c.ends_with("address-family ipv4-unicast state disabled")));
        assert!(commands
            .iter()
            .any(|c| c.ends_with("address-family ipv6-unicast state enabled")));
        assert!(commands
            .iter()
            .any(|c| c.contains("address-family ipv6-unicast policy inbound route-map")));
    }
}
