mod a10;
mod cisco;
mod fortigate;
mod vyos;

use crate::bgp::naming::generate_policy_names;
use crate::bgp::{CommunityListEntry, NeighborDraft, PrefixListEntry, RouteMapEntry};
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
            cisco::cisco_create(draft, local_as, &names)
        }
        RouterVendor::VyOs => vyos::vyos_create(draft, local_as, &names),
        RouterVendor::FortiGate => fortigate::fortigate_create(draft, &names),
        RouterVendor::A10 => a10::a10_create(draft, local_as, &names),
    }
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
        RouterVendor::Cisco
        | RouterVendor::PfSense
        | RouterVendor::CitrixVpx
        | RouterVendor::A10 => {
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
            cisco::cisco_routemap_save(name, entries)
        }
        RouterVendor::VyOs => vyos::vyos_routemap_save(name, entries),
        RouterVendor::FortiGate => fortigate::fortigate_routemap_save(name, entries),
        RouterVendor::A10 => a10::a10_routemap_save(name, entries),
    }
}

// ─── Prefix-list save (replace) ─────────────────────────────────────────────

pub fn prefixlist_save_commands(
    vendor: &RouterVendor,
    name: &str,
    entries: &[PrefixListEntry],
) -> Vec<String> {
    match vendor {
        RouterVendor::Cisco | RouterVendor::PfSense | RouterVendor::CitrixVpx => {
            cisco::cisco_prefixlist_save(name, entries)
        }
        RouterVendor::VyOs => vyos::vyos_prefixlist_save(name, entries),
        RouterVendor::FortiGate => fortigate::fortigate_prefixlist_save(name, entries),
        RouterVendor::A10 => a10::a10_prefixlist_save(name, entries),
    }
}

// ─── Community-list save (replace) ───────────────────────────────────────────

pub fn communitylist_save_commands(
    vendor: &RouterVendor,
    name: &str,
    entries: &[CommunityListEntry],
) -> Vec<String> {
    match vendor {
        RouterVendor::Cisco | RouterVendor::PfSense | RouterVendor::CitrixVpx => {
            cisco::cisco_communitylist_save(name, entries)
        }
        RouterVendor::VyOs => vyos::vyos_communitylist_save(name, entries),
        RouterVendor::FortiGate => fortigate::fortigate_communitylist_save(name, entries),
        RouterVendor::A10 => a10::a10_communitylist_save(name, entries),
    }
}

// ─── Neighbor shutdown toggle ────────────────────────────────────────────────

pub fn shutdown_neighbor_commands(vendor: &RouterVendor, ip: IpAddr, local_as: u32) -> Vec<String> {
    let ip = ip.to_string();
    match vendor {
        RouterVendor::Cisco
        | RouterVendor::PfSense
        | RouterVendor::CitrixVpx
        | RouterVendor::A10 => {
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
        RouterVendor::Cisco
        | RouterVendor::PfSense
        | RouterVendor::CitrixVpx
        | RouterVendor::A10 => {
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
