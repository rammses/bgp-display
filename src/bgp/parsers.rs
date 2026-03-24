use chrono::Utc;
use std::net::IpAddr;

use super::{BgpPeer, BgpState, BgpSummary};

// ─── Cisco/FRR `show ip bgp summary` full parser ─────────────────────────────
//
// Parses router-id and local-AS directly from the header so no prior knowledge
// of the router is required.

pub fn parse_bgp_summary(output: &str) -> BgpSummary {
    // Extract router-id and local-AS from:
    //   "BGP router identifier 1.2.3.4, local AS number 65001"
    let hdr_re =
        regex::Regex::new(r"BGP router identifier\s+(\S+),\s+local AS number\s+(\d+)").unwrap();

    let (router_id, local_as) = hdr_re
        .captures(output)
        .map(|c| {
            let rid: IpAddr = c[1]
                .parse()
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            let las: u32 = c[2].parse().unwrap_or(0);
            (rid, las)
        })
        .unwrap_or((IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0));

    parse_cisco_bgp_summary(output, router_id, local_as)
}

// ─── Cisco `show ip bgp summary` parser ──────────────────────────────────────

pub fn parse_cisco_bgp_summary(output: &str, router_id: IpAddr, local_as: u32) -> BgpSummary {
    let mut peers: Vec<BgpPeer> = Vec::new();
    let mut table_version = 0u64;

    // Regex: Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd [PfxSnt] [Desc]
    // The PfxSnt column is present in newer FRR versions.
    let row_re = regex::Regex::new(
        r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+(\d+))?",
    )
    .unwrap();
    let tv_re = regex::Regex::new(r"table version is (\d+)").unwrap();

    for line in output.lines() {
        if let Some(cap) = tv_re.captures(line) {
            table_version = cap[1].parse().unwrap_or(0);
        }
        if let Some(cap) = row_re.captures(line) {
            let neighbor_ip: IpAddr = cap[1]
                .parse()
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            let remote_as: u32 = cap[2].parse().unwrap_or(0);
            let msg_rcvd: u64 = cap[3].parse().unwrap_or(0);
            let msg_sent: u64 = cap[4].parse().unwrap_or(0);
            let uptime = cap[5].to_string();
            let state_pfx = &cap[6];

            let (state, prefixes_received) = if let Ok(n) = state_pfx.parse::<u64>() {
                (BgpState::Established, n)
            } else {
                (BgpState::from_str(state_pfx), 0)
            };

            let prefixes_advertised: u64 = cap
                .get(7)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);

            peers.push(BgpPeer {
                neighbor_ip,
                remote_as,
                local_as,
                state,
                uptime: Some(uptime),
                prefixes_received,
                prefixes_advertised,
                description: None,
                update_source: None,
                next_hop_self: false,
                route_reflector_client: false,
                password_configured: false,
                msg_rcvd,
                msg_sent,
                hold_time: 90,
                keepalive: 30,
                communities: vec![],
                route_map_in: None,
                route_map_out: None,
                reset_count: 0,
                last_reset_reason: None,
                notifs_sent: 0,
                notifs_rcvd: 0,
                bfd_state: None,
                mtu_probe: None,
            });
        }
    }

    BgpSummary {
        router_id,
        local_as,
        table_version,
        peers,
        fetched_at: Utc::now(),
    }
}
