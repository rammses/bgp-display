use crate::{
    bgp::{
        BgpPeer, BgpRoute, BgpState, BgpSummary, RouteOrigin, RouteStatus,
    },
    router::{ConnectionStatus, RouterConfig},
};
use anyhow::Result;
use chrono::Utc;
use std::net::IpAddr;

// ─── Mock Backend ─────────────────────────────────────────────────────────────

pub struct MockBackend {
    pub summary: BgpSummary,
    pub routes:  Vec<BgpRoute>,
    status:      ConnectionStatus,
}

#[allow(dead_code)]
impl MockBackend {
    /// Build a realistic mock backend for a given RouterConfig.
    pub fn for_router(cfg: &RouterConfig) -> Self {
        let local_as  = cfg.local_as.unwrap_or(65001);
        let router_id = cfg.router_id.unwrap_or_else(|| {
            cfg.hostname.parse().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)))
        });

        let (peers, routes) = match cfg.name.as_str() {
            "ATL-Core-01" => (mock_atl_peers(local_as), mock_atl_routes()),
            "NYC-Core-01" => (mock_nyc_peers(local_as), mock_nyc_routes()),
            "Edge-01"     => (mock_edge_peers(local_as), mock_edge_routes()),
            _             => (mock_atl_peers(local_as), mock_atl_routes()),
        };

        let summary = BgpSummary {
            router_id: Some(router_id),
            local_as: Some(local_as),
            table_version: Some(1542),
            peers,
            fetched_at: Utc::now(),
        };

        Self {
            summary,
            routes,
            status: ConnectionStatus::Connected,
        }
    }

    pub fn status(&self) -> &ConnectionStatus {
        &self.status
    }

    pub async fn connect(&mut self) -> Result<()> {
        self.status = ConnectionStatus::Connected;
        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        self.status = ConnectionStatus::Disconnected;
        Ok(())
    }

    pub async fn refresh(&mut self) -> Result<BgpSummary> {
        Ok(self.summary.clone())
    }

    pub async fn get_routes(&mut self) -> Result<Vec<BgpRoute>> {
        Ok(self.routes.clone())
    }

    pub async fn apply_config(&mut self, _config: &str) -> Result<()> {
        // Mock: pretend the config was applied
        Ok(())
    }
}

// ─── ATL-Core-01 mock data (AS 65001) ────────────────────────────────────────

fn mock_atl_peers(local_as: u32) -> Vec<BgpPeer> {
    vec![
        BgpPeer {
            neighbor_ip:            "174.0.0.1".parse().unwrap(),
            key: None,
            admin_disabled: None,
            native_source: None,
            remote_as:              Some(174),
            local_as: Some(local_as),
            state:                  BgpState::Established,
            uptime:                 Some("15d03h".into()),
            prefixes_received:      Some(120_823),
            prefixes_advertised:    Some(12),
            description:            Some("Cogent-eBGP".into()),
            update_source:          None,
            next_hop_self:          Some(false),
            route_reflector_client: Some(false),
            password_configured:    Some(true),
            msg_rcvd:               Some(985_421),
            msg_sent:               Some(987_234),
            hold_time:              Some(90),
            keepalive:              Some(30),
            communities:            vec!["174:1000".into()],
            route_map_in: None,
            route_map_out: None,
            reset_count: None,
            last_reset_reason: None,
            notifs_sent: None,
            notifs_rcvd: None,
            bfd_state: None,
            mtu_probe: None,
        },
        BgpPeer {
            neighbor_ip:            "209.244.0.1".parse().unwrap(),
            key: None,
            admin_disabled: None,
            native_source: None,
            remote_as:              Some(3356),
            local_as: Some(local_as),
            state:                  BgpState::Established,
            uptime:                 Some("3d11h".into()),
            prefixes_received:      Some(110_540),
            prefixes_advertised:    Some(12),
            description:            Some("Lumen-eBGP".into()),
            update_source:          None,
            next_hop_self:          Some(false),
            route_reflector_client: Some(false),
            password_configured:    Some(true),
            msg_rcvd:               Some(234_112),
            msg_sent:               Some(234_889),
            hold_time:              Some(90),
            keepalive:              Some(30),
            communities:            vec!["3356:100".into()],
            route_map_in: None,
            route_map_out: None,
            reset_count: None,
            last_reset_reason: None,
            notifs_sent: None,
            notifs_rcvd: None,
            bfd_state: None,
            mtu_probe: None,
        },
        BgpPeer {
            neighbor_ip:            "10.0.0.2".parse().unwrap(),
            key: None,
            admin_disabled: None,
            native_source: None,
            remote_as:              Some(local_as),
            local_as: Some(local_as),
            state:                  BgpState::Established,
            uptime:                 Some("45d02h".into()),
            prefixes_received:      Some(15),
            prefixes_advertised:    Some(231_375),
            description:            Some("NYC-Core-01-iBGP".into()),
            update_source:          Some("10.0.0.1".parse().unwrap()),
            next_hop_self:          Some(true),
            route_reflector_client: Some(false),
            password_configured:    Some(false),
            msg_rcvd:               Some(3_210_044),
            msg_sent:               Some(3_209_977),
            hold_time:              Some(90),
            keepalive:              Some(30),
            communities:            vec![],
            route_map_in: None,
            route_map_out: None,
            reset_count: None,
            last_reset_reason: None,
            notifs_sent: None,
            notifs_rcvd: None,
            bfd_state: None,
            mtu_probe: None,
        },
        BgpPeer {
            neighbor_ip:            "10.0.0.10".parse().unwrap(),
            key: None,
            admin_disabled: None,
            native_source: None,
            remote_as:              Some(local_as),
            local_as: Some(local_as),
            state:                  BgpState::Active,
            uptime:                 Some("never".into()),
            prefixes_received:      Some(0),
            prefixes_advertised:    Some(0),
            description:            Some("Edge-01-iBGP".into()),
            update_source:          Some("10.0.0.1".parse().unwrap()),
            next_hop_self:          Some(true),
            route_reflector_client: Some(false),
            password_configured:    Some(false),
            msg_rcvd:               Some(0),
            msg_sent:               Some(0),
            hold_time:              Some(90),
            keepalive:              Some(30),
            communities:            vec![],
            route_map_in: None,
            route_map_out: None,
            reset_count: None,
            last_reset_reason: None,
            notifs_sent: None,
            notifs_rcvd: None,
            bfd_state: None,
            mtu_probe: None,
        },
    ]
}

fn mock_atl_routes() -> Vec<BgpRoute> {
    vec![
        BgpRoute {
            status:      Some(RouteStatus::BestExternal),
            native_flags: None,
            as_path_raw: None,
            network:     "0.0.0.0/0".into(),
            next_hop:    "174.0.0.1".into(),
            metric:      Some(0),
            local_pref:  Some(100),
            weight:      Some(0),
            as_path:     Some(vec![174]),
            origin:      Some(RouteOrigin::Igp),
            communities: Some(vec!["174:1000".into()]),
        },
        BgpRoute {
            status:      Some(RouteStatus::BestExternal),
            native_flags: None,
            as_path_raw: None,
            network:     "1.1.1.0/24".into(),
            next_hop:    "174.0.0.1".into(),
            metric:      Some(0),
            local_pref:  Some(100),
            weight:      Some(0),
            as_path:     Some(vec![174, 13335]),
            origin:      Some(RouteOrigin::Igp),
            communities: Some(vec![]),
        },
        BgpRoute {
            status:      Some(RouteStatus::Valid),
            native_flags: None,
            as_path_raw: None,
            network:     "8.8.8.0/24".into(),
            next_hop:    "209.244.0.1".into(),
            metric:      Some(0),
            local_pref:  Some(100),
            weight:      Some(0),
            as_path:     Some(vec![3356, 15169]),
            origin:      Some(RouteOrigin::Igp),
            communities: Some(vec!["3356:100".into()]),
        },
        BgpRoute {
            status:      Some(RouteStatus::BestExternal),
            native_flags: None,
            as_path_raw: None,
            network:     "8.8.4.0/24".into(),
            next_hop:    "174.0.0.1".into(),
            metric:      Some(0),
            local_pref:  Some(100),
            weight:      Some(0),
            as_path:     Some(vec![174, 3356, 15169]),
            origin:      Some(RouteOrigin::Igp),
            communities: Some(vec![]),
        },
        BgpRoute {
            status:      Some(RouteStatus::BestExternal),
            native_flags: None,
            as_path_raw: None,
            network:     "10.0.0.0/8".into(),
            next_hop:    "10.0.0.2".into(),
            metric:      Some(0),
            local_pref:  Some(200),
            weight:      Some(0),
            as_path:     Some(vec![]),
            origin:      Some(RouteOrigin::Igp),
            communities: Some(vec!["65001:100".into()]),
        },
        BgpRoute {
            status:      Some(RouteStatus::BestExternal),
            native_flags: None,
            as_path_raw: None,
            network:     "192.168.100.0/24".into(),
            next_hop:    "0.0.0.0".into(),
            metric:      Some(0),
            local_pref:  Some(100),
            weight:      Some(32768),
            as_path:     Some(vec![]),
            origin:      Some(RouteOrigin::Igp),
            communities: Some(vec!["65001:200".into()]),
        },
    ]
}

// ─── NYC-Core-01 mock data (AS 65001) ────────────────────────────────────────

fn mock_nyc_peers(local_as: u32) -> Vec<BgpPeer> {
    vec![
        BgpPeer {
            neighbor_ip:            "64.71.255.1".parse().unwrap(),
            key: None,
            admin_disabled: None,
            native_source: None,
            remote_as:              Some(6939),
            local_as: Some(local_as),
            state:                  BgpState::Established,
            uptime:                 Some("7d14h".into()),
            prefixes_received:      Some(90_123),
            prefixes_advertised:    Some(8),
            description:            Some("HE-eBGP".into()),
            update_source:          None,
            next_hop_self:          Some(false),
            route_reflector_client: Some(false),
            password_configured:    Some(true),
            msg_rcvd:               Some(512_000),
            msg_sent:               Some(512_100),
            hold_time:              Some(90),
            keepalive:              Some(30),
            communities:            vec!["6939:1000".into()],
            route_map_in: None,
            route_map_out: None,
            reset_count: None,
            last_reset_reason: None,
            notifs_sent: None,
            notifs_rcvd: None,
            bfd_state: None,
            mtu_probe: None,
        },
        BgpPeer {
            neighbor_ip:            "10.0.0.1".parse().unwrap(),
            key: None,
            admin_disabled: None,
            native_source: None,
            remote_as:              Some(local_as),
            local_as: Some(local_as),
            state:                  BgpState::Established,
            uptime:                 Some("45d02h".into()),
            prefixes_received:      Some(231_375),
            prefixes_advertised:    Some(15),
            description:            Some("ATL-Core-01-iBGP".into()),
            update_source:          Some("10.0.0.2".parse().unwrap()),
            next_hop_self:          Some(true),
            route_reflector_client: Some(false),
            password_configured:    Some(false),
            msg_rcvd:               Some(3_209_977),
            msg_sent:               Some(3_210_044),
            hold_time:              Some(90),
            keepalive:              Some(30),
            communities:            vec![],
            route_map_in: None,
            route_map_out: None,
            reset_count: None,
            last_reset_reason: None,
            notifs_sent: None,
            notifs_rcvd: None,
            bfd_state: None,
            mtu_probe: None,
        },
    ]
}

fn mock_nyc_routes() -> Vec<BgpRoute> {
    vec![
        BgpRoute {
            status:      Some(RouteStatus::BestExternal),
            native_flags: None,
            as_path_raw: None,
            network:     "0.0.0.0/0".into(),
            next_hop:    "64.71.255.1".into(),
            metric:      Some(0),
            local_pref:  Some(100),
            weight:      Some(0),
            as_path:     Some(vec![6939]),
            origin:      Some(RouteOrigin::Igp),
            communities: Some(vec![]),
        },
        BgpRoute {
            status:      Some(RouteStatus::BestExternal),
            native_flags: None,
            as_path_raw: None,
            network:     "10.0.0.0/8".into(),
            next_hop:    "10.0.0.1".into(),
            metric:      Some(0),
            local_pref:  Some(200),
            weight:      Some(0),
            as_path:     Some(vec![]),
            origin:      Some(RouteOrigin::Igp),
            communities: Some(vec!["65001:100".into()]),
        },
    ]
}

// ─── Edge-01 mock data (AS 65001) ─────────────────────────────────────────────

fn mock_edge_peers(local_as: u32) -> Vec<BgpPeer> {
    vec![
        BgpPeer {
            neighbor_ip:            "10.0.0.1".parse().unwrap(),
            key: None,
            admin_disabled: None,
            native_source: None,
            remote_as:              Some(local_as),
            local_as: Some(local_as),
            state:                  BgpState::Active,
            uptime:                 Some("never".into()),
            prefixes_received:      Some(0),
            prefixes_advertised:    Some(0),
            description:            Some("ATL-Core-01-iBGP".into()),
            update_source:          Some("10.0.0.10".parse().unwrap()),
            next_hop_self:          Some(false),
            route_reflector_client: Some(false),
            password_configured:    Some(false),
            msg_rcvd:               Some(0),
            msg_sent:               Some(12),
            hold_time:              Some(90),
            keepalive:              Some(30),
            communities:            vec![],
            route_map_in: None,
            route_map_out: None,
            reset_count: None,
            last_reset_reason: None,
            notifs_sent: None,
            notifs_rcvd: None,
            bfd_state: None,
            mtu_probe: None,
        },
        BgpPeer {
            neighbor_ip:            "172.16.100.1".parse().unwrap(),
            key: None,
            admin_disabled: None,
            native_source: None,
            remote_as:              Some(65100),
            local_as: Some(local_as),
            state:                  BgpState::Established,
            uptime:                 Some("2d05h".into()),
            prefixes_received:      Some(5),
            prefixes_advertised:    Some(1),
            description:            Some("Customer-A-eBGP".into()),
            update_source:          None,
            next_hop_self:          Some(true),
            route_reflector_client: Some(false),
            password_configured:    Some(true),
            msg_rcvd:               Some(14_432),
            msg_sent:               Some(14_200),
            hold_time:              Some(90),
            keepalive:              Some(30),
            communities:            vec!["65001:500".into()],
            route_map_in: None,
            route_map_out: None,
            reset_count: None,
            last_reset_reason: None,
            notifs_sent: None,
            notifs_rcvd: None,
            bfd_state: None,
            mtu_probe: None,
        },
    ]
}

fn mock_edge_routes() -> Vec<BgpRoute> {
    vec![
        BgpRoute {
            status:      Some(RouteStatus::BestExternal),
            native_flags: None,
            as_path_raw: None,
            network:     "172.16.100.0/24".into(),
            next_hop:    "172.16.100.1".into(),
            metric:      Some(0),
            local_pref:  Some(100),
            weight:      Some(0),
            as_path:     Some(vec![65100]),
            origin:      Some(RouteOrigin::Igp),
            communities: Some(vec!["65001:500".into()]),
        },
    ]
}
