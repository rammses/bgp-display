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
            router_id,
            local_as,
            table_version: 1542,
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
            remote_as:              174,
            local_as,
            state:                  BgpState::Established,
            uptime:                 Some("15d03h".into()),
            prefixes_received:      120_823,
            prefixes_advertised:    12,
            description:            Some("Cogent-eBGP".into()),
            update_source:          None,
            next_hop_self:          false,
            route_reflector_client: false,
            password_configured:    true,
            msg_rcvd:               985_421,
            msg_sent:               987_234,
            hold_time:              90,
            keepalive:              30,
            communities:            vec!["174:1000".into()],
        },
        BgpPeer {
            neighbor_ip:            "209.244.0.1".parse().unwrap(),
            remote_as:              3356,
            local_as,
            state:                  BgpState::Established,
            uptime:                 Some("3d11h".into()),
            prefixes_received:      110_540,
            prefixes_advertised:    12,
            description:            Some("Lumen-eBGP".into()),
            update_source:          None,
            next_hop_self:          false,
            route_reflector_client: false,
            password_configured:    true,
            msg_rcvd:               234_112,
            msg_sent:               234_889,
            hold_time:              90,
            keepalive:              30,
            communities:            vec!["3356:100".into()],
        },
        BgpPeer {
            neighbor_ip:            "10.0.0.2".parse().unwrap(),
            remote_as:              local_as,
            local_as,
            state:                  BgpState::Established,
            uptime:                 Some("45d02h".into()),
            prefixes_received:      15,
            prefixes_advertised:    231_375,
            description:            Some("NYC-Core-01-iBGP".into()),
            update_source:          Some("10.0.0.1".parse().unwrap()),
            next_hop_self:          true,
            route_reflector_client: false,
            password_configured:    false,
            msg_rcvd:               3_210_044,
            msg_sent:               3_209_977,
            hold_time:              90,
            keepalive:              30,
            communities:            vec![],
        },
        BgpPeer {
            neighbor_ip:            "10.0.0.10".parse().unwrap(),
            remote_as:              local_as,
            local_as,
            state:                  BgpState::Active,
            uptime:                 Some("never".into()),
            prefixes_received:      0,
            prefixes_advertised:    0,
            description:            Some("Edge-01-iBGP".into()),
            update_source:          Some("10.0.0.1".parse().unwrap()),
            next_hop_self:          true,
            route_reflector_client: false,
            password_configured:    false,
            msg_rcvd:               0,
            msg_sent:               0,
            hold_time:              90,
            keepalive:              30,
            communities:            vec![],
        },
    ]
}

fn mock_atl_routes() -> Vec<BgpRoute> {
    vec![
        BgpRoute {
            status:      RouteStatus::BestExternal,
            network:     "0.0.0.0/0".into(),
            next_hop:    "174.0.0.1".into(),
            metric:      Some(0),
            local_pref:  Some(100),
            weight:      0,
            as_path:     vec![174],
            origin:      RouteOrigin::Igp,
            communities: vec!["174:1000".into()],
        },
        BgpRoute {
            status:      RouteStatus::BestExternal,
            network:     "1.1.1.0/24".into(),
            next_hop:    "174.0.0.1".into(),
            metric:      Some(0),
            local_pref:  Some(100),
            weight:      0,
            as_path:     vec![174, 13335],
            origin:      RouteOrigin::Igp,
            communities: vec![],
        },
        BgpRoute {
            status:      RouteStatus::Valid,
            network:     "8.8.8.0/24".into(),
            next_hop:    "209.244.0.1".into(),
            metric:      Some(0),
            local_pref:  Some(100),
            weight:      0,
            as_path:     vec![3356, 15169],
            origin:      RouteOrigin::Igp,
            communities: vec!["3356:100".into()],
        },
        BgpRoute {
            status:      RouteStatus::BestExternal,
            network:     "8.8.4.0/24".into(),
            next_hop:    "174.0.0.1".into(),
            metric:      Some(0),
            local_pref:  Some(100),
            weight:      0,
            as_path:     vec![174, 3356, 15169],
            origin:      RouteOrigin::Igp,
            communities: vec![],
        },
        BgpRoute {
            status:      RouteStatus::BestExternal,
            network:     "10.0.0.0/8".into(),
            next_hop:    "10.0.0.2".into(),
            metric:      Some(0),
            local_pref:  Some(200),
            weight:      0,
            as_path:     vec![],
            origin:      RouteOrigin::Igp,
            communities: vec!["65001:100".into()],
        },
        BgpRoute {
            status:      RouteStatus::BestExternal,
            network:     "192.168.100.0/24".into(),
            next_hop:    "0.0.0.0".into(),
            metric:      Some(0),
            local_pref:  Some(100),
            weight:      32768,
            as_path:     vec![],
            origin:      RouteOrigin::Igp,
            communities: vec!["65001:200".into()],
        },
    ]
}

// ─── NYC-Core-01 mock data (AS 65001) ────────────────────────────────────────

fn mock_nyc_peers(local_as: u32) -> Vec<BgpPeer> {
    vec![
        BgpPeer {
            neighbor_ip:            "64.71.255.1".parse().unwrap(),
            remote_as:              6939,
            local_as,
            state:                  BgpState::Established,
            uptime:                 Some("7d14h".into()),
            prefixes_received:      90_123,
            prefixes_advertised:    8,
            description:            Some("HE-eBGP".into()),
            update_source:          None,
            next_hop_self:          false,
            route_reflector_client: false,
            password_configured:    true,
            msg_rcvd:               512_000,
            msg_sent:               512_100,
            hold_time:              90,
            keepalive:              30,
            communities:            vec!["6939:1000".into()],
        },
        BgpPeer {
            neighbor_ip:            "10.0.0.1".parse().unwrap(),
            remote_as:              local_as,
            local_as,
            state:                  BgpState::Established,
            uptime:                 Some("45d02h".into()),
            prefixes_received:      231_375,
            prefixes_advertised:    15,
            description:            Some("ATL-Core-01-iBGP".into()),
            update_source:          Some("10.0.0.2".parse().unwrap()),
            next_hop_self:          true,
            route_reflector_client: false,
            password_configured:    false,
            msg_rcvd:               3_209_977,
            msg_sent:               3_210_044,
            hold_time:              90,
            keepalive:              30,
            communities:            vec![],
        },
    ]
}

fn mock_nyc_routes() -> Vec<BgpRoute> {
    vec![
        BgpRoute {
            status:      RouteStatus::BestExternal,
            network:     "0.0.0.0/0".into(),
            next_hop:    "64.71.255.1".into(),
            metric:      Some(0),
            local_pref:  Some(100),
            weight:      0,
            as_path:     vec![6939],
            origin:      RouteOrigin::Igp,
            communities: vec![],
        },
        BgpRoute {
            status:      RouteStatus::BestExternal,
            network:     "10.0.0.0/8".into(),
            next_hop:    "10.0.0.1".into(),
            metric:      Some(0),
            local_pref:  Some(200),
            weight:      0,
            as_path:     vec![],
            origin:      RouteOrigin::Igp,
            communities: vec!["65001:100".into()],
        },
    ]
}

// ─── Edge-01 mock data (AS 65001) ─────────────────────────────────────────────

fn mock_edge_peers(local_as: u32) -> Vec<BgpPeer> {
    vec![
        BgpPeer {
            neighbor_ip:            "10.0.0.1".parse().unwrap(),
            remote_as:              local_as,
            local_as,
            state:                  BgpState::Active,
            uptime:                 Some("never".into()),
            prefixes_received:      0,
            prefixes_advertised:    0,
            description:            Some("ATL-Core-01-iBGP".into()),
            update_source:          Some("10.0.0.10".parse().unwrap()),
            next_hop_self:          false,
            route_reflector_client: false,
            password_configured:    false,
            msg_rcvd:               0,
            msg_sent:               12,
            hold_time:              90,
            keepalive:              30,
            communities:            vec![],
        },
        BgpPeer {
            neighbor_ip:            "172.16.100.1".parse().unwrap(),
            remote_as:              65100,
            local_as,
            state:                  BgpState::Established,
            uptime:                 Some("2d05h".into()),
            prefixes_received:      5,
            prefixes_advertised:    1,
            description:            Some("Customer-A-eBGP".into()),
            update_source:          None,
            next_hop_self:          true,
            route_reflector_client: false,
            password_configured:    true,
            msg_rcvd:               14_432,
            msg_sent:               14_200,
            hold_time:              90,
            keepalive:              30,
            communities:            vec!["65001:500".into()],
        },
    ]
}

fn mock_edge_routes() -> Vec<BgpRoute> {
    vec![
        BgpRoute {
            status:      RouteStatus::BestExternal,
            network:     "172.16.100.0/24".into(),
            next_hop:    "172.16.100.1".into(),
            metric:      Some(0),
            local_pref:  Some(100),
            weight:      0,
            as_path:     vec![65100],
            origin:      RouteOrigin::Igp,
            communities: vec!["65001:500".into()],
        },
    ]
}
