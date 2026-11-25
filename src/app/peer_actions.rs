use crate::bgp::{BgpRoute, NeighborDraft};
use crate::events::FetchRequest;
use ratatui::widgets::TableState;
use std::net::IpAddr;
use uuid::Uuid;

use super::{App, PeerRouteView};

impl App {
    // ── Neighbor shutdown toggle ─────────────────────────────────────────────

    pub fn toggle_peer_shutdown(&mut self) {
        if self.reject_native_management() {
            return;
        }
        let peer_ip = match self
            .peer_table_state
            .selected()
            .and_then(|i| self.peer_indices.get(i))
            .and_then(|&idx| self.current_peers.get(idx))
        {
            Some(p) => p.neighbor_ip.clone(),
            None => return,
        };

        let router = match self.selected_router() {
            Some(r) => r.clone(),
            None => return,
        };

        let local_as = router.local_as.unwrap_or(0);
        if local_as == 0 {
            self.set_status("Cannot toggle shutdown: unknown local AS");
            return;
        }

        let is_established = self
            .current_peers
            .iter()
            .find(|p| p.neighbor_ip == peer_ip)
            .map(|p| p.state.is_established())
            .unwrap_or(false);

        let (commands, desc) = if is_established {
            (
                crate::router::commands::shutdown_neighbor_commands(
                    &router.vendor,
                    &peer_ip,
                    local_as,
                ),
                format!("Shutdown neighbor {peer_ip}"),
            )
        } else {
            (
                crate::router::commands::no_shutdown_neighbor_commands(
                    &router.vendor,
                    &peer_ip,
                    local_as,
                ),
                format!("No-shutdown neighbor {peer_ip}"),
            )
        };

        self.send_fetch(FetchRequest::ApplyConfig {
            router_id: router.id,
            commands,
            description: desc.clone(),
        });
        self.set_status(desc);
    }

    // ── Clone neighbor to another router ─────────────────────────────────────

    pub fn start_clone_peer(&mut self) {
        if self.reject_native_management() {
            return;
        }
        let router_id = match self.selected_router() {
            Some(r) => r.id,
            None => return,
        };

        let peer_ip = match self
            .peer_table_state
            .selected()
            .and_then(|i| self.peer_indices.get(i))
            .and_then(|&idx| self.current_peers.get(idx))
        {
            Some(p) => p.neighbor_ip.clone(),
            None => return,
        };

        let from_desired = self
            .desired_neighbors
            .get(&router_id)
            .and_then(|neighbors| {
                neighbors
                    .iter()
                    .find(|d| d.neighbor_ip.trim() == peer_ip)
                    .cloned()
            });

        let draft = if let Some(mut d) = from_desired {
            d.id = None;
            d.router_id = None;
            d.created_at = None;
            d.updated_at = None;
            d
        } else if let Some(peer) = self.current_peers.iter().find(|p| p.neighbor_ip == peer_ip) {
            let (
                Some(remote_as),
                Some(next_hop_self),
                Some(route_reflector_client),
                Some(hold_time),
                Some(keepalive),
            ) = (
                peer.remote_as,
                peer.next_hop_self,
                peer.route_reflector_client,
                peer.hold_time,
                peer.keepalive,
            )
            else {
                self.set_status("Clone unavailable: required legacy observations unknown");
                return;
            };
            NeighborDraft {
                neighbor_ip: peer.neighbor_ip.to_string(),
                remote_as: remote_as.to_string(),
                description: peer.description.clone().unwrap_or_default(),
                update_source: peer
                    .update_source
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                next_hop_self,
                route_reflector_client,
                hold_time: hold_time.to_string(),
                keepalive: keepalive.to_string(),
                bfd: peer.bfd_state.is_some(),
                address_family: crate::bgp::AddressFamily::from_ip(&peer.neighbor_ip.to_string()),
                ..Default::default()
            }
        } else {
            return;
        };

        self.clone_draft = Some(draft);
        self.clone_target_router = Some(0);
        self.set_status(format!("Clone neighbor {peer_ip} — select target router"));
    }

    pub fn execute_clone(&mut self) {
        if self.reject_native_management() {
            return;
        }
        let draft = match self.clone_draft.take() {
            Some(d) => d,
            None => return,
        };
        let target_idx = match self.clone_target_router.take() {
            Some(i) => i,
            None => return,
        };
        let target_router = match self.all_routers.get(target_idx) {
            Some(r) => r.clone(),
            None => {
                self.set_status("Clone failed: invalid target router");
                return;
            }
        };
        if target_router.vendor == crate::router::RouterVendor::MikroTik {
            self.set_status("Clone into MikroTik unavailable — native-only management");
            return;
        }

        let local_as = self
            .bgp_cache
            .get(&target_router.id)
            .and_then(|c| c.summary.local_as)
            .or(target_router.local_as)
            .unwrap_or(0);

        if let Err(error) = draft.validate_for_vendor(&target_router.vendor) {
            self.set_status(format!("Clone failed: {error}"));
            return;
        }

        let commands = crate::router::commands::create_neighbor_commands(
            &target_router.vendor,
            &draft,
            local_as,
        );
        if commands.is_empty() {
            self.set_status("Clone failed: no commands generated for this vendor");
            return;
        }

        let desc = format!(
            "Clone neighbor {} to {}",
            draft.neighbor_ip, target_router.name
        );

        let ip_str = draft.neighbor_ip.clone();
        let rollback_cmds = crate::router::commands::delete_neighbor_commands(
            &target_router.vendor,
            &ip_str,
            local_as,
            &draft.description,
        );

        if let Some(db) = &self.router_db {
            let _ = db.insert_config_history(
                target_router.id,
                "neighbor_clone",
                &desc,
                &commands,
                &rollback_cmds,
            );
        }

        self.send_fetch(FetchRequest::ApplyConfig {
            router_id: target_router.id,
            commands,
            description: desc.clone(),
        });
        self.set_status(desc);
    }

    pub fn cancel_clone(&mut self) {
        self.clone_draft = None;
        self.clone_target_router = None;
        self.set_status("Clone cancelled");
    }

    // ── Per-peer route drill-down ─────────────────────────────────────────────

    /// Open the per-peer route drill-down for the currently selected peer.
    pub fn open_peer_route_view(&mut self, dir: crate::bgp::PeerRouteDirection) {
        if self.is_native_selected() {
            self.open_native_peer_routes(dir);
            return;
        }
        let ip = match self
            .peer_table_state
            .selected()
            .and_then(|i| self.peer_indices.get(i))
            .and_then(|&idx| self.current_peers.get(idx))
        {
            Some(p) => p.neighbor_ip.clone(),
            None => return,
        };
        self.peer_route_view = Some(PeerRouteView {
            peer_ip: ip.clone(),
            direction: dir,
            routes: None,
            error: None,
            native_request: None,
            native_source: None,
        });
        self.peer_route_table_state = TableState::default();
        self.request_peer_routes_fetch(ip.clone(), dir);
        self.set_status(format!("Fetching {} routes for {}…", dir.label(), ip));
    }

    pub fn close_peer_route_view(&mut self) {
        self.peer_route_view = None;
        self.peer_route_table_state = TableState::default();
    }

    /// Toggle between Received and Advertised in the drill-down view.
    pub fn toggle_peer_route_direction(&mut self) {
        if self.is_native_selected() {
            if let Some(view) = &self.peer_route_view {
                let direction = view.direction.toggle();
                self.open_native_peer_routes(direction);
            }
            return;
        }
        let (ip, dir) = match self.peer_route_view.as_mut() {
            Some(view) => {
                view.direction = view.direction.toggle();
                view.routes = None;
                view.error = None;
                (view.peer_ip.clone(), view.direction)
            }
            None => return,
        };
        self.peer_route_table_state = TableState::default();
        self.request_peer_routes_fetch(ip.clone(), dir);
        self.set_status(format!("Fetching {} routes for {}…", dir.label(), ip));
    }

    pub(crate) fn request_peer_routes_fetch(
        &mut self,
        ip: String,
        dir: crate::bgp::PeerRouteDirection,
    ) {
        if self.is_native_selected() {
            self.open_native_peer_routes(dir);
            return;
        }
        let Some(router) = self.selected_router() else {
            return;
        };
        self.send_fetch(FetchRequest::FetchPeerRoutes {
            router_id: router.id,
            ip,
            dir,
        });
    }

    /// Called when per-peer routes arrive from the background task.
    pub fn handle_peer_routes(
        &mut self,
        _id: Uuid,
        ip: String,
        dir: crate::bgp::PeerRouteDirection,
        routes: Vec<BgpRoute>,
    ) {
        if self.is_native_selected() {
            return;
        }
        let count = routes.len();
        if let Some(view) = self.peer_route_view.as_mut() {
            if view.peer_ip == ip && view.direction == dir {
                view.routes = Some(routes);
                view.error = None;
            } else {
                return;
            }
        } else {
            return;
        }
        if count > 0 {
            self.peer_route_table_state.select(Some(0));
        }
        self.set_status(format!(
            "{} {} routes for {}",
            count,
            dir.label().to_lowercase(),
            ip
        ));
    }

    /// Called when a per-peer routes fetch fails.
    pub fn handle_peer_routes_error(
        &mut self,
        _id: Uuid,
        ip: String,
        dir: crate::bgp::PeerRouteDirection,
        err: String,
    ) {
        if self.is_native_selected() {
            return;
        }
        if let Some(view) = self.peer_route_view.as_mut() {
            if view.peer_ip == ip && view.direction == dir {
                view.error = Some(err.clone());
                view.routes = Some(vec![]);
            }
        }
        tracing::warn!(peer = %ip, direction = %dir.label(), error = %err, "peer routes fetch failed");
        self.conn_log(format!(
            "Peer routes error {ip}: {}",
            super::truncate_error(&err, 60)
        ));
    }

    // ── Path-MTU probe ───────────────────────────────────────────────────────────

    fn legacy_mtu_peer_index(&self, router_id: Uuid, target: IpAddr) -> Option<usize> {
        let router = self.selected_router()?;
        if router.id != router_id
            || router.vendor == crate::router::RouterVendor::MikroTik
            || self.native_view.is_some()
        {
            return None;
        }
        let target = target.to_string();
        self.current_peers.iter().position(|peer| {
            peer.neighbor_ip == target
                && peer.native_source.is_none()
                && matches!(
                    peer.key.as_ref(),
                    None | Some(crate::bgp::PeerKey::Legacy(_))
                )
        })
    }

    pub fn request_mtu_probe(&mut self, target: IpAddr) {
        if self.is_native_selected() {
            self.set_status("MikroTik MTU unavailable — no native probes");
            return;
        }
        let Some(router) = self.selected_router() else {
            return;
        };
        self.send_fetch(FetchRequest::FetchMtu {
            router_id: router.id,
            target,
        });
    }

    /// Called when a path-MTU probe returns a result.
    pub fn handle_mtu_probe_result(&mut self, id: Uuid, ip: IpAddr, max_bytes: u16) {
        let Some(index) = self.legacy_mtu_peer_index(id, ip) else {
            return;
        };
        use crate::bgp::MtuProbeState;
        let state = if max_bytes >= 1500 {
            MtuProbeState::Ok(max_bytes)
        } else if max_bytes > 0 {
            MtuProbeState::Degraded(max_bytes)
        } else {
            MtuProbeState::Failed("all probes failed".into())
        };
        self.current_peers[index].mtu_probe = Some(state.clone());
        let msg = match &state {
            MtuProbeState::Ok(n) => format!("MTU probe {ip}: OK (path MTU ≥ {n} B)"),
            MtuProbeState::Degraded(n) => format!("MTU probe {ip}: degraded — max frame {n} B"),
            MtuProbeState::Failed(e) => format!("MTU probe {ip}: failed — {e}"),
            MtuProbeState::Running => unreachable!(),
        };
        self.set_status(msg);
    }

    /// Called when a path-MTU probe SSH call fails entirely.
    pub fn handle_mtu_probe_error(&mut self, id: Uuid, ip: IpAddr, err: String) {
        let Some(index) = self.legacy_mtu_peer_index(id, ip) else {
            return;
        };
        self.current_peers[index].mtu_probe = Some(crate::bgp::MtuProbeState::Failed(err.clone()));
        tracing::warn!(target = %ip, error = %err, "MTU probe failed");
        self.conn_log(format!(
            "MTU probe error {ip}: {}",
            super::truncate_error(&err, 60)
        ));
        self.set_status(format!("MTU probe to {ip} failed"));
    }

    pub fn log(&mut self, msg: impl Into<String>) {
        let entry = format!(
            "[{}] {}",
            chrono::Local::now().format("%H:%M:%S"),
            msg.into()
        );
        self.logs.push(entry);
        if self.logs.len() > 500 {
            self.logs.remove(0);
        }
        let len = self.logs.len();
        self.log_list_state.select(Some(len.saturating_sub(1)));
    }

    pub fn conn_log(&mut self, msg: impl Into<String>) {
        let entry = format!(
            "[{}] {}",
            chrono::Local::now().format("%H:%M:%S"),
            msg.into()
        );
        self.conn_logs.push(entry);
        if self.conn_logs.len() > 500 {
            self.conn_logs.remove(0);
        }
        let len = self.conn_logs.len();
        self.conn_log_state.select(Some(len.saturating_sub(1)));
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some(msg.into());
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use crate::bgp::MtuProbeState;
    use crate::config::AppConfig;
    use crate::db::RouterDb;
    use crate::router::mikrotik::{test_support::documented_snapshot, NativeDiscovery};
    use crate::router::{RouterConfig, RouterVendor};

    fn native_app() -> App {
        let config = RouterConfig {
            id: Uuid::nil(),
            vendor: RouterVendor::MikroTik,
            hostname: "lab.invalid".into(),
            username: "tester".into(),
            mikrotik_instance: Some("blue".into()),
            ..RouterConfig::default()
        };
        let mut app = App::new(
            AppConfig {
                routers: vec![config],
                ..AppConfig::default()
            },
            RouterDb::in_memory().unwrap(),
        );
        app.request_native_refresh(Uuid::nil());
        let mut snapshot = documented_snapshot();
        snapshot.request = app.native_cache[&Uuid::nil()].latest_request;
        app.handle_native_data(
            Uuid::nil(),
            snapshot.request,
            NativeDiscovery::Snapshot(snapshot),
        );
        app.set_status("native unsupported MTU remains unchanged");
        app
    }

    #[test]
    fn mikrotik_sec_002_mtu_success_and_error_cannot_contaminate_native_display() {
        for same_id in [false, true] {
            for success in [false, true] {
                let mut app = native_app();
                let origin = if same_id {
                    Uuid::nil()
                } else {
                    Uuid::from_u128(9)
                };
                let before = app.current_peers.clone();
                let status = app.status_message.clone();
                let logs = app.conn_logs.clone();
                let generation = app.native_view.as_ref().unwrap().snapshot.generation;
                if success {
                    app.handle_mtu_probe_result(origin, "192.0.2.2".parse().unwrap(), 1500);
                } else {
                    app.handle_mtu_probe_error(
                        origin,
                        "192.0.2.2".parse().unwrap(),
                        "old legacy failure".into(),
                    );
                }
                assert_eq!(
                    app.current_peers, before,
                    "late legacy MTU must not mutate native peer"
                );
                assert_eq!(app.status_message, status);
                assert_eq!(app.conn_logs, logs);
                assert_eq!(
                    app.native_cache[&Uuid::nil()]
                        .snapshot
                        .as_ref()
                        .unwrap()
                        .generation,
                    generation
                );
            }
        }
    }

    #[test]
    fn mikrotik_sec_002_native_presentation_and_peer_source_reject_mtu_even_under_legacy_config() {
        for keep_view in [true, false] {
            let mut app = native_app();
            app.routers[0].vendor = RouterVendor::Cisco;
            app.all_routers[0].vendor = RouterVendor::Cisco;
            if !keep_view {
                app.native_view = None;
            }
            let before = app.current_peers.clone();
            let status = app.status_message.clone();
            app.handle_mtu_probe_result(Uuid::nil(), "192.0.2.2".parse().unwrap(), 1500);
            app.handle_mtu_probe_error(
                Uuid::nil(),
                "192.0.2.2".parse().unwrap(),
                "late failure".into(),
            );
            assert_eq!(app.current_peers, before);
            assert_eq!(app.status_message, status);
        }
    }

    #[test]
    fn mikrotik_sec_002_matching_legacy_mtu_still_works_and_other_router_is_ignored() {
        let mut app = native_app();
        app.routers[0].vendor = RouterVendor::Cisco;
        app.all_routers[0].vendor = RouterVendor::Cisco;
        app.native_view = None;
        let summary = crate::bgp::parse_bgp_summary("BGP router identifier 192.0.2.1, local AS number 65000\n192.0.2.2 4 65001 1 2 1 0 0 00:01:00 3");
        app.current_peers = summary.peers;
        app.current_peers[0].mtu_probe = Some(MtuProbeState::Running);
        let status = app.status_message.clone();
        app.handle_mtu_probe_result(Uuid::from_u128(9), "192.0.2.2".parse().unwrap(), 1500);
        app.handle_mtu_probe_error(
            Uuid::from_u128(9),
            "192.0.2.2".parse().unwrap(),
            "foreign failure".into(),
        );
        assert_eq!(app.current_peers[0].mtu_probe, Some(MtuProbeState::Running));
        assert_eq!(app.status_message, status);
        app.handle_mtu_probe_result(Uuid::nil(), "192.0.2.2".parse().unwrap(), 1500);
        assert_eq!(
            app.current_peers[0].mtu_probe,
            Some(MtuProbeState::Ok(1500))
        );
        app.handle_mtu_probe_error(
            Uuid::nil(),
            "192.0.2.2".parse().unwrap(),
            "matching failure".into(),
        );
        assert_eq!(
            app.current_peers[0].mtu_probe,
            Some(MtuProbeState::Failed("matching failure".into()))
        );
    }
}
