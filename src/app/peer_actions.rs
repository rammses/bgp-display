use crate::bgp::{BgpRoute, NeighborDraft};
use crate::events::FetchRequest;
use ratatui::widgets::TableState;
use std::net::IpAddr;
use uuid::Uuid;

use super::{App, PeerRouteView};

impl App {
    // ── Neighbor shutdown toggle ─────────────────────────────────────────────

    pub fn toggle_peer_shutdown(&mut self) {
        let peer_ip = match self
            .peer_table_state
            .selected()
            .and_then(|i| self.peer_indices.get(i))
            .and_then(|&idx| self.current_peers.get(idx))
        {
            Some(p) => p.neighbor_ip,
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
                    peer_ip,
                    local_as,
                ),
                format!("Shutdown neighbor {peer_ip}"),
            )
        } else {
            (
                crate::router::commands::no_shutdown_neighbor_commands(
                    &router.vendor,
                    peer_ip,
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
            Some(p) => p.neighbor_ip,
            None => return,
        };

        let from_desired = self
            .desired_neighbors
            .get(&router_id)
            .and_then(|neighbors| {
                neighbors
                    .iter()
                    .find(|d| d.neighbor_ip.trim() == peer_ip.to_string())
                    .cloned()
            });

        let draft = if let Some(mut d) = from_desired {
            d.id = None;
            d.router_id = None;
            d.created_at = None;
            d.updated_at = None;
            d
        } else if let Some(peer) = self.current_peers.iter().find(|p| p.neighbor_ip == peer_ip) {
            let mut d = NeighborDraft::default();
            d.neighbor_ip = peer.neighbor_ip.to_string();
            d.remote_as = peer.remote_as.to_string();
            d.description = peer.description.clone().unwrap_or_default();
            d.update_source = peer
                .update_source
                .map(|s| s.to_string())
                .unwrap_or_default();
            d.next_hop_self = peer.next_hop_self;
            d.route_reflector_client = peer.route_reflector_client;
            d.hold_time = peer.hold_time.to_string();
            d.keepalive = peer.keepalive.to_string();
            d.bfd = peer.bfd_state.is_some();
            d.address_family = crate::bgp::AddressFamily::from_ip(&peer.neighbor_ip.to_string());
            d
        } else {
            return;
        };

        self.clone_draft = Some(draft);
        self.clone_target_router = Some(0);
        self.set_status(format!("Clone neighbor {peer_ip} — select target router"));
    }

    pub fn execute_clone(&mut self) {
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

        let local_as = self
            .bgp_cache
            .get(&target_router.id)
            .map(|c| c.summary.local_as)
            .or(target_router.local_as)
            .unwrap_or(0);

        let commands = crate::router::commands::create_neighbor_commands(
            &target_router.vendor,
            &draft,
            local_as,
        );

        let desc = format!(
            "Clone neighbor {} to {}",
            draft.neighbor_ip, target_router.name
        );

        let ip_str = draft.neighbor_ip.clone();
        let rollback_cmds = if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
            crate::router::commands::delete_neighbor_commands(
                &target_router.vendor,
                ip,
                local_as,
                &draft.description,
            )
        } else {
            vec![]
        };

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
        let ip = match self
            .peer_table_state
            .selected()
            .and_then(|i| self.peer_indices.get(i))
            .and_then(|&idx| self.current_peers.get(idx))
        {
            Some(p) => p.neighbor_ip,
            None => return,
        };
        self.peer_route_view = Some(PeerRouteView {
            peer_ip: ip,
            direction: dir,
            routes: None,
            error: None,
        });
        self.peer_route_table_state = TableState::default();
        self.request_peer_routes_fetch(ip, dir);
        self.set_status(format!("Fetching {} routes for {}…", dir.label(), ip));
    }

    pub fn close_peer_route_view(&mut self) {
        self.peer_route_view = None;
        self.peer_route_table_state = TableState::default();
    }

    /// Toggle between Received and Advertised in the drill-down view.
    pub fn toggle_peer_route_direction(&mut self) {
        let (ip, dir) = match self.peer_route_view.as_mut() {
            Some(view) => {
                view.direction = view.direction.toggle();
                view.routes = None;
                view.error = None;
                (view.peer_ip, view.direction)
            }
            None => return,
        };
        self.peer_route_table_state = TableState::default();
        self.request_peer_routes_fetch(ip, dir);
        self.set_status(format!("Fetching {} routes for {}…", dir.label(), ip));
    }

    pub(crate) fn request_peer_routes_fetch(
        &self,
        ip: IpAddr,
        dir: crate::bgp::PeerRouteDirection,
    ) {
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
        ip: IpAddr,
        dir: crate::bgp::PeerRouteDirection,
        routes: Vec<BgpRoute>,
    ) {
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
        ip: IpAddr,
        dir: crate::bgp::PeerRouteDirection,
        err: String,
    ) {
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

    pub fn request_mtu_probe(&self, target: IpAddr) {
        let Some(router) = self.selected_router() else {
            return;
        };
        self.send_fetch(FetchRequest::FetchMtu {
            router_id: router.id,
            target,
        });
    }

    /// Called when a path-MTU probe returns a result.
    pub fn handle_mtu_probe_result(&mut self, _id: Uuid, ip: IpAddr, max_bytes: u16) {
        use crate::bgp::MtuProbeState;
        let state = if max_bytes >= 1500 {
            MtuProbeState::Ok(max_bytes)
        } else if max_bytes > 0 {
            MtuProbeState::Degraded(max_bytes)
        } else {
            MtuProbeState::Failed("all probes failed".into())
        };
        if let Some(peer) = self.current_peers.iter_mut().find(|p| p.neighbor_ip == ip) {
            peer.mtu_probe = Some(state.clone());
        }
        let msg = match &state {
            MtuProbeState::Ok(n) => format!("MTU probe {ip}: OK (path MTU ≥ {n} B)"),
            MtuProbeState::Degraded(n) => format!("MTU probe {ip}: degraded — max frame {n} B"),
            MtuProbeState::Failed(e) => format!("MTU probe {ip}: failed — {e}"),
            MtuProbeState::Running => unreachable!(),
        };
        self.set_status(msg);
    }

    /// Called when a path-MTU probe SSH call fails entirely.
    pub fn handle_mtu_probe_error(&mut self, _id: Uuid, ip: IpAddr, err: String) {
        if let Some(peer) = self.current_peers.iter_mut().find(|p| p.neighbor_ip == ip) {
            peer.mtu_probe = Some(crate::bgp::MtuProbeState::Failed(err.clone()));
        }
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
