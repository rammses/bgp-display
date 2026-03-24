use super::types::{ActiveTab, BgpCache};
use super::App;
use crate::bgp::{BgpRoute, BgpSummary, CommunityListEntry, PrefixListEntry};
use crate::events::FetchRequest;
use crate::router::ConnectionStatus;
use std::net::IpAddr;
use uuid::Uuid;

impl App {
    /// Called when a BGP fetch succeeds.
    pub fn handle_bgp_data(&mut self, id: Uuid, summary: BgpSummary, rendered: String) {
        self.router_status.insert(id, ConnectionStatus::Connected);

        let is_selected = self.selected_router().map(|r| r.id) == Some(id);

        let router_name = self
            .routers
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| id.to_string());

        // Detect peer state transitions by comparing against cached peers.
        // Collect changes first to avoid borrow conflicts with self.log() etc.
        let mut state_changes: Vec<(IpAddr, String, String, bool, bool)> = Vec::new();
        if let Some(cached) = self.bgp_cache.get(&id) {
            for new_peer in &summary.peers {
                if let Some(old_peer) = cached
                    .peers
                    .iter()
                    .find(|p| p.neighbor_ip == new_peer.neighbor_ip)
                {
                    if let Some((old_state, new_state)) = new_peer.state_changed_from(old_peer) {
                        let is_down = old_state == crate::bgp::BgpState::Established
                            && new_state != crate::bgp::BgpState::Established;
                        let is_up = old_state != crate::bgp::BgpState::Established
                            && new_state == crate::bgp::BgpState::Established;
                        state_changes.push((
                            new_peer.neighbor_ip,
                            old_state.to_string(),
                            new_state.to_string(),
                            is_down,
                            is_up,
                        ));
                    }
                }
            }
        }
        for (ip, old_s, new_s, is_down, is_up) in state_changes {
            let arrow = if is_down {
                "▼ DOWN"
            } else if is_up {
                "▲ UP"
            } else {
                "→"
            };
            let msg = format!("[{router_name}] Peer {ip} {arrow}: {old_s} → {new_s}");
            self.log(&msg);
            self.conn_log(&msg);

            let key = (id, ip);
            let history = self.peer_state_history.entry(key).or_default();
            history.push_back((chrono::Utc::now(), old_s.clone(), new_s.clone()));
            while history.len() > 100 {
                history.pop_front();
            }

            if is_down {
                self.peer_down_alert_tick = Some(self.tick_counter);
                self.set_status(format!("⚠ PEER DOWN: {ip} on {router_name}"));
            } else if is_up {
                self.set_status(format!("✓ Peer {ip} on {router_name} is Established"));
            }
        }

        // Check if the data actually changed compared to the cache
        let data_changed = self
            .bgp_cache
            .get(&id)
            .map(|cached| !cached.summary.content_eq(&summary) || cached.config != rendered)
            .unwrap_or(true); // no cache = treat as changed

        // Always update the per-router cache
        let entry = self.bgp_cache.entry(id).or_insert_with(|| BgpCache {
            summary: summary.clone(),
            peers: vec![],
            routes: vec![],
            config: String::new(),
        });
        entry.summary = summary.clone();
        entry.peers = summary.peers.clone();
        entry.config = rendered.clone();

        if is_selected {
            if !data_changed {
                // Data hasn't changed — don't disturb the user at all
                return;
            }

            // If user is actively browsing the Config tab, defer the update
            if self.current_tab == ActiveTab::Config && !self.config_lines.is_empty() {
                self.pending_bgp_update = Some((id, summary, rendered));
                self.has_pending_update = true;
                return;
            }

            // Otherwise apply immediately
            self.apply_bgp_update(id, summary, rendered);
        }
    }

    /// Apply a BGP data update to the displayed state.
    fn apply_bgp_update(&mut self, id: Uuid, summary: BgpSummary, rendered: String) {
        self.current_peers = summary.peers.clone();
        self.current_summary = Some(summary);
        self.rendered_config = rendered;
        self.config_lines = self
            .rendered_config
            .lines()
            .map(|l| l.to_string())
            .collect();
        if !self.config_lines.is_empty() && self.config_list_state.selected().is_none() {
            self.config_list_state.select(Some(0));
        }
        self.config_rm_name = None;
        self.config_routemap = None;
        // Invalidate cached route-map details for this router since BGP data changed
        self.routemap_cache.retain(|&(rid, _), _| rid != id);
        self.update_peer_filter();
    }

    /// Accept pending BGP update and apply it to the displayed state.
    pub fn accept_pending_update(&mut self) {
        if let Some((id, summary, rendered)) = self.pending_bgp_update.take() {
            self.apply_bgp_update(id, summary, rendered);
        }
        if let Some((id, routes)) = self.pending_route_update.take() {
            if let Some(entry) = self.bgp_cache.get_mut(&id) {
                entry.routes = routes.clone();
            }
            self.current_routes = routes;
        }
        self.has_pending_update = false;
        self.update_peer_filter();
        self.update_route_filter();
        self.set_status("Update applied");
        self.log("Pending BGP update applied");
    }

    /// Dismiss pending update notification without applying.
    pub fn dismiss_pending_update(&mut self) {
        self.pending_bgp_update = None;
        self.pending_route_update = None;
        self.has_pending_update = false;
    }

    /// Called when a route table fetch completes.
    pub fn handle_route_data(&mut self, id: Uuid, routes: Vec<BgpRoute>) {
        let is_selected = self.selected_router().map(|r| r.id) == Some(id);

        // Check if routes actually changed
        let data_changed = self
            .bgp_cache
            .get(&id)
            .map(|cached| cached.routes != routes)
            .unwrap_or(true);

        // Always update the cache
        if let Some(entry) = self.bgp_cache.get_mut(&id) {
            entry.routes = routes.clone();
        }

        if is_selected {
            if !data_changed {
                return;
            }

            // If user is on Config tab with a pending BGP update, bundle routes too
            if self.has_pending_update {
                self.pending_route_update = Some((id, routes));
                return;
            }

            self.current_routes = routes;
            self.update_route_filter();
        }
    }

    /// Called when a route-map detail fetch completes.
    pub fn handle_routemap_detail(&mut self, id: Uuid, detail: crate::bgp::RouteMapDetail) {
        self.routemap_cache
            .insert((id, detail.name.clone()), detail.clone());
        if self.config_rm_name.as_deref() == Some(detail.name.as_str()) {
            self.config_routemap = Some(detail);
        }
    }

    pub fn handle_policy_data(
        &mut self,
        router_id: Uuid,
        prefix_lists: std::collections::HashMap<String, Vec<PrefixListEntry>>,
        community_lists: std::collections::HashMap<String, Vec<CommunityListEntry>>,
    ) {
        for (name, entries) in prefix_lists {
            self.prefix_list_cache.insert((router_id, name), entries);
        }
        for (name, entries) in community_lists {
            self.community_list_cache.insert((router_id, name), entries);
        }
    }

    pub(in crate::app) fn request_routemap_fetch(&self, rm_name: String) {
        let Some(router) = self.selected_router() else {
            return;
        };
        self.send_fetch(FetchRequest::FetchRouteMap {
            router_id: router.id,
            rm_name,
        });
    }

    /// Called when the selected config line changes — triggers route-map fetch if applicable.
    pub fn on_config_nav(&mut self) {
        let idx = match self.config_list_state.selected() {
            Some(i) => i,
            None => return,
        };
        let line = self.config_lines.get(idx).cloned().unwrap_or_default();

        if let Some(pl_name) = super::helpers::extract_prefixlist_name_from_line(&line) {
            self.config_rm_name = None;
            self.config_routemap = None;
            self.routemap_fetch_queued = None;
            self.config_pl_name = Some(pl_name);
            return;
        }

        self.config_pl_name = None;

        if let Some(rm_name) = super::helpers::extract_routemap_name_from_line(&line) {
            if self.config_rm_name.as_deref() != Some(&rm_name) {
                self.config_rm_name = Some(rm_name.clone());
                self.routemap_detail_scroll = 0;

                let rid = self.selected_router().map(|r| r.id);
                if let Some(rid) = rid {
                    if let Some(cached) = self.routemap_cache.get(&(rid, rm_name.clone())) {
                        self.config_routemap = Some(cached.clone());
                        return;
                    }
                }

                self.config_routemap = None;
                self.routemap_fetch_queued = Some(rm_name);
            }
        } else {
            self.config_rm_name = None;
            self.config_routemap = None;
            self.routemap_fetch_queued = None;
        }
    }
}
