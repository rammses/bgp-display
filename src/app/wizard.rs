use super::types::{WizardMode, WizardStep};
use super::App;
use crate::bgp::NeighborDraft;
use crate::events::FetchRequest;
use crate::router::RouterVendor;
use std::net::IpAddr;

impl App {
    pub fn wizard_open_create(&mut self) {
        self.wizard_mode = WizardMode::NeighborCreate;
        self.wizard_step = WizardStep::Fields;
        self.wizard_field = 0;
        self.wizard_buf.clear();
        self.wizard_draft = Some(NeighborDraft::default());
        self.wizard_preview.clear();
        self.wizard_error = None;
        self.wizard_result_msg = None;
    }

    pub fn wizard_open_edit(&mut self, peer_ip: IpAddr) {
        let router_id = self.selected_router().map(|r| r.id);

        // Prefer the stored desired-state draft (has password etc.)
        let from_desired = router_id.and_then(|rid| {
            self.desired_neighbors.get(&rid).and_then(|neighbors| {
                neighbors
                    .iter()
                    .find(|d| d.neighbor_ip.trim() == peer_ip.to_string())
                    .cloned()
            })
        });

        let draft = if let Some(d) = from_desired {
            d
        } else if let Some(peer) = self.current_peers.iter().find(|p| p.neighbor_ip == peer_ip) {
            NeighborDraft {
                router_id,
                neighbor_ip: peer.neighbor_ip.to_string(),
                remote_as: peer.remote_as.to_string(),
                description: peer.description.clone().unwrap_or_default(),
                update_source: peer
                    .update_source
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                next_hop_self: peer.next_hop_self,
                route_reflector_client: peer.route_reflector_client,
                hold_time: peer.hold_time.to_string(),
                keepalive: peer.keepalive.to_string(),
                bfd: peer.bfd_state.is_some(),
                address_family: crate::bgp::AddressFamily::from_ip(&peer.neighbor_ip.to_string()),
                ..Default::default()
            }
        } else {
            return;
        };

        self.wizard_mode = WizardMode::NeighborEdit(peer_ip);
        self.wizard_step = WizardStep::Fields;
        self.wizard_field = 0;
        self.wizard_buf = draft.field_value(0);
        self.wizard_draft = Some(draft);
        self.wizard_preview.clear();
        self.wizard_error = None;
        self.wizard_result_msg = None;
    }

    pub fn wizard_open_delete(&mut self, peer_ip: IpAddr) {
        self.wizard_mode = WizardMode::NeighborDelete(peer_ip);
        self.wizard_step = WizardStep::Review;
        self.wizard_error = None;
        self.wizard_result_msg = None;

        if let Some(peer) = self.current_peers.iter().find(|p| p.neighbor_ip == peer_ip) {
            let desc = peer.description.clone().unwrap_or_default();
            let local_as = self
                .current_summary
                .as_ref()
                .map(|s| s.local_as)
                .unwrap_or(0);
            let vendor = self
                .selected_router()
                .map(|r| r.vendor.clone())
                .unwrap_or(RouterVendor::Cisco);
            self.wizard_preview = crate::router::commands::delete_neighbor_commands(
                &vendor, peer_ip, local_as, &desc,
            );
        }
    }

    pub fn wizard_close(&mut self) {
        self.wizard_mode = WizardMode::Closed;
        self.wizard_step = WizardStep::Fields;
        self.wizard_draft = None;
        self.wizard_preview.clear();
        self.wizard_error = None;
        self.wizard_result_msg = None;
        self.wizard_diff.clear();
    }

    pub fn load_config_history(&mut self) {
        if let Some(router) = self.selected_router() {
            let rid = router.id;
            if let Some(db) = &self.router_db {
                self.config_history = db.load_config_history(rid).unwrap_or_default();
            }
        }
    }

    pub fn execute_rollback(&mut self, idx: usize) {
        if idx >= self.config_history.len() {
            return;
        }
        let entry = self.config_history[idx].clone();
        if entry.rollback.is_empty() {
            self.set_status("No rollback commands available for this entry");
            return;
        }
        self.send_fetch(FetchRequest::RollbackConfig {
            router_id: entry.router_id,
            history_id: entry.id,
            commands: entry.rollback.clone(),
            description: format!("Rollback: {}", entry.description),
        });
        self.set_status(format!("Rolling back: {}", entry.description));
    }

    pub fn wizard_generate_preview(&mut self) {
        if let Some(draft) = &self.wizard_draft {
            if let Err(e) = draft.validate() {
                self.wizard_error = Some(e);
                return;
            }
            self.wizard_error = None;
            let local_as = self
                .current_summary
                .as_ref()
                .map(|s| s.local_as)
                .unwrap_or(0);
            let vendor = self
                .selected_router()
                .map(|r| r.vendor.clone())
                .unwrap_or(RouterVendor::Cisco);
            self.wizard_preview =
                crate::router::commands::create_neighbor_commands(&vendor, draft, local_as);

            self.wizard_diff.clear();
            if let WizardMode::NeighborEdit(ip) = &self.wizard_mode {
                let router_id = self.selected_router().map(|r| r.id);
                let old_draft = router_id.and_then(|rid| {
                    self.desired_neighbors.get(&rid).and_then(|neighbors| {
                        neighbors
                            .iter()
                            .find(|d| d.neighbor_ip.trim() == ip.to_string())
                            .cloned()
                    })
                });
                if let Some(old) = old_draft {
                    for i in 0..NeighborDraft::NFIELDS {
                        let old_val = old.field_value(i);
                        let new_val = draft.field_value(i);
                        if old_val != new_val {
                            self.wizard_diff.push((
                                NeighborDraft::FIELDS[i].to_string(),
                                format!("{old_val} → {new_val}"),
                            ));
                        }
                    }
                }
            }

            self.wizard_step = WizardStep::Review;
        }
    }

    pub fn wizard_apply(&mut self) {
        if self.wizard_preview.is_empty() {
            return;
        }
        let router_id = match self.selected_router() {
            Some(r) => r.id,
            None => return,
        };
        let vendor = self
            .selected_router()
            .map(|r| r.vendor.clone())
            .unwrap_or(RouterVendor::Cisco);
        let local_as = self
            .current_summary
            .as_ref()
            .map(|s| s.local_as)
            .unwrap_or(0);

        let (description, action, rollback) = match &self.wizard_mode {
            WizardMode::NeighborCreate => {
                let desc = self
                    .wizard_draft
                    .as_ref()
                    .map(|d| d.description.clone())
                    .unwrap_or_default();
                let ip_str = self
                    .wizard_draft
                    .as_ref()
                    .and_then(|d| d.parsed_ip())
                    .map(|ip| ip.to_string())
                    .unwrap_or_default();
                let rb = if !ip_str.is_empty() {
                    crate::router::commands::delete_neighbor_commands(
                        &vendor,
                        ip_str.parse().unwrap(),
                        local_as,
                        &desc,
                    )
                } else {
                    vec![]
                };
                (format!("Create neighbor {desc}"), "neighbor_create", rb)
            }
            WizardMode::NeighborEdit(ip) => {
                // Rollback is re-applying the old draft from desired_neighbors
                let rb = self
                    .desired_neighbors
                    .get(&router_id)
                    .and_then(|neighbors| {
                        neighbors
                            .iter()
                            .find(|d| d.neighbor_ip.trim() == ip.to_string())
                    })
                    .map(|old_draft| {
                        crate::router::commands::create_neighbor_commands(
                            &vendor, old_draft, local_as,
                        )
                    })
                    .unwrap_or_default();
                (format!("Update neighbor {ip}"), "neighbor_edit", rb)
            }
            WizardMode::NeighborDelete(ip) => {
                // Rollback is re-creating from the stored draft
                let rb = self
                    .desired_neighbors
                    .get(&router_id)
                    .and_then(|neighbors| {
                        neighbors
                            .iter()
                            .find(|d| d.neighbor_ip.trim() == ip.to_string())
                    })
                    .map(|old_draft| {
                        crate::router::commands::create_neighbor_commands(
                            &vendor, old_draft, local_as,
                        )
                    })
                    .unwrap_or_default();
                (format!("Delete neighbor {ip}"), "neighbor_delete", rb)
            }
            WizardMode::RouteMapEdit(name) => {
                (format!("Update route-map {name}"), "routemap_save", vec![])
            }
            WizardMode::PrefixListEdit(name) => (
                format!("Update prefix-list {name}"),
                "prefixlist_save",
                vec![],
            ),
            WizardMode::CommunityListEdit(name) => (
                format!("Update community-list {name}"),
                "communitylist_save",
                vec![],
            ),
            WizardMode::Closed => return,
        };

        // Store config history for rollback
        if let Some(db) = &self.router_db {
            let _ = db.insert_config_history(
                router_id,
                action,
                &description,
                &self.wizard_preview,
                &rollback,
            );
        }

        self.wizard_step = WizardStep::Applying;
        self.send_fetch(FetchRequest::ApplyConfig {
            router_id,
            commands: self.wizard_preview.clone(),
            description,
        });
    }
}
