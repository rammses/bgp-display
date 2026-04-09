use super::App;

impl App {
    // ── Filter helpers ────────────────────────────────────────────────────────

    /// Recompute `peer_indices` from the current filter and peers list.
    pub fn update_peer_filter(&mut self) {
        let filter = self.peer_filter.to_lowercase();
        self.peer_indices = (0..self.current_peers.len())
            .filter(|&i| {
                if filter.is_empty() {
                    return true;
                }
                let p = &self.current_peers[i];
                p.neighbor_ip.to_string().contains(&filter)
                    || p.remote_as.to_string().contains(&filter)
                    || p.state.as_str().to_lowercase().contains(&filter)
                    || p.description
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&filter)
                    || p.route_map_in
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&filter)
                    || p.route_map_out
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&filter)
                    || p.session_type().to_lowercase().contains(&filter)
            })
            .collect();
        // Keep selection valid
        match self.peer_table_state.selected() {
            Some(i) if i >= self.peer_indices.len() => {
                self.peer_table_state
                    .select(if self.peer_indices.is_empty() {
                        None
                    } else {
                        Some(0)
                    });
            }
            None if !self.peer_indices.is_empty() => {
                self.peer_table_state.select(Some(0));
            }
            _ => {}
        }
    }

    /// Recompute `route_indices` from the current filter and routes list.
    pub fn update_route_filter(&mut self) {
        let filter = self.route_filter.to_lowercase();
        self.route_indices = (0..self.current_routes.len())
            .filter(|&i| {
                if filter.is_empty() {
                    return true;
                }
                let r = &self.current_routes[i];
                r.network.to_lowercase().contains(&filter)
                    || r.next_hop.to_lowercase().contains(&filter)
                    || r.as_path_str().contains(&filter)
                    || r.communities
                        .iter()
                        .any(|c| c.to_lowercase().contains(&filter))
                    || r.origin.to_string().to_lowercase().contains(&filter)
            })
            .collect();
        match self.route_table_state.selected() {
            Some(i) if i >= self.route_indices.len() => {
                self.route_table_state
                    .select(if self.route_indices.is_empty() {
                        None
                    } else {
                        Some(0)
                    });
            }
            None if !self.route_indices.is_empty() => {
                self.route_table_state.select(Some(0));
            }
            _ => {}
        }
    }

    pub fn update_config_filter(&mut self) {
        let filter = self.config_filter.to_lowercase();
        self.config_indices = (0..self.config_lines.len())
            .filter(|&i| {
                if filter.is_empty() {
                    return true;
                }
                self.config_lines[i].to_lowercase().contains(&filter)
            })
            .collect();
        match self.config_list_state.selected() {
            Some(i) if i >= self.config_indices.len() => {
                self.config_list_state
                    .select(if self.config_indices.is_empty() {
                        None
                    } else {
                        Some(0)
                    });
            }
            None if !self.config_indices.is_empty() => {
                self.config_list_state.select(Some(0));
            }
            _ => {}
        }
    }

    pub fn update_log_filter(&mut self) {
        let filter = self.log_filter.to_lowercase();
        self.log_indices = (0..self.logs.len())
            .filter(|&i| {
                if filter.is_empty() {
                    return true;
                }
                self.logs[i].to_lowercase().contains(&filter)
            })
            .collect();
        match self.log_list_state.selected() {
            Some(i) if i >= self.log_indices.len() => {
                self.log_list_state.select(if self.log_indices.is_empty() {
                    None
                } else {
                    Some(0)
                });
            }
            None if !self.log_indices.is_empty() => {
                self.log_list_state.select(Some(0));
            }
            _ => {}
        }
    }

    pub fn update_conn_log_filter(&mut self) {
        let filter = self.conn_log_filter.to_lowercase();
        self.conn_log_indices = (0..self.conn_logs.len())
            .filter(|&i| {
                if filter.is_empty() {
                    return true;
                }
                self.conn_logs[i].to_lowercase().contains(&filter)
            })
            .collect();
        match self.conn_log_state.selected() {
            Some(i) if i >= self.conn_log_indices.len() => {
                self.conn_log_state
                    .select(if self.conn_log_indices.is_empty() {
                        None
                    } else {
                        Some(0)
                    });
            }
            None if !self.conn_log_indices.is_empty() => {
                self.conn_log_state.select(Some(0));
            }
            _ => {}
        }
    }
}
