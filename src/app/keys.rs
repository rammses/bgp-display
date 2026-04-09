use crate::bgp::{BgpRoute, MtuProbeState, PeerRouteDirection};
use crate::router::RouterVendor;

use super::helpers::extract_routemap_name_from_line;
use super::types::{ActiveTab, EditorMode, FilterMode, ProjectEditorMode, WizardMode};
use super::wizard_keys::handle_wizard_key;
use super::App;

// ─── Key Handler ─────────────────────────────────────────────────────────────

pub fn handle_key(app: &mut App, key: crossterm::event::KeyEvent) {
    use crossterm::event::{KeyCode, KeyModifiers};

    // ── Confirmation dialog intercepts all input ─────────────────────────────
    if app.confirm_action.is_some() {
        match key.code {
            KeyCode::Char('y') | KeyCode::Enter => app.confirm_action_execute(),
            KeyCode::Char('n') | KeyCode::Esc => app.confirm_action_cancel(),
            _ => {}
        }
        return;
    }

    // ── Config history popup intercepts all input ────────────────────────────
    if app.show_history {
        match key.code {
            KeyCode::Esc | KeyCode::Char('h') => {
                app.show_history = false;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let i = app.history_list_state.selected().unwrap_or(0);
                if i > 0 {
                    app.history_list_state.select(Some(i - 1));
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let i = app.history_list_state.selected().unwrap_or(0);
                let max = app.config_history.len().saturating_sub(1);
                app.history_list_state.select(Some((i + 1).min(max)));
            }
            KeyCode::Char('u') => {
                if let Some(idx) = app.history_list_state.selected() {
                    app.execute_rollback(idx);
                    app.show_history = false;
                }
            }
            _ => {}
        }
        return;
    }

    // ── Help overlay intercepts all input ────────────────────────────────────
    if app.show_help {
        app.show_help = false;
        return;
    }

    // ── Clone-neighbor popup intercepts all input ────────────────────────────
    if app.clone_draft.is_some() {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(i) = app.clone_target_router.as_mut() {
                    if *i > 0 {
                        *i -= 1;
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(i) = app.clone_target_router.as_mut() {
                    let max = app.all_routers.len().saturating_sub(1);
                    *i = (*i + 1).min(max);
                }
            }
            KeyCode::Enter => app.execute_clone(),
            KeyCode::Esc => app.cancel_clone(),
            _ => {}
        }
        return;
    }

    // ── Router editor captures all input while editing a field ────────────────
    if app.current_tab == ActiveTab::Routers && app.editor_mode == EditorMode::EditField {
        match key.code {
            KeyCode::Esc => {
                app.editor_mode = EditorMode::Browse;
                app.editor_draft = None;
                app.editor_buf.clear();
                app.set_status("Edit cancelled");
            }
            KeyCode::Backspace => {
                app.editor_buf.pop();
            }
            KeyCode::Tab => app.editor_commit_and_advance(),
            KeyCode::Enter => app.editor_commit_and_advance(),
            KeyCode::BackTab => app.editor_commit_and_retreat(),
            // Vendor field (5): Space cycles Cisco ↔ VyOs; other chars are ignored
            KeyCode::Char(' ') if app.editor_field == 5 => {
                if let Some(draft) = app.editor_draft.as_mut() {
                    draft.vendor = match draft.vendor {
                        RouterVendor::Cisco => RouterVendor::VyOs,
                        RouterVendor::VyOs => RouterVendor::CitrixVpx,
                        RouterVendor::CitrixVpx => RouterVendor::PfSense,
                        RouterVendor::PfSense => RouterVendor::FortiGate,
                        RouterVendor::FortiGate => RouterVendor::A10,
                        RouterVendor::A10 => RouterVendor::Cisco,
                    };
                    app.editor_buf = draft.vendor.to_string();
                }
            }
            KeyCode::Char(_) if app.editor_field == 5 => {
                // vendor field is cycle-only; ignore free text
            }
            KeyCode::Char(c) => app.editor_buf.push(c),
            _ => {}
        }
        return;
    }

    // ── Wizard popup captures all input when open ─────────────────────────────
    if app.wizard_mode != WizardMode::Closed {
        handle_wizard_key(app, key);
        return;
    }

    // ── Project popup captures all input when open ───────────────────────────
    if app.project_popup {
        match app.project_editor_mode {
            ProjectEditorMode::EditName => {
                match key.code {
                    KeyCode::Esc => {
                        app.project_editor_mode = ProjectEditorMode::Browse;
                        app.project_editor_buf.clear();
                    }
                    KeyCode::Backspace => {
                        app.project_editor_buf.pop();
                    }
                    KeyCode::Enter => app.project_save_name(),
                    KeyCode::Char(c) => app.project_editor_buf.push(c),
                    _ => {}
                }
                return;
            }
            ProjectEditorMode::ToggleRouters => {
                match key.code {
                    KeyCode::Esc | KeyCode::Enter => {
                        app.project_editor_mode = ProjectEditorMode::Browse;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.all_routers.is_empty() {
                            return;
                        }
                        let next = match app.project_toggle_state.selected() {
                            Some(0) | None => app.all_routers.len() - 1,
                            Some(i) => i - 1,
                        };
                        app.project_toggle_state.select(Some(next));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.all_routers.is_empty() {
                            return;
                        }
                        let next = match app.project_toggle_state.selected() {
                            Some(i) => (i + 1) % app.all_routers.len(),
                            None => 0,
                        };
                        app.project_toggle_state.select(Some(next));
                    }
                    KeyCode::Char(' ') => app.project_toggle_router(),
                    _ => {}
                }
                return;
            }
            ProjectEditorMode::Browse => {
                match key.code {
                    KeyCode::Esc | KeyCode::Char('p') => {
                        app.project_popup = false;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.projects.is_empty() {
                            return;
                        }
                        let next = match app.project_list_state.selected() {
                            Some(0) | None => app.projects.len() - 1,
                            Some(i) => i - 1,
                        };
                        app.project_list_state.select(Some(next));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.projects.is_empty() {
                            return;
                        }
                        let next = match app.project_list_state.selected() {
                            Some(i) => (i + 1) % app.projects.len(),
                            None => 0,
                        };
                        app.project_list_state.select(Some(next));
                    }
                    KeyCode::Enter => {
                        let idx = app.project_list_state.selected();
                        app.select_project(idx);
                        app.project_popup = false;
                    }
                    KeyCode::Char('0') => {
                        app.select_project(None);
                        app.project_popup = false;
                    }
                    KeyCode::Char('a') => app.project_add(),
                    KeyCode::Char('d') => app.project_request_delete(),
                    KeyCode::Char('e') => app.project_enter_toggle_routers(),
                    _ => {}
                }
                return;
            }
        }
    }

    // ── Filter input capture (Peers / Routes tab, while Typing) ────────────────────
    if app.peer_filter_mode == FilterMode::Typing && app.current_tab == ActiveTab::Peers {
        match key.code {
            KeyCode::Esc => {
                app.peer_filter.clear();
                app.peer_filter_mode = FilterMode::Off;
                app.update_peer_filter();
            }
            KeyCode::Enter => {
                app.peer_filter_mode = if app.peer_filter.is_empty() {
                    FilterMode::Off
                } else {
                    FilterMode::Active
                };
            }
            KeyCode::Backspace => {
                app.peer_filter.pop();
                app.update_peer_filter();
            }
            KeyCode::Char(c) => {
                app.peer_filter.push(c);
                app.update_peer_filter();
            }
            _ => {}
        }
        return;
    }
    if app.route_filter_mode == FilterMode::Typing && app.current_tab == ActiveTab::Routes {
        match key.code {
            KeyCode::Esc => {
                app.route_filter.clear();
                app.route_filter_mode = FilterMode::Off;
                app.update_route_filter();
            }
            KeyCode::Enter => {
                app.route_filter_mode = if app.route_filter.is_empty() {
                    FilterMode::Off
                } else {
                    FilterMode::Active
                };
            }
            KeyCode::Backspace => {
                app.route_filter.pop();
                app.update_route_filter();
            }
            KeyCode::Char(c) => {
                app.route_filter.push(c);
                app.update_route_filter();
            }
            _ => {}
        }
        return;
    }
    if app.config_filter_mode == FilterMode::Typing && app.current_tab == ActiveTab::Config {
        match key.code {
            KeyCode::Esc => {
                app.config_filter.clear();
                app.config_filter_mode = FilterMode::Off;
                app.update_config_filter();
            }
            KeyCode::Enter => {
                app.config_filter_mode = if app.config_filter.is_empty() {
                    FilterMode::Off
                } else {
                    FilterMode::Active
                };
            }
            KeyCode::Backspace => {
                app.config_filter.pop();
                app.update_config_filter();
            }
            KeyCode::Char(c) => {
                app.config_filter.push(c);
                app.update_config_filter();
            }
            _ => {}
        }
        return;
    }
    if app.log_filter_mode == FilterMode::Typing && app.current_tab == ActiveTab::Logs {
        match key.code {
            KeyCode::Esc => {
                app.log_filter.clear();
                app.log_filter_mode = FilterMode::Off;
                app.update_log_filter();
            }
            KeyCode::Enter => {
                app.log_filter_mode = if app.log_filter.is_empty() {
                    FilterMode::Off
                } else {
                    FilterMode::Active
                };
            }
            KeyCode::Backspace => {
                app.log_filter.pop();
                app.update_log_filter();
            }
            KeyCode::Char(c) => {
                app.log_filter.push(c);
                app.update_log_filter();
            }
            _ => {}
        }
        return;
    }
    if app.conn_log_filter_mode == FilterMode::Typing && app.current_tab == ActiveTab::ConnLog {
        match key.code {
            KeyCode::Esc => {
                app.conn_log_filter.clear();
                app.conn_log_filter_mode = FilterMode::Off;
                app.update_conn_log_filter();
            }
            KeyCode::Enter => {
                app.conn_log_filter_mode = if app.conn_log_filter.is_empty() {
                    FilterMode::Off
                } else {
                    FilterMode::Active
                };
            }
            KeyCode::Backspace => {
                app.conn_log_filter.pop();
                app.update_conn_log_filter();
            }
            KeyCode::Char(c) => {
                app.conn_log_filter.push(c);
                app.update_conn_log_filter();
            }
            _ => {}
        }
        return;
    }

    // ── Per-peer route drill-down: capture all input while view is open ───────
    if app.peer_route_view.is_some() && app.current_tab == ActiveTab::Peers {
        match key.code {
            KeyCode::Esc => {
                app.close_peer_route_view();
            }
            KeyCode::Char('i') => {
                if app.peer_route_view.as_ref().map(|v| v.direction)
                    != Some(PeerRouteDirection::Received)
                {
                    app.toggle_peer_route_direction();
                }
            }
            KeyCode::Char('o') => {
                if app.peer_route_view.as_ref().map(|v| v.direction)
                    != Some(PeerRouteDirection::Advertised)
                {
                    app.toggle_peer_route_direction();
                }
            }
            KeyCode::Tab => {
                app.toggle_peer_route_direction();
            }
            KeyCode::Char('r') | KeyCode::F(5) => {
                let (ip, dir) = match app.peer_route_view.as_mut() {
                    Some(view) => {
                        view.routes = None;
                        view.error = None;
                        (view.peer_ip, view.direction)
                    }
                    None => return,
                };
                app.request_peer_routes_fetch(ip, dir);
                app.set_status(format!("Refreshing {} routes for {}…", dir.label(), ip));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let len = app
                    .peer_route_view
                    .as_ref()
                    .and_then(|v| v.routes.as_ref())
                    .map(|r: &Vec<BgpRoute>| r.len())
                    .unwrap_or(0);
                if len > 0 {
                    let next = match app.peer_route_table_state.selected() {
                        Some(0) | None => len - 1,
                        Some(i) => i - 1,
                    };
                    app.peer_route_table_state.select(Some(next));
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let len = app
                    .peer_route_view
                    .as_ref()
                    .and_then(|v| v.routes.as_ref())
                    .map(|r: &Vec<BgpRoute>| r.len())
                    .unwrap_or(0);
                if len > 0 {
                    let next = match app.peer_route_table_state.selected() {
                        Some(i) => (i + 1) % len,
                        None => 0,
                    };
                    app.peer_route_table_state.select(Some(next));
                }
            }
            _ => {}
        }
        return;
    }

    // Global quit
    match (key.code, key.modifiers) {
        (KeyCode::Char('q'), _) | (KeyCode::Char('Q'), _) => {
            app.should_quit = true;
            return;
        }
        (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
            app.should_quit = true;
            return;
        }
        _ => {}
    }

    match key.code {
        // ── Tab switching ────────────────────────────────────────────────────
        KeyCode::Tab => {
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = app.current_tab.next();
        }
        KeyCode::BackTab => {
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = app.current_tab.prev();
        }
        KeyCode::Char('1') => {
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = ActiveTab::Dashboard;
            app.bgp_refresh_tick = 149;
        }
        KeyCode::Char('2') => {
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = ActiveTab::Peers;
            app.bgp_refresh_tick = 149;
        }
        KeyCode::Char('3') => {
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = ActiveTab::Routes;
            app.bgp_refresh_tick = 149;
        }
        KeyCode::Char('4') => app.current_tab = ActiveTab::Config,
        KeyCode::Char('5') => {
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = ActiveTab::Logs;
            app.bgp_refresh_tick = 149;
        }
        KeyCode::Char('6') => {
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = ActiveTab::Routers;
            app.bgp_refresh_tick = 149;
        }
        KeyCode::Char('7') => {
            if app.current_tab == ActiveTab::Config && app.has_pending_update {
                app.accept_pending_update();
            }
            app.current_tab = ActiveTab::ConnLog;
            app.bgp_refresh_tick = 149;
        }

        // ── Navigation ───────────────────────────────────────────────────────
        KeyCode::Up | KeyCode::Char('k') => navigate_up(app),
        KeyCode::Down | KeyCode::Char('j') => navigate_down(app),

        // ── Help overlay ─────────────────────────────────────────────────────
        KeyCode::Char('?') => {
            app.show_help = !app.show_help;
        }

        // ── Open filter ──────────────────────────────────────────────────────
        KeyCode::Char('/') if app.current_tab == ActiveTab::Peers => {
            app.peer_filter_mode = FilterMode::Typing;
        }
        KeyCode::Char('/') if app.current_tab == ActiveTab::Routes => {
            app.route_filter_mode = FilterMode::Typing;
        }
        KeyCode::Char('/') if app.current_tab == ActiveTab::Config => {
            app.config_filter_mode = FilterMode::Typing;
        }
        KeyCode::Char('/') if app.current_tab == ActiveTab::Logs => {
            app.log_filter_mode = FilterMode::Typing;
        }
        KeyCode::Char('/') if app.current_tab == ActiveTab::ConnLog => {
            app.conn_log_filter_mode = FilterMode::Typing;
        }

        // ── Dismiss active filter with Esc ───────────────────────────────────
        KeyCode::Esc
            if app.current_tab == ActiveTab::Peers && app.peer_filter_mode != FilterMode::Off =>
        {
            app.peer_filter.clear();
            app.peer_filter_mode = FilterMode::Off;
            app.update_peer_filter();
        }
        KeyCode::Esc
            if app.current_tab == ActiveTab::Routes && app.route_filter_mode != FilterMode::Off =>
        {
            app.route_filter.clear();
            app.route_filter_mode = FilterMode::Off;
            app.update_route_filter();
        }
        KeyCode::Esc
            if app.current_tab == ActiveTab::Config
                && app.config_filter_mode != FilterMode::Off =>
        {
            app.config_filter.clear();
            app.config_filter_mode = FilterMode::Off;
            app.update_config_filter();
        }
        KeyCode::Esc
            if app.current_tab == ActiveTab::Logs && app.log_filter_mode != FilterMode::Off =>
        {
            app.log_filter.clear();
            app.log_filter_mode = FilterMode::Off;
            app.update_log_filter();
        }
        KeyCode::Esc
            if app.current_tab == ActiveTab::ConnLog
                && app.conn_log_filter_mode != FilterMode::Off =>
        {
            app.conn_log_filter.clear();
            app.conn_log_filter_mode = FilterMode::Off;
            app.update_conn_log_filter();
        }

        // ── Scroll route-map detail (Config tab) ─────────────────────────────
        KeyCode::PageDown => {
            if app.current_tab == ActiveTab::Config && app.config_routemap.is_some() {
                app.routemap_detail_scroll = app.routemap_detail_scroll.saturating_add(10);
            }
        }
        KeyCode::PageUp => {
            if app.current_tab == ActiveTab::Config && app.config_routemap.is_some() {
                app.routemap_detail_scroll = app.routemap_detail_scroll.saturating_sub(10);
            }
        }

        // ── Refresh ──────────────────────────────────────────────────────────
        KeyCode::Char('r') | KeyCode::F(5) => {
            app.reload_selected_router();
            app.request_refresh_selected();
            app.set_status("Refreshing…");
            app.log("Manual refresh triggered");
            app.request_ping();
        }

        // ── Config history popup (Config tab) ─────────────────────────────────
        KeyCode::Char('h') if app.current_tab == ActiveTab::Config => {
            app.load_config_history();
            app.show_history = true;
            if !app.config_history.is_empty() {
                app.history_list_state.select(Some(0));
            }
        }

        // ── Accept / dismiss pending BGP update (Config tab) ─────────────────
        KeyCode::Char('y') if app.current_tab == ActiveTab::Config && app.has_pending_update => {
            app.accept_pending_update();
        }
        KeyCode::Char('n') if app.current_tab == ActiveTab::Config && app.has_pending_update => {
            app.dismiss_pending_update();
            app.set_status("Update dismissed");
        }

        // ── Project selector ─────────────────────────────────────────────────
        KeyCode::Char('p') => {
            app.project_popup = true;
            if !app.projects.is_empty() && app.project_list_state.selected().is_none() {
                app.project_list_state.select(Some(0));
            }
            app.set_status(
                "Projects — Enter: switch  a: add  d: delete  e: edit routers  0: all  Esc: close",
            );
        }

        // ── Router editor actions (Routers tab only) ──────────────────────────
        KeyCode::Char('a') if app.current_tab == ActiveTab::Routers => {
            app.editor_start_add();
        }
        KeyCode::Char('d') if app.current_tab == ActiveTab::Routers => {
            app.editor_request_delete();
        }
        KeyCode::Char('s') if app.current_tab == ActiveTab::Routers => {
            app.editor_save_config();
        }
        KeyCode::Enter if app.current_tab == ActiveTab::Routers => {
            app.editor_start_edit();
        }

        // ── Open per-peer route view (Peers tab) ─────────────────────────────
        KeyCode::Enter if app.current_tab == ActiveTab::Peers => {
            app.open_peer_route_view(PeerRouteDirection::Received);
        }
        KeyCode::Char('i') if app.current_tab == ActiveTab::Peers => {
            app.open_peer_route_view(PeerRouteDirection::Received);
        }
        KeyCode::Char('o') if app.current_tab == ActiveTab::Peers => {
            app.open_peer_route_view(PeerRouteDirection::Advertised);
        }

        // ── Path-MTU probe (Peers tab) ──────────────────────────────────────
        KeyCode::Char('m') if app.current_tab == ActiveTab::Peers => {
            if let Some(ip) = app
                .peer_table_state
                .selected()
                .and_then(|i| app.peer_indices.get(i))
                .and_then(|&idx| app.current_peers.get(idx))
                .map(|p| p.neighbor_ip)
            {
                if let Some(peer) = app.current_peers.iter_mut().find(|p| p.neighbor_ip == ip) {
                    peer.mtu_probe = Some(MtuProbeState::Running);
                }
                app.request_mtu_probe(ip);
                app.set_status(format!("Running MTU probe to {ip}…"));
            }
        }

        // ── Neighbor shutdown toggle (Peers tab) ────────────────────────────
        KeyCode::Char('s')
            if app.current_tab == ActiveTab::Peers && app.peer_route_view.is_none() =>
        {
            app.toggle_peer_shutdown();
        }

        // ── BGP Neighbor Wizard (Peers tab) ─────────────────────────────────
        KeyCode::Char('n')
            if app.current_tab == ActiveTab::Peers || app.current_tab == ActiveTab::Dashboard =>
        {
            app.wizard_open_create();
        }
        KeyCode::Char('e')
            if app.current_tab == ActiveTab::Peers && app.peer_route_view.is_none() =>
        {
            if let Some(ip) = app
                .peer_table_state
                .selected()
                .and_then(|i| app.peer_indices.get(i))
                .and_then(|&idx| app.current_peers.get(idx))
                .map(|p| p.neighbor_ip)
            {
                app.wizard_open_edit(ip);
            }
        }
        KeyCode::Char('x')
            if app.current_tab == ActiveTab::Peers && app.peer_route_view.is_none() =>
        {
            if let Some(ip) = app
                .peer_table_state
                .selected()
                .and_then(|i| app.peer_indices.get(i))
                .and_then(|&idx| app.current_peers.get(idx))
                .map(|p| p.neighbor_ip)
            {
                app.wizard_open_delete(ip);
            }
        }
        KeyCode::Char('c')
            if app.current_tab == ActiveTab::Peers && app.peer_route_view.is_none() =>
        {
            app.start_clone_peer();
        }

        // ── Route-map / Prefix-list / Community-list editors (Config tab) ──
        KeyCode::Char('e') if app.current_tab == ActiveTab::Config => {
            if let Some(line) = app
                .config_list_state
                .selected()
                .and_then(|i| app.config_lines.get(i))
            {
                let trimmed = line.trim();
                if trimmed.contains("route-map") {
                    if let Some(name) = extract_routemap_name_from_line(trimmed) {
                        app.open_routemap_editor(&name);
                    }
                } else if trimmed.contains("prefix-list") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if let Some(pos) = parts.iter().position(|&p| p == "prefix-list") {
                        if let Some(name) = parts.get(pos + 1) {
                            let name = name.trim_end_matches(':').to_string();
                            app.open_prefixlist_editor(&name);
                        }
                    }
                } else if trimmed.contains("community-list") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if let Some(pos) = parts.iter().position(|&p| p == "community-list") {
                        let name_pos = if parts
                            .get(pos + 1)
                            .map(|&s| s == "standard" || s == "expanded")
                            .unwrap_or(false)
                        {
                            pos + 2
                        } else {
                            pos + 1
                        };
                        if let Some(name) = parts.get(name_pos) {
                            let name = name.to_string();
                            app.open_communitylist_editor(&name);
                        }
                    }
                }
            }
        }

        // ── Direct prefix-list editor (Config tab, creates new if needed) ──
        KeyCode::Char('P') if app.current_tab == ActiveTab::Config => {
            app.open_prefixlist_editor("NEW-PREFIX-LIST");
        }

        // ── Direct community-list editor (Config tab, creates new if needed)
        KeyCode::Char('C') if app.current_tab == ActiveTab::Config => {
            app.open_communitylist_editor("NEW-COMMUNITY-LIST");
        }

        _ => {}
    }
}

fn navigate_up(app: &mut App) {
    match app.current_tab {
        ActiveTab::Dashboard => {
            if app.routers.is_empty() {
                return;
            }
            let next = match app.router_list_state.selected() {
                Some(0) | None => app.routers.len() - 1,
                Some(i) => i - 1,
            };
            app.router_list_state.select(Some(next));
            app.reload_selected_router();
        }
        ActiveTab::Peers => {
            if app.peer_indices.is_empty() {
                return;
            }
            let len = app.peer_indices.len();
            let next = match app.peer_table_state.selected() {
                Some(0) | None => len - 1,
                Some(i) => i - 1,
            };
            app.peer_table_state.select(Some(next));
        }
        ActiveTab::Routes => {
            if app.route_indices.is_empty() {
                return;
            }
            let len = app.route_indices.len();
            let next = match app.route_table_state.selected() {
                Some(0) | None => len - 1,
                Some(i) => i - 1,
            };
            app.route_table_state.select(Some(next));
        }
        ActiveTab::Logs => {
            let len = if app.log_filter_mode != FilterMode::Off {
                app.log_indices.len()
            } else {
                app.logs.len()
            };
            if len == 0 {
                return;
            }
            let next = match app.log_list_state.selected() {
                Some(0) | None => len - 1,
                Some(i) => i - 1,
            };
            app.log_list_state.select(Some(next));
        }
        ActiveTab::Config => {
            let len = if app.config_filter_mode != FilterMode::Off {
                app.config_indices.len()
            } else {
                app.config_lines.len()
            };
            if len == 0 {
                return;
            }
            let next = match app.config_list_state.selected() {
                Some(0) | None => len - 1,
                Some(i) => i - 1,
            };
            app.config_list_state.select(Some(next));
            app.on_config_nav();
        }
        ActiveTab::Routers => {
            if app.routers.is_empty() {
                return;
            }
            let next = match app.editor_list_state.selected() {
                Some(0) | None => app.routers.len() - 1,
                Some(i) => i - 1,
            };
            app.editor_list_state.select(Some(next));
        }
        ActiveTab::ConnLog => {
            let len = if app.conn_log_filter_mode != FilterMode::Off {
                app.conn_log_indices.len()
            } else {
                app.conn_logs.len()
            };
            if len == 0 {
                return;
            }
            let next = match app.conn_log_state.selected() {
                Some(0) | None => len - 1,
                Some(i) => i - 1,
            };
            app.conn_log_state.select(Some(next));
        }
    }
}

fn navigate_down(app: &mut App) {
    match app.current_tab {
        ActiveTab::Dashboard => {
            if app.routers.is_empty() {
                return;
            }
            let next = match app.router_list_state.selected() {
                Some(i) => (i + 1) % app.routers.len(),
                None => 0,
            };
            app.router_list_state.select(Some(next));
            app.reload_selected_router();
        }
        ActiveTab::Peers => {
            if app.peer_indices.is_empty() {
                return;
            }
            let next = match app.peer_table_state.selected() {
                Some(i) => (i + 1) % app.peer_indices.len(),
                None => 0,
            };
            app.peer_table_state.select(Some(next));
        }
        ActiveTab::Routes => {
            if app.route_indices.is_empty() {
                return;
            }
            let next = match app.route_table_state.selected() {
                Some(i) => (i + 1) % app.route_indices.len(),
                None => 0,
            };
            app.route_table_state.select(Some(next));
        }
        ActiveTab::Logs => {
            let len = if app.log_filter_mode != FilterMode::Off {
                app.log_indices.len()
            } else {
                app.logs.len()
            };
            if len == 0 {
                return;
            }
            let next = match app.log_list_state.selected() {
                Some(i) => (i + 1) % len,
                None => 0,
            };
            app.log_list_state.select(Some(next));
        }
        ActiveTab::Config => {
            let len = if app.config_filter_mode != FilterMode::Off {
                app.config_indices.len()
            } else {
                app.config_lines.len()
            };
            if len == 0 {
                return;
            }
            let next = match app.config_list_state.selected() {
                Some(i) => (i + 1) % len,
                None => 0,
            };
            app.config_list_state.select(Some(next));
            app.on_config_nav();
        }
        ActiveTab::Routers => {
            if app.routers.is_empty() {
                return;
            }
            let next = match app.editor_list_state.selected() {
                Some(i) => (i + 1) % app.routers.len(),
                None => 0,
            };
            app.editor_list_state.select(Some(next));
        }
        ActiveTab::ConnLog => {
            let len = if app.conn_log_filter_mode != FilterMode::Off {
                app.conn_log_indices.len()
            } else {
                app.conn_logs.len()
            };
            if len == 0 {
                return;
            }
            let next = match app.conn_log_state.selected() {
                Some(i) => (i + 1) % len,
                None => 0,
            };
            app.conn_log_state.select(Some(next));
        }
    }
}
