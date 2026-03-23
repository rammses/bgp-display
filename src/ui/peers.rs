use crate::{
    app::{App, FilterMode},
    bgp::{BgpState, MtuProbeState, PeerRouteDirection, RouteOrigin, RouteStatus},
    ui::{
        fmt_num, state_style, C_BORDER, C_DIM, C_EBGP, C_ERROR, C_ESTABLISHED, C_HEADER, C_IBGP,
        C_SELECTED, C_WARN,
    },
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

// ─── Peers tab ────────────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    // Per-peer route drill-down replaces the normal view
    if app.peer_route_view.is_some() {
        draw_peer_route_view(f, app, area);
        return;
    } // Split off a filter bar between table and detail when filter is active
    let (table_area, filter_area, detail_area) = if app.peer_filter_mode != FilterMode::Off {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),
                Constraint::Length(3),
                Constraint::Length(19),
            ])
            .split(area);
        (chunks[0], Some(chunks[1]), chunks[2])
    } else {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(19)])
            .split(area);
        (chunks[0], None, chunks[1])
    };

    draw_peer_table(f, app, table_area);
    if let Some(fa) = filter_area {
        draw_filter_bar(
            f,
            &app.peer_filter,
            app.peer_filter_mode == FilterMode::Typing,
            fa,
        );
    }
    draw_peer_detail(f, app, detail_area);
}

// ─── Peer table ───────────────────────────────────────────────────────────────

fn peer_state_cell(state: &BgpState) -> Cell<'static> {
    Cell::from(state.as_str().to_string()).style(state_style(state))
}

fn draw_peer_table(f: &mut Frame, app: &mut App, area: Rect) {
    let local_as = app
        .current_summary
        .as_ref()
        .map(|s| s.local_as)
        .unwrap_or(0);

    let router_name = app
        .selected_router()
        .map(|r| r.name.clone())
        .unwrap_or_else(|| "—".into());

    let header = Row::new(vec![
        Cell::from("Neighbor").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("Remote AS").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("Type").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("State").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("Uptime").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("Pfx/Rx").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("Pfx/Tx").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("RM-In").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("RM-Out").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("Description").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
    ])
    .height(1)
    .style(Style::default().add_modifier(Modifier::UNDERLINED));

    let rows: Vec<Row> = app
        .peer_indices
        .iter()
        .map(|&idx| {
            let peer = &app.current_peers[idx];
            let type_style = if peer.remote_as == local_as {
                Style::default().fg(C_IBGP)
            } else {
                Style::default().fg(C_EBGP)
            };

            Row::new(vec![
                Cell::from(peer.neighbor_ip.to_string()),
                Cell::from(peer.remote_as.to_string()),
                Cell::from(peer.session_type().to_string()).style(type_style),
                peer_state_cell(&peer.state),
                Cell::from(peer.uptime.as_deref().unwrap_or("—").to_string()),
                Cell::from(fmt_num(peer.prefixes_received)),
                Cell::from(fmt_num(peer.prefixes_advertised)),
                Cell::from(peer.route_map_in.as_deref().unwrap_or("—").to_string()),
                Cell::from(peer.route_map_out.as_deref().unwrap_or("—").to_string()),
                Cell::from(peer.description.as_deref().unwrap_or("").to_string()),
            ])
            .height(1)
        })
        .collect();

    let total = app.current_peers.len();
    let shown = app.peer_indices.len();
    let title = if app.peer_filter_mode != FilterMode::Off {
        format!(" BGP Peers: {} ({}/{} match) ", router_name, shown, total)
    } else {
        format!(" BGP Peers: {} ({} peers) ", router_name, total)
    };

    let widths = [
        Constraint::Length(16),
        Constraint::Length(9),
        Constraint::Length(6),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Length(20),
        Constraint::Length(20),
        Constraint::Min(16),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(title, Style::default().fg(C_HEADER))),
        )
        .row_highlight_style(
            Style::default()
                .bg(ratatui::style::Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(table, area, &mut app.peer_table_state);
}

// ─── Peer detail pane ─────────────────────────────────────────────────────────

fn draw_peer_detail(f: &mut Frame, app: &App, area: Rect) {
    let selected = app.peer_table_state.selected();
    // Resolve through the filter index map to the actual peer
    let peer = selected
        .and_then(|i| app.peer_indices.get(i))
        .and_then(|&idx| app.current_peers.get(idx));

    let mut lines: Vec<Line> = if let Some(p) = peer {
        let type_color = if p.remote_as
            == app
                .current_summary
                .as_ref()
                .map(|s| s.local_as)
                .unwrap_or(0)
        {
            C_IBGP
        } else {
            C_EBGP
        };

        vec![
            Line::from(vec![
                kv("  Neighbor   ", p.neighbor_ip.to_string()),
                Span::raw("   "),
                kv("Session ", p.session_type().to_string()),
                Span::styled(
                    format!("  ({}) ", p.session_type()),
                    Style::default().fg(type_color),
                ),
            ]),
            Line::from(vec![
                kv("  State     ", p.state.to_string()),
                Span::raw("   "),
                kv("Uptime ", p.uptime.clone().unwrap_or_else(|| "—".into())),
            ]),
            Line::from(vec![
                kv("  Msg Rcvd  ", fmt_num(p.msg_rcvd)),
                Span::raw("   "),
                kv("Msg Sent ", fmt_num(p.msg_sent)),
            ]),
            Line::from(vec![
                kv("  Hold Time ", format!("{}s", p.hold_time)),
                Span::raw("   "),
                kv("Keepalive ", format!("{}s", p.keepalive)),
                Span::raw("   "),
                kv(
                    "Auth ",
                    if p.password_configured {
                        "Yes".into()
                    } else {
                        "No".into()
                    },
                ),
            ]),
            Line::from(vec![
                kv("  NH-Self   ", bool_str(p.next_hop_self).to_string()),
                Span::raw("   "),
                kv("RR-Client ", bool_str(p.route_reflector_client).to_string()),
            ]),
            Line::from(vec![
                kv(
                    "  RM-In     ",
                    p.route_map_in.clone().unwrap_or_else(|| "—".into()),
                ),
                Span::raw("   "),
                kv(
                    "RM-Out    ",
                    p.route_map_out.clone().unwrap_or_else(|| "—".into()),
                ),
            ]),
            Line::from(vec![
                kv(
                    "  Upd-Src   ",
                    p.update_source
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "—".into()),
                ),
                Span::raw("   "),
                kv("Communities ", p.communities.join(" ")),
            ]),
            Line::from(vec![
                kv("  Resets    ", p.reset_count.to_string()),
                Span::raw("   "),
                kv("Notifs Sent ", p.notifs_sent.to_string()),
                Span::raw("   "),
                kv("Rcvd ", p.notifs_rcvd.to_string()),
            ]),
            {
                let reason = p.last_reset_reason.clone().unwrap_or_else(|| "—".into());
                Line::from(vec![
                    Span::styled("  Last Reset  ", Style::default().fg(C_DIM)),
                    Span::raw(reason),
                ])
            },
            Line::from(vec![
                kv("  BFD       ", {
                    match p.bfd_state.as_deref() {
                        Some(s) => s.to_string(),
                        None => "—".into(),
                    }
                }),
                Span::raw("   "),
                kv("MTU probe ", {
                    match &p.mtu_probe {
                        None => "— (m to probe)".into(),
                        Some(MtuProbeState::Running) => "⏳ running…".into(),
                        Some(MtuProbeState::Ok(n)) => format!("✅ ≥{n} B"),
                        Some(MtuProbeState::Degraded(n)) => format!("⚠️ {n} B (tunnel?)"),
                        Some(MtuProbeState::Failed(e)) => format!("❌ {e}"),
                    }
                }),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "  Select a peer with ↑/↓",
            Style::default().fg(C_DIM),
        ))]
    };

    let peer_for_history = selected
        .and_then(|i| app.peer_indices.get(i))
        .and_then(|&idx| app.current_peers.get(idx));

    if let Some(p) = peer_for_history {
        if let Some(router) = app.selected_router() {
            let key = (router.id, p.neighbor_ip);
            if let Some(history) = app.peer_state_history.get(&key) {
                if !history.is_empty() {
                    lines.push(Line::from(Span::styled(
                        "  ── State History ─────────────────────",
                        Style::default().fg(C_DIM),
                    )));
                    let start = history.len().saturating_sub(5);
                    for (ts, old_s, new_s) in history.iter().skip(start) {
                        let time_str = ts.format("%H:%M:%S").to_string();
                        let arrow_color = if new_s == "Established" {
                            C_ESTABLISHED
                        } else if old_s == "Established" {
                            C_ERROR
                        } else {
                            C_WARN
                        };
                        lines.push(Line::from(vec![
                            Span::styled(
                                format!("  {time_str}  "),
                                Style::default().fg(C_DIM),
                            ),
                            Span::styled(
                                format!("{old_s} → {new_s}"),
                                Style::default().fg(arrow_color),
                            ),
                        ]));
                    }
                }
            }
        }
    }

    let title = selected
        .and_then(|i| app.peer_indices.get(i))
        .and_then(|&idx| app.current_peers.get(idx))
        .map(|p| format!(" Peer Detail: {} ", p.neighbor_ip))
        .unwrap_or_else(|| " Peer Detail ".into());

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(title, Style::default().fg(C_SELECTED))),
    );
    f.render_widget(para, area);
}

fn kv(key: &str, val: String) -> Span<'static> {
    Span::raw(format!("{key}{val}"))
}

fn bool_str(b: bool) -> &'static str {
    if b {
        "Yes"
    } else {
        "No"
    }
}

// ─── Filter bar ───────────────────────────────────────────────────────────────

fn draw_filter_bar(f: &mut Frame, filter: &str, is_typing: bool, area: Rect) {
    let cursor = if is_typing { "▌" } else { "" };
    let hint = if is_typing {
        " Enter: apply  Esc: clear"
    } else {
        " /: edit  Esc: clear"
    };
    let content = Line::from(vec![
        Span::styled(
            format!(" / {filter}{cursor}"),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(hint.to_string(), Style::default().fg(C_DIM)),
    ]);
    let border_style = if is_typing {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(C_WARN)
    };
    let para = Paragraph::new(content).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(Span::styled(" Filter ", Style::default().fg(C_SELECTED))),
    );
    f.render_widget(para, area);
}

// ─── Per-peer route drill-down ────────────────────────────────────────────────

fn route_status_style(s: &RouteStatus) -> Style {
    match s {
        RouteStatus::BestExternal => Style::default()
            .fg(C_ESTABLISHED)
            .add_modifier(Modifier::BOLD),
        RouteStatus::Best => Style::default().fg(C_ESTABLISHED),
        RouteStatus::Valid => Style::default().fg(C_WARN),
        RouteStatus::Internal => Style::default().fg(Color::LightBlue),
        RouteStatus::Suppressed => Style::default().fg(C_DIM),
        RouteStatus::History => Style::default().fg(C_DIM),
    }
}

fn route_origin_style(o: &RouteOrigin) -> Style {
    match o {
        RouteOrigin::Igp => Style::default().fg(C_ESTABLISHED),
        RouteOrigin::Egp => Style::default().fg(C_WARN),
        RouteOrigin::Incomplete => Style::default().fg(Color::Red),
    }
}

fn draw_peer_route_view(f: &mut Frame, app: &mut App, area: Rect) {
    let view = match app.peer_route_view.as_ref() {
        Some(v) => v,
        None => return,
    };
    let peer_ip = view.peer_ip;
    let dir = view.direction;
    let routes = view.routes.clone();
    let error = view.error.clone();

    // Table area + 1-line hint bar
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    // ── Route table ───────────────────────────────────────────────────────────
    let count_str = match &routes {
        Some(r) => format!(
            " {} prefix{}",
            r.len(),
            if r.len() == 1 { "" } else { "es" }
        ),
        None => " fetching\u{2026}".to_string(),
    };
    let (rcv_label, adv_label) = if dir == PeerRouteDirection::Received {
        (
            Span::styled(
                " [Received]",
                Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" [Advertised]", Style::default().fg(C_DIM)),
        )
    } else {
        (
            Span::styled(" [Received]", Style::default().fg(C_DIM)),
            Span::styled(
                " [Advertised]",
                Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
            ),
        )
    };

    let header = Row::new(vec![
        Cell::from("St").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("Network").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("Next-Hop").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("LP").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("MED").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("Wt").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("AS Path").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("Org").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("Communities").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
    ])
    .height(1)
    .style(Style::default().add_modifier(Modifier::UNDERLINED));

    let placeholder: Vec<crate::bgp::BgpRoute> = vec![];
    let route_list: &Vec<crate::bgp::BgpRoute> = routes.as_ref().unwrap_or(&placeholder);

    let rows: Vec<Row> = if let Some(ref err_msg) = error {
        vec![Row::new(vec![
            Cell::from(""),
            Cell::from(format!("Error: {err_msg}")).style(Style::default().fg(Color::Red)),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
        ])]
    } else if routes.is_none() {
        vec![] // loading — empty rows, title says "fetching…"
    } else if route_list.is_empty() {
        vec![Row::new(vec![
            Cell::from(""),
            Cell::from(format!(
                "No {} routes for this peer",
                dir.label().to_lowercase()
            ))
            .style(Style::default().fg(C_DIM)),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
        ])]
    } else {
        route_list
            .iter()
            .map(|r: &crate::bgp::BgpRoute| {
                Row::new(vec![
                    Cell::from(r.status.to_string()).style(route_status_style(&r.status)),
                    Cell::from(r.network.clone()),
                    Cell::from(r.next_hop.clone()),
                    Cell::from(
                        r.local_pref
                            .map(|lp: u32| lp.to_string())
                            .unwrap_or_else(|| "—".into()),
                    ),
                    Cell::from(
                        r.metric
                            .map(|m: u32| m.to_string())
                            .unwrap_or_else(|| "—".into()),
                    ),
                    Cell::from(r.weight.to_string()),
                    Cell::from(r.as_path_str()),
                    Cell::from(r.origin.to_string()).style(route_origin_style(&r.origin)),
                    Cell::from(r.communities.join(" ")),
                ])
                .height(1)
            })
            .collect()
    };

    let widths = [
        Constraint::Length(4),
        Constraint::Length(20),
        Constraint::Length(16),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Min(16),
        Constraint::Length(4),
        Constraint::Min(12),
    ];

    // We render the table, then overlay a custom title with coloured direction indicators
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" Peer Routes — {}{} ", peer_ip, count_str),
            Style::default().fg(C_HEADER),
        ));

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(
            Style::default()
                .bg(ratatui::style::Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(table, chunks[0], &mut app.peer_route_table_state);

    // Mark direction labels on the top border via spans drawn over it
    // Draw direction tabs just inside the top border of chunks[0]
    let dir_area = Rect {
        x: chunks[0].x + 2,
        y: chunks[0].y,
        width: chunks[0].width.saturating_sub(4),
        height: 1,
    };
    let dir_line = Line::from(vec![
        Span::raw(
            " ".repeat(
                format!(" Peer Routes — {}{} ", peer_ip, count_str)
                    .len()
                    .min(dir_area.width as usize / 2),
            ),
        ),
        rcv_label,
        adv_label,
    ]);
    f.render_widget(Paragraph::new(dir_line), dir_area);

    // ── Hint bar ──────────────────────────────────────────────────────────────
    let hint = Line::from(vec![
        Span::styled(
            " Enter/i",
            Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
        ),
        Span::styled(":received  ", Style::default().fg(C_DIM)),
        Span::styled(
            "o",
            Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
        ),
        Span::styled(":advertised  ", Style::default().fg(C_DIM)),
        Span::styled(
            "Tab",
            Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
        ),
        Span::styled(":toggle  ", Style::default().fg(C_DIM)),
        Span::styled(
            "r",
            Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
        ),
        Span::styled(":refresh  ", Style::default().fg(C_DIM)),
        Span::styled(
            "Esc",
            Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
        ),
        Span::styled(":back  ", Style::default().fg(C_DIM)),
        Span::styled(
            "↑↓/jk",
            Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
        ),
        Span::styled(":navigate", Style::default().fg(C_DIM)),
    ]);
    f.render_widget(Paragraph::new(hint), chunks[1]);
}
