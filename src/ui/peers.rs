use crate::{
    app::App,
    bgp::BgpState,
    ui::{C_BORDER, C_DIM, C_EBGP, C_HEADER, C_IBGP, C_SELECTED, fmt_num, state_style},
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

// ─── Peers tab ────────────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(7)])
        .split(area);

    draw_peer_table(f, app, rows[0]);
    draw_peer_detail(f, app, rows[1]);
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
        .current_peers
        .iter()
        .map(|peer| {
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
                Cell::from(fmt_num(peer.prefixes_advertised)),                Cell::from(peer.route_map_in.as_deref().unwrap_or("—").to_string()),
                Cell::from(peer.route_map_out.as_deref().unwrap_or("—").to_string()),                Cell::from(
                    peer.description
                        .as_deref()
                        .unwrap_or("")
                        .to_string(),
                ),
            ])
            .height(1)
        })
        .collect();

    let title = format!(" BGP Peers: {} ({} peers) ", router_name, app.current_peers.len());

    let widths = [
        Constraint::Length(16),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(14),
        Constraint::Length(14),
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
    let peer     = selected.and_then(|i| app.current_peers.get(i));

    let lines: Vec<Line> = if let Some(p) = peer {
        let type_color = if p.remote_as == app.current_summary.as_ref().map(|s| s.local_as).unwrap_or(0) {
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
                kv("Auth ", if p.password_configured { "Yes".into() } else { "No".into() }),
            ]),
            Line::from(vec![
                kv("  NH-Self   ", bool_str(p.next_hop_self).to_string()),
                Span::raw("   "),
                kv("RR-Client ", bool_str(p.route_reflector_client).to_string()),
            ]),
            Line::from(vec![
                kv("  RM-In     ", p.route_map_in.clone().unwrap_or_else(|| "—".into())),
                Span::raw("   "),
                kv("RM-Out    ", p.route_map_out.clone().unwrap_or_else(|| "—".into())),
            ]),
            Line::from(vec![
                kv("  Upd-Src   ", p.update_source.map(|a| a.to_string()).unwrap_or_else(|| "—".into())),
                Span::raw("   "),
                kv("Communities ", p.communities.join(" ")),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "  Select a peer with ↑/↓",
            Style::default().fg(C_DIM),
        ))]
    };

    let title = selected
        .and_then(|i| app.current_peers.get(i))
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
    if b { "Yes" } else { "No" }
}
