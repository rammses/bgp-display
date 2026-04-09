use crate::{
    app::App,
    bgp::{PeerRouteDirection, RouteOrigin, RouteStatus},
    ui::{C_BORDER, C_DIM, C_ESTABLISHED, C_HEADER, C_SELECTED, C_WARN},
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

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

pub fn draw_peer_route_view(f: &mut Frame, app: &mut App, area: Rect) {
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
