use crate::{
    app::{App, FilterMode},
    bgp::{RouteOrigin, RouteStatus},
    ui::{C_BORDER, C_DIM, C_ESTABLISHED, C_HEADER, C_SELECTED, C_WARN},
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

// ─── Routes tab ───────────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    // Split off a filter bar when filter is active
    let (table_area, filter_area, detail_area) = if app.route_filter_mode != FilterMode::Off {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),
                Constraint::Length(3),
                Constraint::Length(5),
            ])
            .split(area);
        (chunks[0], Some(chunks[1]), chunks[2])
    } else {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(5)])
            .split(area);
        (chunks[0], None, chunks[1])
    };

    draw_route_table(f, app, table_area);
    if let Some(fa) = filter_area {
        draw_filter_bar(
            f,
            &app.route_filter,
            app.route_filter_mode == FilterMode::Typing,
            fa,
        );
    }
    draw_route_detail(f, app, detail_area);
}

// ─── Route table ──────────────────────────────────────────────────────────────

fn status_style(s: &RouteStatus) -> Style {
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

fn origin_style(o: &RouteOrigin) -> Style {
    match o {
        RouteOrigin::Igp => Style::default().fg(C_ESTABLISHED),
        RouteOrigin::Egp => Style::default().fg(C_WARN),
        RouteOrigin::Incomplete => Style::default().fg(Color::Red),
    }
}

fn draw_route_table(f: &mut Frame, app: &mut App, area: Rect) {
    let router_name = app
        .selected_router()
        .map(|r| r.name.clone())
        .unwrap_or_else(|| "—".into());

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

    let rows: Vec<Row> = app
        .route_indices
        .iter()
        .map(|&idx| {
            let route = &app.current_routes[idx];
            Row::new(vec![
                Cell::from(route.status.to_string()).style(status_style(&route.status)),
                Cell::from(route.network.clone()),
                Cell::from(route.next_hop.clone()),
                Cell::from(
                    route
                        .local_pref
                        .map(|lp| lp.to_string())
                        .unwrap_or_else(|| "—".into()),
                ),
                Cell::from(
                    route
                        .metric
                        .map(|m| m.to_string())
                        .unwrap_or_else(|| "—".into()),
                ),
                Cell::from(route.weight.to_string()),
                Cell::from(route.as_path_str()),
                Cell::from(route.origin.to_string()).style(origin_style(&route.origin)),
                Cell::from(route.communities.join(" ")),
            ])
            .height(1)
        })
        .collect();

    let total = app.current_routes.len();
    let shown = app.route_indices.len();
    let title = if app.route_filter_mode != FilterMode::Off {
        format!(" BGP Routes: {} ({}/{} match) ", router_name, shown, total)
    } else {
        format!(" BGP Routes: {} ({} routes) ", router_name, total)
    };

    let widths = [
        Constraint::Length(3),
        Constraint::Length(20),
        Constraint::Length(16),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(6),
        Constraint::Min(20),
        Constraint::Length(4),
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
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(table, area, &mut app.route_table_state);
}

// ─── Route detail pane ────────────────────────────────────────────────────────

fn draw_route_detail(f: &mut Frame, app: &App, area: Rect) {
    // Resolve through the filter index map to the actual route
    let route = app
        .route_table_state
        .selected()
        .and_then(|i| app.route_indices.get(i))
        .and_then(|&idx| app.current_routes.get(idx));

    let lines: Vec<Line> = if let Some(r) = route {
        vec![
            Line::from(vec![
                Span::raw("  "),
                kv("Network    ", r.network.clone()),
                Span::raw("   "),
                kv("Next-Hop ", r.next_hop.clone()),
                Span::raw("   "),
                kv("Origin ", r.origin.to_string()),
            ]),
            Line::from(vec![
                Span::raw("  "),
                kv(
                    "Local Pref ",
                    r.local_pref
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "—".into()),
                ),
                Span::raw("   "),
                kv(
                    "MED ",
                    r.metric
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "—".into()),
                ),
                Span::raw("   "),
                kv("Weight ", r.weight.to_string()),
            ]),
            Line::from(vec![
                Span::raw("  "),
                kv("AS Path    ", r.as_path_str()),
                Span::raw("   "),
                kv("Communities ", r.communities.join(" ")),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "  Select a route with ↑/↓",
            Style::default().fg(C_DIM),
        ))]
    };

    let title = route
        .map(|r| format!(" Route Detail: {} ", r.network))
        .unwrap_or_else(|| " Route Detail ".into());

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
