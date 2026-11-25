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
    let detail_height = if app.is_native_selected() { 6 } else { 5 };
    // Split off a filter bar when filter is active
    let (table_area, filter_area, detail_area) = if app.route_filter_mode != FilterMode::Off {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),
                Constraint::Length(3),
                Constraint::Length(detail_height),
            ])
            .split(area);
        (chunks[0], Some(chunks[1]), chunks[2])
    } else {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(detail_height)])
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

fn status_style(status: &Option<RouteStatus>) -> Style {
    let Some(s) = status else {
        return Style::default().fg(C_DIM);
    };
    match s {
        RouteStatus::BestExternal => Style::default()
            .fg(C_ESTABLISHED)
            .add_modifier(Modifier::BOLD),
        RouteStatus::Best => Style::default().fg(C_ESTABLISHED),
        RouteStatus::Valid => Style::default().fg(C_WARN),
        RouteStatus::Internal => Style::default().fg(Color::LightBlue),
        RouteStatus::Suppressed => Style::default().fg(C_DIM),
        RouteStatus::History => Style::default().fg(C_DIM),
        RouteStatus::Filtered | RouteStatus::Unreachable => Style::default().fg(Color::Red),
    }
}

fn origin_style(origin: &Option<RouteOrigin>) -> Style {
    let Some(o) = origin else {
        return Style::default().fg(C_DIM);
    };
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
                Cell::from(crate::bgp::known_text(route.status.as_ref()))
                    .style(status_style(&route.status)),
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
                Cell::from(crate::bgp::known_text(route.weight)),
                Cell::from(route.as_path_str()),
                Cell::from(crate::bgp::known_text(route.origin.as_ref()))
                    .style(origin_style(&route.origin)),
                Cell::from(
                    route
                        .communities
                        .as_ref()
                        .map(|c| c.join(" "))
                        .unwrap_or_else(|| "N/A".into()),
                ),
            ])
            .height(1)
        })
        .collect();

    let total = app.current_routes.len();
    let shown = app.route_indices.len();
    let mut title = if app.route_filter_mode != FilterMode::Off {
        format!(" BGP Routes: {} ({}/{} match) ", router_name, shown, total)
    } else {
        format!(" BGP Routes: {} ({} routes) ", router_name, total)
    };
    if let Some(router) = app
        .selected_router()
        .filter(|r| r.vendor == crate::router::RouterVendor::MikroTik)
    {
        let stale = app
            .native_cache
            .get(&router.id)
            .and_then(|c| c.stale_reason.as_deref());
        title = format!(
            " Native stored routes (not full Adj-RIB-In) — {} ",
            stale.unwrap_or("observed selected-main cache")
        );
    }

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

    let mut lines: Vec<Line> = if let Some(r) = route {
        vec![
            Line::from(vec![
                Span::raw("  "),
                kv("Network    ", r.network.clone()),
                Span::raw("   "),
                kv("Next-Hop ", r.next_hop.clone()),
                Span::raw("   "),
                kv("Origin ", crate::bgp::known_text(r.origin.as_ref())),
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
                kv("Weight ", crate::bgp::known_text(r.weight)),
            ]),
            Line::from(vec![
                Span::raw("  "),
                kv("AS Path    ", r.as_path_str()),
                Span::raw("   "),
                kv(
                    "Communities ",
                    r.communities
                        .as_ref()
                        .map(|c| c.join(" "))
                        .unwrap_or_else(|| "N/A".into()),
                ),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "  Select a route with ↑/↓",
            Style::default().fg(C_DIM),
        ))]
    };
    if let Some(flags) = route.and_then(|route| route.native_flags.as_ref()) {
        lines.push(Line::from(format!("  Native flags/raw: {flags}")));
    }

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
