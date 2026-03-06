use crate::{
    app::App,
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
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(5)])
        .split(area);

    draw_route_table(f, app, rows[0]);
    draw_route_detail(f, app, rows[1]);
}

// ─── Route table ──────────────────────────────────────────────────────────────

fn status_style(s: &RouteStatus) -> Style {
    match s {
        RouteStatus::BestExternal => Style::default().fg(C_ESTABLISHED).add_modifier(Modifier::BOLD),
        RouteStatus::Best         => Style::default().fg(C_ESTABLISHED),
        RouteStatus::Valid        => Style::default().fg(C_WARN),
        RouteStatus::Internal     => Style::default().fg(Color::LightBlue),
        RouteStatus::Suppressed   => Style::default().fg(C_DIM),
        RouteStatus::History      => Style::default().fg(C_DIM),
    }
}

fn origin_style(o: &RouteOrigin) -> Style {
    match o {
        RouteOrigin::Igp        => Style::default().fg(C_ESTABLISHED),
        RouteOrigin::Egp        => Style::default().fg(C_WARN),
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
        .current_routes
        .iter()
        .map(|route| {
            Row::new(vec![
                Cell::from(route.status.to_string()).style(status_style(&route.status)),
                Cell::from(route.network.clone()),
                Cell::from(route.next_hop.clone()),
                Cell::from(
                    route.local_pref
                        .map(|lp| lp.to_string())
                        .unwrap_or_else(|| "—".into()),
                ),
                Cell::from(
                    route.metric
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

    let title = format!(
        " BGP Routes: {} ({} routes) ",
        router_name,
        app.current_routes.len()
    );

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
    let route = app
        .route_table_state
        .selected()
        .and_then(|i| app.current_routes.get(i));

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
                kv("Local Pref ", r.local_pref.map(|n| n.to_string()).unwrap_or_else(|| "—".into())),
                Span::raw("   "),
                kv("MED ", r.metric.map(|n| n.to_string()).unwrap_or_else(|| "—".into())),
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
