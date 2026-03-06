use crate::{
    app::App,
    router::ConnectionStatus,
    ui::{C_BORDER, C_DIM, C_ERROR, C_ESTABLISHED, C_HEADER, C_SELECTED, C_WARN},
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

// ─── Connectivity Log tab ─────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(2 + app.routers.len() as u16)])
        .split(area);

    draw_log_list(f, app, rows[0]);
    draw_status_panel(f, app, rows[1]);
}

// ─── Event log ────────────────────────────────────────────────────────────────

fn draw_log_list(f: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = if app.conn_logs.is_empty() {
        vec![ListItem::new(Span::styled(
            "  No connectivity events yet — probes run every 5 s.",
            Style::default().fg(C_DIM),
        ))]
    } else {
        app.conn_logs
            .iter()
            .map(|entry| {
                let style = if entry.contains("ONLINE") {
                    Style::default().fg(C_ESTABLISHED)
                } else if entry.contains("OFFLINE") {
                    Style::default().fg(C_ERROR)
                } else if entry.contains("added") || entry.contains("updated") {
                    Style::default().fg(C_HEADER)
                } else if entry.contains("removed") {
                    Style::default().fg(C_WARN)
                } else {
                    Style::default().fg(C_DIM)
                };
                ListItem::new(Span::styled(entry.as_str(), style))
            })
            .collect()
    };

    let title = if app.conn_logs.is_empty() {
        " Connectivity Log ".to_string()
    } else {
        format!(" Connectivity Log ({} events) ", app.conn_logs.len())
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(title, Style::default().fg(C_HEADER))),
        )
        .highlight_style(
            Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut app.conn_log_state);
}

// ─── Current status summary ───────────────────────────────────────────────────

fn draw_status_panel(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = vec![];
    for r in &app.routers {
        let (dot, dot_style, label) = match app.router_status.get(&r.id) {
            Some(ConnectionStatus::Connected)    => ("●", Style::default().fg(C_ESTABLISHED), "Online"),
            Some(ConnectionStatus::Connecting)   => ("◌", Style::default().fg(C_WARN),        "Connecting"),
            Some(ConnectionStatus::Error(_))     => ("✕", Style::default().fg(C_ERROR),       "Error"),
            _                                    => ("○", Style::default().fg(C_DIM),          "Offline"),
        };
        lines.push(Line::from(vec![
            Span::styled(dot, dot_style),
            Span::raw(" "),
            Span::styled(format!("{:<16}", r.name),     Style::default().fg(C_HEADER)),
            Span::styled(format!("{:<12}", r.hostname), Style::default().fg(C_DIM)),
            Span::styled(label, dot_style),
        ]));
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" Current Status ", Style::default().fg(C_HEADER))),
    );
    f.render_widget(para, area);
}
