pub mod config_tab;
pub mod conn_log;
pub mod dashboard;
pub mod logs;
pub mod peers;
pub mod project_popup;
pub mod router_editor;
pub mod routes;

use crate::app::{ActiveTab, App};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Tabs},
    Frame,
};

// ─── Colour palette ───────────────────────────────────────────────────────────

pub const C_TITLE:      Color = Color::Cyan;
pub const C_SELECTED:   Color = Color::Yellow;
pub const C_BORDER:     Color = Color::DarkGray;
pub const C_HEADER:     Color = Color::Cyan;
pub const C_ESTABLISHED:Color = Color::Green;
pub const C_WARN:       Color = Color::Yellow;
pub const C_ERROR:      Color = Color::Red;
pub const C_IBGP:       Color = Color::LightBlue;
pub const C_EBGP:       Color = Color::Magenta;
pub const C_STATUS_OK:  Color = Color::Green;
pub const C_DIM:        Color = Color::DarkGray;

// ─── Top-level draw ───────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title bar
            Constraint::Length(3), // tab bar
            Constraint::Min(0),    // content
            Constraint::Length(3), // help bar
        ])
        .split(f.area());

    draw_title(f, app, chunks[0]);
    draw_tabs(f, app, chunks[1]);
    draw_content(f, app, chunks[2]);
    draw_help(f, app, chunks[3]);

    // Project popup overlay
    if app.project_popup {
        project_popup::draw(f, app);
    }
}

// ─── Title bar ────────────────────────────────────────────────────────────────

fn draw_title(f: &mut Frame, app: &App, area: Rect) {
    let now = chrono::Local::now().format("%H:%M:%S").to_string();

    // Build AS / Router-ID info from selected router
    let (as_info, conn_info) = if let Some(r) = app.selected_router() {
        let as_str   = r.local_as.map(|a| format!("AS {a}")).unwrap_or_default();
        let conn_str = app.connection_status().to_string();
        (as_str, conn_str)
    } else {
        (String::new(), String::new())
    };

    let title_style  = Style::default().fg(C_TITLE).add_modifier(Modifier::BOLD);
    let right_style  = Style::default().fg(C_DIM);
    let status_style = match app.connection_status() {
        crate::router::ConnectionStatus::Connected     => Style::default().fg(C_STATUS_OK),
        crate::router::ConnectionStatus::Connecting    => Style::default().fg(C_WARN),
        crate::router::ConnectionStatus::Disconnected  => Style::default().fg(C_DIM),
        crate::router::ConnectionStatus::Error(_)      => Style::default().fg(C_ERROR),
    };

    let title = Line::from(vec![
        Span::styled(" BGP Link Manager ", title_style),
        Span::styled("v0.1.0", right_style),
        Span::raw("  "),
        Span::styled(
            app.active_project_name()
                .map(|n| format!("[{n}]"))
                .unwrap_or_else(|| "[All Routers]".into()),
            Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(&as_info, Style::default().fg(C_HEADER)),
        Span::raw("  "),
        Span::styled(&conn_info, status_style),
    ]);

    let time_line = Line::from(vec![
        Span::styled(now, right_style),
    ]);

    // Two sub-columns: title left, time right
    let inner = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(12)])
        .split(area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_TITLE))
        .title(Span::styled(" bgp-link-manager ", title_style));

    let status_para = ratatui::widgets::Paragraph::new(title)
        .block(block);
    f.render_widget(status_para, area);

    // Overlay time in top-right corner, no block
    let time_para = ratatui::widgets::Paragraph::new(time_line)
        .alignment(ratatui::layout::Alignment::Right);
    // Draw inside the border area
    let inner_area = Rect {
        x:      inner[1].x,
        y:      area.y + 1,
        width:  inner[1].width.saturating_sub(2),
        height: 1,
    };
    f.render_widget(time_para, inner_area);
}

// ─── Tab bar ─────────────────────────────────────────────────────────────────

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = ActiveTab::ALL
        .iter()
        .map(|t| Line::from(Span::raw(t.label())))
        .collect();

    let tabs = Tabs::new(titles)
        .select(app.current_tab as usize)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER)),
        )
        .highlight_style(
            Style::default()
                .fg(C_SELECTED)
                .add_modifier(Modifier::BOLD),
        )
        .divider(Span::styled(" │ ", Style::default().fg(C_BORDER)));

    f.render_widget(tabs, area);
}

// ─── Content router ───────────────────────────────────────────────────────────

fn draw_content(f: &mut Frame, app: &mut App, area: Rect) {
    match app.current_tab {
        ActiveTab::Dashboard => dashboard::draw(f, app, area),
        ActiveTab::Peers     => peers::draw(f, app, area),
        ActiveTab::Routes    => routes::draw(f, app, area),
        ActiveTab::Config    => config_tab::draw(f, app, area),
        ActiveTab::Logs      => logs::draw(f, app, area),
        ActiveTab::Routers   => router_editor::draw(f, app, area),
        ActiveTab::ConnLog   => conn_log::draw(f, app, area),
    }
}

// ─── Help bar ─────────────────────────────────────────────────────────────────

fn draw_help(f: &mut Frame, app: &App, area: Rect) {
    let status = app
        .status_message
        .as_deref()
        .unwrap_or("Ready");

    let mut keys: Vec<(&str, &str)> = vec![
        ("q", "Quit"),
        ("Tab", "Switch"),
        ("↑↓/jk", "Navigate"),
        ("r/F5", "Refresh"),
        ("p", "Projects"),
        ("1-7", "Jump tab"),
    ];

    // Tab-specific hints
    if app.current_tab == ActiveTab::Peers && app.peer_route_view.is_none() {
        keys.push(("Enter", "Peer routes"));
        keys.push(("m", "MTU probe"));
        keys.push(("/", "Filter"));
    }

    let mut spans: Vec<Span> = vec![
        Span::styled(format!(" {status}  "), Style::default().fg(C_STATUS_OK)),
        Span::styled("  ", Style::default()),
    ];

    for (key, desc) in &keys {
        spans.push(Span::styled(*key, Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD)));
        spans.push(Span::styled(format!(":{desc}  "), Style::default().fg(C_DIM)));
    }

    let para = ratatui::widgets::Paragraph::new(Line::from(spans))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER)),
        );
    f.render_widget(para, area);
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Returns a coloured style for a given BGP state.
pub fn state_style(state: &crate::bgp::BgpState) -> Style {
    use crate::bgp::BgpState;
    match state {
        BgpState::Established => Style::default().fg(C_ESTABLISHED),
        BgpState::Active      => Style::default().fg(C_WARN),
        BgpState::Connect     => Style::default().fg(C_WARN),
        BgpState::OpenSent    => Style::default().fg(C_WARN),
        BgpState::OpenConfirm => Style::default().fg(C_WARN),
        BgpState::Idle        => Style::default().fg(C_ERROR),
        BgpState::Unknown(_)  => Style::default().fg(C_DIM),
    }
}

/// Formats a large number with thousands separator.
pub fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { result.push(','); }
        result.push(c);
    }
    result.chars().rev().collect()
}
