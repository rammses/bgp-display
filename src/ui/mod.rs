pub mod communitylist_editor;
pub mod config_tab;
pub mod conn_log;
pub mod dashboard;
pub mod help_overlay;
pub mod logs;
pub mod neighbor_wizard;
pub mod peers;
pub mod prefixlist_editor;
pub mod project_popup;
pub mod routemap_editor;
pub mod router_editor;
pub mod routes;

use crate::app::{ActiveTab, App, ConfirmAction};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Tabs, Wrap},
    Frame,
};

// ─── Colour palette ───────────────────────────────────────────────────────────

pub const C_TITLE: Color = Color::Cyan;
pub const C_SELECTED: Color = Color::Yellow;
pub const C_BORDER: Color = Color::DarkGray;
pub const C_HEADER: Color = Color::Cyan;
pub const C_ESTABLISHED: Color = Color::Green;
pub const C_WARN: Color = Color::Yellow;
pub const C_ERROR: Color = Color::Red;
pub const C_IBGP: Color = Color::LightBlue;
pub const C_EBGP: Color = Color::Magenta;
pub const C_STATUS_OK: Color = Color::Green;
pub const C_DIM: Color = Color::DarkGray;

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

    // Wizard overlay (neighbor, route-map, prefix-list editors)
    match &app.wizard_mode {
        crate::app::WizardMode::Closed => {}
        crate::app::WizardMode::NeighborCreate
        | crate::app::WizardMode::NeighborEdit(_)
        | crate::app::WizardMode::NeighborDelete(_) => {
            neighbor_wizard::draw(f, app);
        }
        crate::app::WizardMode::RouteMapEdit(_) => {
            routemap_editor::draw(f, app);
        }
        crate::app::WizardMode::PrefixListEdit(_) => {
            prefixlist_editor::draw(f, app);
        }
        crate::app::WizardMode::CommunityListEdit(_) => {
            communitylist_editor::draw(f, app);
        }
    }

    // Config history popup overlay
    if app.show_history {
        draw_history_popup(f, app);
    }

    // Clone neighbor popup overlay
    if app.clone_draft.is_some() {
        draw_clone_popup(f, app);
    }

    // Confirmation dialog overlay
    if app.confirm_action.is_some() {
        draw_confirm_dialog(f, app);
    }

    // Help overlay
    if app.show_help {
        help_overlay::draw(f, app);
    }
}

// ─── Title bar ────────────────────────────────────────────────────────────────

fn draw_title(f: &mut Frame, app: &App, area: Rect) {
    let now = chrono::Local::now().format("%H:%M:%S").to_string();

    // Build AS / Router-ID info from selected router
    let (as_info, conn_info) = if let Some(r) = app.selected_router() {
        let as_str = r.local_as.map(|a| format!("AS {a}")).unwrap_or_default();
        let conn_str = app.connection_status().to_string();
        (as_str, conn_str)
    } else {
        (String::new(), String::new())
    };

    let title_style = Style::default().fg(C_TITLE).add_modifier(Modifier::BOLD);
    let right_style = Style::default().fg(C_DIM);
    let status_style = match app.connection_status() {
        crate::router::ConnectionStatus::Connected => Style::default().fg(C_STATUS_OK),
        crate::router::ConnectionStatus::Connecting => Style::default().fg(C_WARN),
        crate::router::ConnectionStatus::Disconnected => Style::default().fg(C_DIM),
        crate::router::ConnectionStatus::Error(_) => Style::default().fg(C_ERROR),
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

    let time_line = Line::from(vec![Span::styled(now, right_style)]);

    // Two sub-columns: title left, time right
    let inner = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(12)])
        .split(area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_TITLE))
        .title(Span::styled(" bgp-link-manager ", title_style));

    let status_para = ratatui::widgets::Paragraph::new(title).block(block);
    f.render_widget(status_para, area);

    // Overlay time in top-right corner, no block
    let time_para =
        ratatui::widgets::Paragraph::new(time_line).alignment(ratatui::layout::Alignment::Right);
    // Draw inside the border area
    let inner_area = Rect {
        x: inner[1].x,
        y: area.y + 1,
        width: inner[1].width.saturating_sub(2),
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
        .highlight_style(Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD))
        .divider(Span::styled(" │ ", Style::default().fg(C_BORDER)));

    f.render_widget(tabs, area);
}

// ─── Content router ───────────────────────────────────────────────────────────

fn draw_content(f: &mut Frame, app: &mut App, area: Rect) {
    match app.current_tab {
        ActiveTab::Dashboard => dashboard::draw(f, app, area),
        ActiveTab::Peers => peers::draw(f, app, area),
        ActiveTab::Routes => routes::draw(f, app, area),
        ActiveTab::Config => config_tab::draw(f, app, area),
        ActiveTab::Logs => logs::draw(f, app, area),
        ActiveTab::Routers => router_editor::draw(f, app, area),
        ActiveTab::ConnLog => conn_log::draw(f, app, area),
    }
}

// ─── Help bar ─────────────────────────────────────────────────────────────────

fn draw_help(f: &mut Frame, app: &App, area: Rect) {
    let status = app.status_message.as_deref().unwrap_or("Ready");

    // Flash the status bar red for ~25 ticks (~5 s) after a peer-down alert
    let alert_active = app
        .peer_down_alert_tick
        .map(|t| app.tick_counter.saturating_sub(t) < 25)
        .unwrap_or(false);

    let mut keys: Vec<(&str, &str)> = vec![
        ("q", "Quit"),
        ("Tab", "Switch"),
        ("↑↓/jk", "Navigate"),
        ("r/F5", "Refresh"),
        ("p", "Projects"),
        ("1-7", "Jump tab"),
    ];

    if app.current_tab == ActiveTab::Peers && app.peer_route_view.is_none() {
        keys.push(("Enter", "Peer routes"));
        keys.push(("m", "MTU probe"));
        keys.push(("n", "New neighbor"));
        keys.push(("e", "Edit"));
        keys.push(("x", "Delete"));
        keys.push(("/", "Filter"));
    }
    if app.current_tab == ActiveTab::Config {
        keys.push(("e", "Edit RM/PL"));
        keys.push(("h", "History"));
        keys.push(("/", "Filter"));
    }
    if app.current_tab == ActiveTab::Logs {
        keys.push(("/", "Filter"));
    }
    if app.current_tab == ActiveTab::ConnLog {
        keys.push(("/", "Filter"));
    }
    if app.current_tab == ActiveTab::Dashboard {
        keys.push(("n", "New neighbor"));
    }
    keys.push(("?", "Help"));

    let status_color = if alert_active { C_ERROR } else { C_STATUS_OK };
    let mut spans: Vec<Span> = vec![
        Span::styled(format!(" {status}  "), Style::default().fg(status_color)),
        Span::styled("  ", Style::default()),
    ];

    for (key, desc) in &keys {
        spans.push(Span::styled(
            *key,
            Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(":{desc}  "),
            Style::default().fg(C_DIM),
        ));
    }

    let para = ratatui::widgets::Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER)),
    );
    f.render_widget(para, area);
}

// ─── Config history popup ─────────────────────────────────────────────────────

fn draw_history_popup(f: &mut Frame, app: &mut App) {
    let area = centered_popup(70, 20.min(f.area().height.saturating_sub(4)), f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_SELECTED))
        .title(Span::styled(
            " Config History (u:undo  Esc:close) ",
            Style::default()
                .fg(C_SELECTED)
                .add_modifier(Modifier::BOLD),
        ));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.config_history.is_empty() {
        let empty = Paragraph::new("  No config history for this router.")
            .style(Style::default().fg(C_DIM));
        f.render_widget(empty, inner);
        return;
    }

    let items: Vec<ratatui::widgets::ListItem> = app
        .config_history
        .iter()
        .map(|entry| {
            let has_rb = if entry.rollback.is_empty() {
                ""
            } else {
                " [undoable]"
            };
            let line = Line::from(vec![
                Span::styled(&entry.applied_at[..19.min(entry.applied_at.len())], Style::default().fg(C_DIM)),
                Span::raw("  "),
                Span::styled(&entry.action, Style::default().fg(C_HEADER)),
                Span::raw("  "),
                Span::styled(&entry.description, Style::default().fg(Color::White)),
                Span::styled(has_rb, Style::default().fg(C_ESTABLISHED)),
            ]);
            ratatui::widgets::ListItem::new(line)
        })
        .collect();

    let list = ratatui::widgets::List::new(items)
        .highlight_style(Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, inner, &mut app.history_list_state);
}

// ─── Clone neighbor popup overlay ────────────────────────────────────────────

fn draw_clone_popup(f: &mut Frame, app: &mut App) {
    let draft = match &app.clone_draft {
        Some(d) => d,
        None => return,
    };
    let selected = app.clone_target_router.unwrap_or(0);
    let neighbor_ip = &draft.neighbor_ip;

    let router_count = app.all_routers.len();
    let popup_h = (router_count as u16 + 6).min(f.area().height.saturating_sub(4));
    let area = centered_popup(60, popup_h, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_SELECTED))
        .title(Span::styled(
            " Clone Neighbor to Router ",
            Style::default()
                .fg(C_SELECTED)
                .add_modifier(Modifier::BOLD),
        ));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // neighbor IP info
            Constraint::Length(1), // separator
            Constraint::Min(1),   // router list
            Constraint::Length(1), // help line
        ])
        .split(inner);

    let info = Paragraph::new(Line::from(vec![
        Span::raw("  Cloning: "),
        Span::styled(
            neighbor_ip.as_str(),
            Style::default()
                .fg(C_HEADER)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  (AS {})", draft.remote_as),
            Style::default().fg(C_DIM),
        ),
    ]));
    f.render_widget(info, chunks[0]);

    let items: Vec<ratatui::widgets::ListItem> = app
        .all_routers
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let vendor = format!("[{}]", r.vendor);
            let style = if i == selected {
                Style::default()
                    .fg(C_SELECTED)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ratatui::widgets::ListItem::new(Line::from(vec![
                Span::styled(&r.name, style),
                Span::raw("  "),
                Span::styled(&r.hostname, Style::default().fg(C_DIM)),
                Span::raw("  "),
                Span::styled(vendor, Style::default().fg(C_IBGP)),
            ]))
        })
        .collect();

    let mut list_state = ratatui::widgets::ListState::default();
    list_state.select(Some(selected));

    let list = ratatui::widgets::List::new(items)
        .highlight_style(
            Style::default()
                .fg(C_SELECTED)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, chunks[2], &mut list_state);

    let help = Paragraph::new(Line::from(vec![
        Span::styled("Enter", Style::default().fg(C_HEADER)),
        Span::raw(":clone  "),
        Span::styled("Esc", Style::default().fg(C_HEADER)),
        Span::raw(":cancel  "),
        Span::styled("↑↓", Style::default().fg(C_HEADER)),
        Span::raw(":select"),
    ]))
    .alignment(Alignment::Center);
    f.render_widget(help, chunks[3]);
}

// ─── Confirm dialog overlay ──────────────────────────────────────────────────

fn draw_confirm_dialog(f: &mut Frame, app: &App) {
    let (title, body) = match &app.confirm_action {
        Some(ConfirmAction::DeleteRouter(id)) => {
            let name = app
                .routers
                .iter()
                .find(|r| r.id == *id)
                .map(|r| r.name.as_str())
                .unwrap_or("unknown");
            (
                " Confirm Delete ",
                format!("Delete router '{name}'?\n\nThis cannot be undone."),
            )
        }
        Some(ConfirmAction::DeleteProject(id)) => {
            let name = app
                .projects
                .iter()
                .find(|p| p.id == *id)
                .map(|p| p.name.as_str())
                .unwrap_or("unknown");
            (
                " Confirm Delete ",
                format!("Delete project '{name}'?\n\nRouters will not be removed."),
            )
        }
        None => return,
    };

    let area = centered_popup(40, 9, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_ERROR))
        .title(Span::styled(
            title,
            Style::default()
                .fg(C_ERROR)
                .add_modifier(Modifier::BOLD),
        ));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(inner);

    let body_para = Paragraph::new(body)
        .style(Style::default().fg(Color::White))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });
    f.render_widget(body_para, rows[0]);

    let hint = Line::from(vec![
        Span::styled(
            " y/Enter",
            Style::default()
                .fg(C_ERROR)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(":confirm  ", Style::default().fg(C_DIM)),
        Span::styled(
            "n/Esc",
            Style::default()
                .fg(C_SELECTED)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(":cancel", Style::default().fg(C_DIM)),
    ]);
    let hint_para = Paragraph::new(hint).alignment(Alignment::Center);
    f.render_widget(hint_para, rows[1]);
}

fn centered_popup(width: u16, height: u16, r: Rect) -> Rect {
    let v_pad = r.height.saturating_sub(height) / 2;
    let h_pad = r.width.saturating_sub(width) / 2;
    Rect {
        x: r.x + h_pad,
        y: r.y + v_pad,
        width: width.min(r.width),
        height: height.min(r.height),
    }
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Returns a coloured style for a given BGP state.
pub fn state_style(state: &crate::bgp::BgpState) -> Style {
    use crate::bgp::BgpState;
    match state {
        BgpState::Established => Style::default().fg(C_ESTABLISHED),
        BgpState::Active => Style::default().fg(C_WARN),
        BgpState::Connect => Style::default().fg(C_WARN),
        BgpState::OpenSent => Style::default().fg(C_WARN),
        BgpState::OpenConfirm => Style::default().fg(C_WARN),
        BgpState::Idle => Style::default().fg(C_ERROR),
        BgpState::Unknown(_) => Style::default().fg(C_DIM),
    }
}

/// Formats a large number with thousands separator.
pub fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}
