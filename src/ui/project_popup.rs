use crate::{
    app::{App, ProjectEditorMode},
    ui::{C_BORDER, C_DIM, C_ESTABLISHED, C_HEADER, C_SELECTED},
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
    Frame,
};

// ─── Project popup overlay ────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = centered_rect(60, 70, f.area());
    f.render_widget(Clear, area);

    match app.project_editor_mode {
        ProjectEditorMode::ToggleRouters => draw_toggle_routers(f, app, area),
        _ => draw_project_list(f, app, area),
    }
}

fn draw_project_list(f: &mut Frame, app: &mut App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    let editing_name = app.project_editor_mode == ProjectEditorMode::EditName;

    let mut items: Vec<ListItem> = Vec::new();

    // "All Routers" entry
    let all_style = if app.active_project.is_none() {
        Style::default()
            .fg(C_ESTABLISHED)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(C_DIM)
    };
    items.push(ListItem::new(Line::from(vec![
        Span::raw("  "),
        Span::styled("◆ All Routers", all_style),
        Span::styled(
            format!("  ({} routers)", app.all_routers.len()),
            Style::default().fg(C_DIM),
        ),
    ])));

    // Separator
    items.push(ListItem::new(Line::from(Span::styled(
        "  ─────────────────────────────",
        Style::default().fg(C_DIM),
    ))));

    // Project entries
    for proj in &app.projects {
        let is_active = app.active_project == Some(proj.id);
        let marker = if is_active { "▶" } else { " " };
        let name_style = if is_active {
            Style::default()
                .fg(C_ESTABLISHED)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_HEADER)
        };
        items.push(ListItem::new(Line::from(vec![
            Span::raw(format!(" {marker} ")),
            Span::styled(&proj.name, name_style),
            Span::styled(
                format!("  ({} routers)", proj.router_ids.len()),
                Style::default().fg(C_DIM),
            ),
        ])));
    }

    // Name editor field
    if editing_name {
        items.push(ListItem::new(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!("  {}▌", app.project_editor_buf),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ])));
    }

    let title = format!(" Projects ({}) ", app.projects.len());
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_SELECTED))
                .title(Span::styled(
                    title,
                    Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
                )),
        )
        .highlight_style(Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    // Offset selection by 2 (for "All Routers" + separator)
    let mut proxy_state = app.project_list_state.clone();
    if !editing_name {
        if let Some(idx) = proxy_state.selected() {
            proxy_state.select(Some(idx + 2));
        }
    }

    f.render_stateful_widget(list, rows[0], &mut proxy_state);

    // Help bar
    let help_spans = if editing_name {
        vec![
            key_span(" Enter"),
            hint_span(":save  "),
            key_span("Esc"),
            hint_span(":cancel"),
        ]
    } else {
        vec![
            key_span(" Enter"),
            hint_span(":switch  "),
            key_span("0"),
            hint_span(":all  "),
            key_span("a"),
            hint_span(":add  "),
            key_span("d"),
            hint_span(":delete  "),
            key_span("e"),
            hint_span(":edit routers  "),
            key_span("Esc"),
            hint_span(":close"),
        ]
    };
    let help = Paragraph::new(Line::from(help_spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER)),
    );
    f.render_widget(help, rows[1]);
}

fn draw_toggle_routers(f: &mut Frame, app: &mut App, area: Rect) {
    let proj = match app
        .project_list_state
        .selected()
        .and_then(|i| app.projects.get(i))
    {
        Some(p) => p,
        None => return,
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    let items: Vec<ListItem> = app
        .all_routers
        .iter()
        .map(|r| {
            let in_proj = proj.router_ids.contains(&r.id);
            let check = if in_proj { "[✓]" } else { "[ ]" };
            let style = if in_proj {
                Style::default().fg(C_ESTABLISHED)
            } else {
                Style::default().fg(C_DIM)
            };
            ListItem::new(Line::from(vec![
                Span::raw("  "),
                Span::styled(check, style),
                Span::raw(" "),
                Span::styled(&r.name, Style::default().fg(C_HEADER)),
                Span::styled(format!("  ({})", r.hostname), Style::default().fg(C_DIM)),
            ]))
        })
        .collect();

    let title = format!(" {} — Select Routers ", proj.name);
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_SELECTED))
                .title(Span::styled(
                    title,
                    Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
                )),
        )
        .highlight_style(Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, rows[0], &mut app.project_toggle_state);

    let help = Paragraph::new(Line::from(vec![
        key_span(" Space"),
        hint_span(":toggle  "),
        key_span("↑↓"),
        hint_span(":navigate  "),
        key_span("Enter/Esc"),
        hint_span(":done"),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER)),
    );
    f.render_widget(help, rows[1]);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Returns a centered Rect using percentage of the parent area.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn key_span(s: &str) -> Span<'static> {
    Span::styled(
        s.to_string(),
        Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
    )
}

fn hint_span(s: &str) -> Span<'static> {
    Span::styled(s.to_string(), Style::default().fg(C_DIM))
}
