use crate::{
    app::{App, EditorMode, EDITOR_FIELDS, EDITOR_NFIELDS},
    router::ConnectionStatus,
    ui::{C_BORDER, C_DIM, C_ERROR, C_ESTABLISHED, C_HEADER, C_SELECTED, C_WARN},
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

// ─── Router Editor tab ────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(30), Constraint::Min(0)])
        .split(rows[0]);

    draw_router_list(f, app, cols[0]);
    draw_edit_form(f, app, cols[1]);
    draw_help_bar(f, app, rows[1]);
}

// ─── Left panel: router list ──────────────────────────────────────────────────

fn draw_router_list(f: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app
        .routers
        .iter()
        .map(|r| {
            let (dot, dot_style) = match app.router_status.get(&r.id) {
                Some(ConnectionStatus::Connected)    => ("●", Style::default().fg(C_ESTABLISHED)),
                Some(ConnectionStatus::Connecting)   => ("◌", Style::default().fg(C_WARN)),
                Some(ConnectionStatus::Error(_))     => ("✕", Style::default().fg(C_ERROR)),
                _                                    => ("○", Style::default().fg(C_DIM)),
            };
            let line = Line::from(vec![
                Span::styled(dot, dot_style),
                Span::raw(" "),
                Span::styled(r.name.clone(), Style::default().fg(C_HEADER)),
            ]);
            ListItem::new(line)
        })
        .collect();

    let title = format!(" Routers ({}) ", app.routers.len());
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

    f.render_stateful_widget(list, area, &mut app.editor_list_state);
}

// ─── Right panel: edit form ───────────────────────────────────────────────────

fn draw_edit_form(f: &mut Frame, app: &App, area: Rect) {
    let editing = app.editor_mode == EditorMode::EditField;
    let draft   = app.editor_draft.as_ref();

    let title = if editing { " ✎ Edit Router " } else { " Router Details " };

    let mut lines: Vec<Line> = vec![Line::from("")];

    if let Some(d) = draft {
        for i in 0..EDITOR_NFIELDS {
            let label     = EDITOR_FIELDS[i];
            let is_active = editing && i == app.editor_field;

            let value: String = if is_active {
                if i == 4 {
                    // Password: show bullets + cursor
                    format!("{}▌", "●".repeat(app.editor_buf.len()))
                } else if i == 5 {
                    // Vendor: show current value + cycle hint
                    format!("{}  (Space to cycle)▌", app.editor_buf)
                } else {
                    format!("{}▌", app.editor_buf)
                }
            } else {
                match i {
                    0 => d.name.clone(),
                    1 => d.hostname.clone(),
                    2 => d.ssh_port.to_string(),
                    3 => d.username.clone(),
                    4 => d.password.as_ref()
                            .map(|p| "●".repeat(p.len()))
                            .unwrap_or_default(),
                    5 => d.vendor.to_string(),
                    _ => String::new(),
                }
            };

            let label_style = if is_active {
                Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(C_DIM)
            };
            let value_style = if is_active {
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(C_HEADER)
            };
            let prefix = if is_active { "  ▶ " } else { "    " };

            lines.push(Line::from(vec![
                Span::styled(format!("{prefix}{label:<12}"), label_style),
                Span::styled(" │ ", Style::default().fg(C_BORDER)),
                Span::styled(value, value_style),
            ]));
            lines.push(Line::from(""));
        }

        if !editing {
            lines.push(Line::from(Span::styled(
                "  Press Enter to edit · a: add new · d: delete · s: save to disk",
                Style::default().fg(C_DIM),
            )));
        }
    } else if app.routers.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No routers configured.",
            Style::default().fg(C_DIM),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Press [a] to add your first router.",
            Style::default().fg(C_DIM),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  Select a router from the list, then press Enter to edit.",
            Style::default().fg(C_DIM),
        )));
    }

    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(title, Style::default().fg(C_HEADER))),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(para, area);
}

// ─── Bottom help bar ─────────────────────────────────────────────────────────

fn draw_help_bar(f: &mut Frame, app: &App, area: Rect) {
    let spans: Vec<Span> = if app.editor_mode == EditorMode::EditField {
        vec![
            Span::styled(
                " EDITING ",
                Style::default()
                    .fg(Color::Black)
                    .bg(C_SELECTED)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            key_span("Tab/Enter"), hint_span(":next field  "),
            key_span("Shift-Tab"),  hint_span(":prev field  "),
            key_span("Esc"),        hint_span(":cancel"),
        ]
    } else {
        vec![
            key_span("Enter"), hint_span(":edit  "),
            key_span("a"),     hint_span(":add  "),
            key_span("d"),     hint_span(":delete  "),
            key_span("s"),     hint_span(":save to disk  "),
            key_span("↑↓/jk"), hint_span(":select"),
        ]
    };

    let para = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER)),
    );
    f.render_widget(para, area);
}

fn key_span(s: &str) -> Span<'static> {
    Span::styled(
        format!(" {s}"),
        Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
    )
}

fn hint_span(s: &str) -> Span<'static> {
    Span::styled(s.to_string(), Style::default().fg(C_DIM))
}
