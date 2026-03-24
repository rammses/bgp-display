use crate::app::{App, WizardMode, WizardStep};
use crate::bgp::naming::generate_policy_names;
use crate::bgp::NeighborDraft;
use crate::ui::{C_BORDER, C_DIM, C_ERROR, C_ESTABLISHED, C_HEADER, C_SELECTED, C_WARN};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = centered_rect(70, 80, f.area());
    f.render_widget(Clear, area);

    match app.wizard_step {
        WizardStep::Fields => draw_fields(f, app, area),
        WizardStep::Review => draw_review(f, app, area),
        WizardStep::Applying => draw_applying(f, app, area),
        WizardStep::Result(ok) => draw_result(f, app, area, ok),
    }
}

fn draw_fields(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(5),
            Constraint::Length(3),
        ])
        .split(area);

    let draft = match &app.wizard_draft {
        Some(d) => d,
        None => return,
    };

    let title = match &app.wizard_mode {
        WizardMode::NeighborCreate => " Create BGP Neighbor ",
        WizardMode::NeighborEdit(_) => " Edit BGP Neighbor ",
        _ => " BGP Neighbor ",
    };

    let mut items: Vec<ListItem> = Vec::new();
    for (i, label) in NeighborDraft::FIELDS.iter().enumerate() {
        let is_active = i == app.wizard_field;
        let value = if is_active && !NeighborDraft::is_toggle_field(i) {
            if i == 8 {
                format!("{}▌", "●".repeat(app.wizard_buf.len()))
            } else {
                format!("{}▌", app.wizard_buf)
            }
        } else {
            draft.field_value(i)
        };

        let label_style = if is_active {
            Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_HEADER)
        };
        let value_style = if is_active {
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_DIM)
        };
        let toggle_hint = if NeighborDraft::is_toggle_field(i) && is_active {
            Span::styled(" [Space] toggle", Style::default().fg(C_DIM))
        } else {
            Span::raw("")
        };

        items.push(ListItem::new(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:<16}", label), label_style),
            Span::styled(format!("[{value}]"), value_style),
            toggle_hint,
        ])));
    }

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_SELECTED))
            .title(Span::styled(
                title,
                Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
            )),
    );
    f.render_widget(list, rows[0]);

    // auto-created objects preview
    let desc = &draft.description;
    let preview_lines = if desc.trim().is_empty() {
        vec![Line::from(Span::styled(
            "  (enter a description to see auto-created objects)",
            Style::default().fg(C_DIM),
        ))]
    } else {
        let names = generate_policy_names(desc);
        vec![
            Line::from(vec![Span::styled(
                "  Auto-creates: ",
                Style::default().fg(C_HEADER),
            )]),
            Line::from(vec![
                Span::raw("    "),
                Span::styled(names.rm_in.clone(), Style::default().fg(C_WARN)),
                Span::styled("  (deny 10)", Style::default().fg(C_DIM)),
                Span::raw("   "),
                Span::styled(names.rm_out.clone(), Style::default().fg(C_WARN)),
                Span::styled("  (deny 10)", Style::default().fg(C_DIM)),
            ]),
            Line::from(vec![
                Span::raw("    "),
                Span::styled(names.pl_in.clone(), Style::default().fg(C_WARN)),
                Span::styled("  (deny all)", Style::default().fg(C_DIM)),
                Span::raw("   "),
                Span::styled(names.pl_out.clone(), Style::default().fg(C_WARN)),
                Span::styled("  (deny all)", Style::default().fg(C_DIM)),
            ]),
        ]
    };

    let mut preview_block_lines = preview_lines;
    if let Some(err) = &app.wizard_error {
        preview_block_lines.push(Line::from(Span::styled(
            format!("  Error: {err}"),
            Style::default().fg(C_ERROR),
        )));
    }

    let preview = Paragraph::new(preview_block_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER)),
    );
    f.render_widget(preview, rows[1]);

    let help = Paragraph::new(Line::from(vec![
        key_span(" Tab/↑↓"),
        hint_span(":navigate  "),
        key_span("Space"),
        hint_span(":toggle  "),
        key_span("Enter"),
        hint_span(":review  "),
        key_span("Esc"),
        hint_span(":cancel"),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER)),
    );
    f.render_widget(help, rows[2]);
}

fn draw_review(f: &mut Frame, app: &App, area: Rect) {
    let has_diff = !app.wizard_diff.is_empty();
    let diff_height = if has_diff {
        (app.wizard_diff.len() as u16) + 3
    } else {
        0
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(diff_height),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(area);

    let title = match &app.wizard_mode {
        WizardMode::NeighborDelete(ip) => format!(" Delete Neighbor {ip} — Confirm "),
        WizardMode::RouteMapEdit(n) => format!(" Save Route-Map {n} — Review "),
        WizardMode::PrefixListEdit(n) => format!(" Save Prefix-List {n} — Review "),
        _ => " Review Commands ".to_string(),
    };

    if has_diff {
        let mut diff_lines: Vec<Line> = Vec::new();
        for (label, change) in &app.wizard_diff {
            diff_lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("{label}: "), Style::default().fg(C_HEADER)),
                Span::styled(change.clone(), Style::default().fg(C_ESTABLISHED)),
            ]));
        }
        diff_lines.push(Line::from(Span::styled(
            "  ─────────────────────────────────",
            Style::default().fg(C_BORDER),
        )));
        let diff_block = Paragraph::new(diff_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_ESTABLISHED))
                .title(Span::styled(
                    " Changes ",
                    Style::default()
                        .fg(C_ESTABLISHED)
                        .add_modifier(Modifier::BOLD),
                )),
        );
        f.render_widget(diff_block, rows[0]);
    }

    let cmd_area = rows[1];

    let items: Vec<ListItem> = app
        .wizard_preview
        .iter()
        .map(|line| {
            let style = if line.starts_with("no ")
                || line.starts_with(" no ")
                || line.starts_with("delete")
            {
                Style::default().fg(C_ERROR)
            } else if line.starts_with("router ")
                || line.starts_with("route-map ")
                || line.starts_with("ip prefix-list ")
            {
                Style::default().fg(C_WARN)
            } else {
                Style::default().fg(C_DIM)
            };
            ListItem::new(Span::styled(format!("  {line}"), style))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_SELECTED))
            .title(Span::styled(
                title,
                Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
            )),
    );
    f.render_widget(list, cmd_area);

    let help_text = if matches!(app.wizard_mode, WizardMode::NeighborDelete(_)) {
        vec![
            key_span(" y/Enter"),
            hint_span(":confirm delete  "),
            key_span("n/Esc"),
            hint_span(":cancel"),
        ]
    } else {
        vec![
            key_span(" Enter"),
            hint_span(":apply  "),
            key_span("Esc"),
            hint_span(":back"),
        ]
    };

    let help = Paragraph::new(Line::from(help_text)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER)),
    );
    f.render_widget(help, rows[2]);
}

fn draw_applying(f: &mut Frame, _app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_SELECTED))
        .title(Span::styled(
            " Applying Configuration ",
            Style::default().fg(C_WARN).add_modifier(Modifier::BOLD),
        ));
    let para = Paragraph::new(Line::from(Span::styled(
        "  Pushing commands to router via SSH…",
        Style::default().fg(C_WARN),
    )))
    .block(block)
    .wrap(Wrap { trim: true });
    f.render_widget(Clear, area);
    f.render_widget(para, area);
}

fn draw_result(f: &mut Frame, app: &App, area: Rect, ok: bool) {
    let (title, style) = if ok {
        (" Config Applied ", Style::default().fg(C_ESTABLISHED))
    } else {
        (" Config Failed ", Style::default().fg(C_ERROR))
    };

    let msg = app.wizard_result_msg.as_deref().unwrap_or(if ok {
        "Configuration applied successfully."
    } else {
        "Configuration push failed."
    });

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if ok { C_ESTABLISHED } else { C_ERROR }))
        .title(Span::styled(title, style.add_modifier(Modifier::BOLD)));

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    let para = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(format!("  {msg}"), style)),
    ])
    .block(block)
    .wrap(Wrap { trim: true });
    f.render_widget(Clear, rows[0]);
    f.render_widget(para, rows[0]);

    let help = Paragraph::new(Line::from(vec![
        key_span(" Enter/Esc"),
        hint_span(":close"),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER)),
    );
    f.render_widget(help, rows[1]);
}

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
