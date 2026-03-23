use crate::app::{App, WizardStep};
use crate::ui::{C_BORDER, C_DIM, C_ERROR, C_ESTABLISHED, C_HEADER, C_SELECTED, C_WARN};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
    Frame,
};

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = centered_rect(70, 80, f.area());
    f.render_widget(Clear, area);

    match app.wizard_step {
        WizardStep::Fields => draw_entries(f, app, area),
        WizardStep::Review => crate::ui::neighbor_wizard::draw(f, app),
        WizardStep::Applying => {
            let block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_WARN))
                .title(" Saving Route-Map… ");
            f.render_widget(
                Paragraph::new("  Pushing config via SSH…").block(block),
                area,
            );
        }
        WizardStep::Result(_) => crate::ui::neighbor_wizard::draw(f, app),
    }
}

fn draw_entries(f: &mut Frame, app: &App, area: Rect) {
    let has_error = app.wizard_error.is_some();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if has_error {
            vec![
                Constraint::Min(0),
                Constraint::Length(1),
                Constraint::Length(3),
            ]
        } else {
            vec![Constraint::Min(0), Constraint::Length(0), Constraint::Length(3)]
        })
        .split(area);

    let title = format!(" Edit Route-Map: {} ", app.rm_editor_name);

    let mut items: Vec<ListItem> = Vec::new();

    // Insert-seq prompt line at top when active
    if app.rm_editor_editing && app.rm_editor_field == 100 {
        items.push(ListItem::new(Line::from(vec![
            Span::styled(
                "  Insert at seq: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{}▌", app.rm_editor_buf),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ])));
        items.push(ListItem::new(Line::from(Span::styled(
            "  ──────────────────────────────────",
            Style::default().fg(C_BORDER),
        ))));
    }

    let in_clause = app.rm_clause_mode;

    for (i, entry) in app.rm_editor_entries.iter().enumerate() {
        let is_sel = i == app.rm_editor_selected;
        let marker = if is_sel && !in_clause { "▶ " } else if is_sel && in_clause { "● " } else { "  " };
        let sel_style = if is_sel {
            Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_HEADER)
        };

        if app.rm_editor_editing && is_sel && app.rm_editor_field < 100 {
            let field_labels = ["Seq", "Action", "Match", "Set"];
            let current_label = field_labels.get(app.rm_editor_field).unwrap_or(&"");
            items.push(ListItem::new(Line::from(vec![
                Span::raw(marker),
                Span::styled(
                    format!("Seq {} [{}]  ", entry.sequence, entry.action),
                    sel_style,
                ),
                Span::styled(
                    format!("Editing {}: {}▌", current_label, app.rm_editor_buf),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ])));
        } else {
            let action_style = if entry.action == "permit" {
                Style::default().fg(C_ESTABLISHED)
            } else {
                Style::default().fg(C_ERROR)
            };
            items.push(ListItem::new(Line::from(vec![
                Span::raw(marker),
                Span::styled(format!("Seq {:>3}  ", entry.sequence), sel_style),
                Span::styled(format!("[{}]", entry.action), action_style),
            ])));

            let is_match_mode = in_clause && is_sel && app.rm_clause_type == "match";
            let is_set_mode = in_clause && is_sel && app.rm_clause_type == "set";

            for (ci, m) in entry.match_clauses.iter().enumerate() {
                let clause_sel = is_match_mode && ci == app.rm_clause_idx;
                let clause_marker = if clause_sel { "  ▸ " } else { "      " };
                let text_style = if clause_sel && app.rm_clause_editing {
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else if clause_sel {
                    Style::default()
                        .fg(C_HEADER)
                        .add_modifier(Modifier::BOLD)
                        .bg(Color::DarkGray)
                } else {
                    Style::default().fg(C_HEADER)
                };
                if clause_sel && app.rm_clause_editing {
                    items.push(ListItem::new(Line::from(vec![
                        Span::raw(clause_marker),
                        Span::styled("Match: ", Style::default().fg(Color::Yellow)),
                        Span::styled(format!("{}▌", app.rm_clause_buf), text_style),
                    ])));
                } else {
                    items.push(ListItem::new(Line::from(vec![
                        Span::raw(clause_marker),
                        Span::styled("Match: ", Style::default().fg(C_DIM)),
                        Span::styled(m, text_style),
                    ])));
                }
            }
            for (ci, s) in entry.set_clauses.iter().enumerate() {
                let clause_sel = is_set_mode && ci == app.rm_clause_idx;
                let clause_marker = if clause_sel { "  ▸ " } else { "      " };
                let text_style = if clause_sel && app.rm_clause_editing {
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else if clause_sel {
                    Style::default()
                        .fg(C_WARN)
                        .add_modifier(Modifier::BOLD)
                        .bg(Color::DarkGray)
                } else {
                    Style::default().fg(C_WARN)
                };
                if clause_sel && app.rm_clause_editing {
                    items.push(ListItem::new(Line::from(vec![
                        Span::raw(clause_marker),
                        Span::styled("Set:   ", Style::default().fg(Color::Yellow)),
                        Span::styled(format!("{}▌", app.rm_clause_buf), text_style),
                    ])));
                } else {
                    items.push(ListItem::new(Line::from(vec![
                        Span::raw(clause_marker),
                        Span::styled("Set:   ", Style::default().fg(C_DIM)),
                        Span::styled(s, text_style),
                    ])));
                }
            }
            if entry.match_clauses.is_empty() && entry.set_clauses.is_empty() {
                items.push(ListItem::new(Line::from(Span::styled(
                    "      (no match/set — press m or t to add)",
                    Style::default().fg(C_DIM),
                ))));
            }
        }

        items.push(ListItem::new(Line::from(Span::styled(
            "  ──────────────────────────────────",
            Style::default().fg(C_BORDER),
        ))));
    }

    if app.rm_editor_entries.is_empty() && !(app.rm_editor_editing && app.rm_editor_field == 100) {
        items.push(ListItem::new(Span::styled(
            "  (no entries — press 'a' to add or 'i' to insert)",
            Style::default().fg(C_DIM),
        )));
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

    if let Some(err) = &app.wizard_error {
        let err_line = Paragraph::new(Line::from(Span::styled(
            format!(" ✗ {err}"),
            Style::default().fg(C_ERROR).add_modifier(Modifier::BOLD),
        )));
        f.render_widget(err_line, rows[1]);
    }

    let help = if in_clause && app.rm_clause_editing {
        Paragraph::new(Line::from(vec![
            key_span(" Enter"),
            hint_span(":save clause  "),
            key_span("Esc"),
            hint_span(":cancel"),
        ]))
    } else if in_clause {
        let mut spans = vec![
            key_span(" Enter"),
            hint_span(":edit  "),
            key_span("a"),
            hint_span(":add  "),
            key_span("d"),
            hint_span(":delete  "),
        ];
        if app.rm_clause_type == "match" {
            spans.push(key_span("p"));
            spans.push(hint_span(":open prefix-list  "));
        }
        spans.push(key_span("Esc"));
        spans.push(hint_span(":back"));
        Paragraph::new(Line::from(spans))
    } else if app.rm_editor_editing && app.rm_editor_field == 100 {
        Paragraph::new(Line::from(vec![
            key_span(" Enter"),
            hint_span(":confirm  "),
            key_span("Esc"),
            hint_span(":cancel"),
        ]))
    } else if app.rm_editor_editing {
        Paragraph::new(Line::from(vec![
            key_span(" Tab"),
            hint_span(":next field  "),
            key_span("Space"),
            hint_span(":toggle action  "),
            key_span("Enter"),
            hint_span(":done  "),
            key_span("Esc"),
            hint_span(":cancel"),
        ]))
    } else {
        Paragraph::new(Line::from(vec![
            key_span(" Enter"),
            hint_span(":edit  "),
            key_span("m"),
            hint_span(":match  "),
            key_span("t"),
            hint_span(":set  "),
            key_span("i"),
            hint_span(":insert  "),
            key_span("Space"),
            hint_span(":toggle  "),
            key_span("a"),
            hint_span(":append  "),
            key_span("d"),
            hint_span(":delete  "),
            key_span("s"),
            hint_span(":save  "),
            key_span("Esc"),
            hint_span(":cancel"),
        ]))
    };

    f.render_widget(
        help.block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER)),
        ),
        rows[2],
    );
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
