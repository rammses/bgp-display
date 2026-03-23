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
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    let title = format!(" Edit Route-Map: {} ", app.rm_editor_name);

    let mut items: Vec<ListItem> = Vec::new();
    for (i, entry) in app.rm_editor_entries.iter().enumerate() {
        let is_sel = i == app.rm_editor_selected;
        let marker = if is_sel { "▶ " } else { "  " };
        let sel_style = if is_sel {
            Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_HEADER)
        };

        if app.rm_editor_editing && is_sel {
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

            for m in &entry.match_clauses {
                items.push(ListItem::new(Line::from(vec![
                    Span::raw("      "),
                    Span::styled("Match: ", Style::default().fg(C_DIM)),
                    Span::styled(m, Style::default().fg(C_HEADER)),
                ])));
            }
            for s in &entry.set_clauses {
                items.push(ListItem::new(Line::from(vec![
                    Span::raw("      "),
                    Span::styled("Set:   ", Style::default().fg(C_DIM)),
                    Span::styled(s, Style::default().fg(C_WARN)),
                ])));
            }
            if entry.match_clauses.is_empty() && entry.set_clauses.is_empty() {
                items.push(ListItem::new(Line::from(Span::styled(
                    "      (no match/set clauses)",
                    Style::default().fg(C_DIM),
                ))));
            }
        }

        items.push(ListItem::new(Line::from(Span::styled(
            "  ──────────────────────────────────",
            Style::default().fg(C_BORDER),
        ))));
    }

    if app.rm_editor_entries.is_empty() {
        items.push(ListItem::new(Span::styled(
            "  (no entries — press 'a' to add)",
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

    let help = if app.rm_editor_editing {
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
            key_span("a"),
            hint_span(":add  "),
            key_span("d"),
            hint_span(":delete  "),
            key_span("s"),
            hint_span(":save & push  "),
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
        rows[1],
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
