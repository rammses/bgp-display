use crate::{
    app::App,
    ui::{C_BORDER, C_DIM, C_HEADER, C_SELECTED},
};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, List, ListItem},
    Frame,
};

// ─── Logs tab ─────────────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app
        .logs
        .iter()
        .map(|entry| {
            let style = if entry.contains("error") || entry.contains("Error") {
                Style::default().fg(Color::Red)
            } else if entry.contains("warn") || entry.contains("Warn") {
                Style::default().fg(Color::Yellow)
            } else if entry.contains("refresh")
                || entry.contains("Refresh")
                || entry.contains("started")
            {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(C_DIM)
            };
            ListItem::new(Span::styled(entry.as_str(), style))
        })
        .collect();

    let title = format!(" BGP Events ({} entries) ", app.logs.len());

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(title, Style::default().fg(C_HEADER))),
        )
        .highlight_style(Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut app.log_list_state);
}
