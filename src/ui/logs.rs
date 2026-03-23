use crate::{
    app::{App, FilterMode},
    ui::{C_BORDER, C_DIM, C_HEADER, C_SELECTED, C_WARN},
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

// ─── Logs tab ─────────────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let (list_area, filter_area) = if app.log_filter_mode != FilterMode::Off {
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(3)])
            .split(area);
        (parts[0], Some(parts[1]))
    } else {
        (area, None)
    };

    let use_filter = app.log_filter_mode != FilterMode::Off && !app.log_indices.is_empty();

    let style_for = |entry: &str| -> Style {
        if entry.contains("error") || entry.contains("Error") {
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
        }
    };

    let items: Vec<ListItem> = if use_filter {
        app.log_indices
            .iter()
            .filter_map(|&i| app.logs.get(i))
            .map(|entry| ListItem::new(Span::styled(entry.as_str(), style_for(entry))))
            .collect()
    } else {
        app.logs
            .iter()
            .map(|entry| ListItem::new(Span::styled(entry.as_str(), style_for(entry))))
            .collect()
    };

    let title = if use_filter {
        format!(
            " BGP Events ({}/{} entries) ",
            app.log_indices.len(),
            app.logs.len()
        )
    } else {
        format!(" BGP Events ({} entries) ", app.logs.len())
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(title, Style::default().fg(C_HEADER))),
        )
        .highlight_style(Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, list_area, &mut app.log_list_state);

    if let Some(fa) = filter_area {
        draw_filter_bar(
            f,
            &app.log_filter,
            app.log_filter_mode == FilterMode::Typing,
            fa,
        );
    }
}

fn draw_filter_bar(f: &mut Frame, filter: &str, is_typing: bool, area: Rect) {
    let cursor = if is_typing { "▌" } else { "" };
    let hint = if is_typing {
        " Enter: apply  Esc: clear"
    } else {
        " /: edit  Esc: clear"
    };
    let content = Line::from(vec![
        Span::styled(
            format!(" / {filter}{cursor}"),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(hint.to_string(), Style::default().fg(C_DIM)),
    ]);
    let border_style = if is_typing {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(C_WARN)
    };
    let para = Paragraph::new(content).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(Span::styled(" Filter ", Style::default().fg(C_SELECTED))),
    );
    f.render_widget(para, area);
}
