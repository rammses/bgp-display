use crate::{
    app::{App, FilterMode, PingStats},
    router::ConnectionStatus,
    ui::{C_BORDER, C_DIM, C_ERROR, C_ESTABLISHED, C_HEADER, C_SELECTED, C_WARN},
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

// ─── Connectivity Log tab ─────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let (main_area, filter_area) = if app.conn_log_filter_mode != FilterMode::Off {
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(3)])
            .split(area);
        (parts[0], Some(parts[1]))
    } else {
        (area, None)
    };

    let status_height = 2 + (app.routers.len() as u16 * 2);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(status_height)])
        .split(main_area);

    draw_log_list(f, app, rows[0]);
    draw_status_panel(f, app, rows[1]);

    if let Some(fa) = filter_area {
        draw_filter_bar(
            f,
            &app.conn_log_filter,
            app.conn_log_filter_mode == FilterMode::Typing,
            fa,
        );
    }
}

// ─── Event log ────────────────────────────────────────────────────────────────

fn draw_log_list(f: &mut Frame, app: &mut App, area: Rect) {
    let use_filter =
        app.conn_log_filter_mode != FilterMode::Off && !app.conn_log_indices.is_empty();

    let style_for = |entry: &str| -> Style {
        if entry.contains("ONLINE") {
            Style::default().fg(C_ESTABLISHED)
        } else if entry.contains("OFFLINE") {
            Style::default().fg(C_ERROR)
        } else if entry.contains("added") || entry.contains("updated") {
            Style::default().fg(C_HEADER)
        } else if entry.contains("removed") {
            Style::default().fg(C_WARN)
        } else {
            Style::default().fg(C_DIM)
        }
    };

    let items: Vec<ListItem> = if app.conn_logs.is_empty() {
        vec![ListItem::new(Span::styled(
            "  No SSH events yet — probes run every 5 s.",
            Style::default().fg(C_DIM),
        ))]
    } else if use_filter {
        app.conn_log_indices
            .iter()
            .filter_map(|&i| app.conn_logs.get(i))
            .map(|entry| ListItem::new(Span::styled(entry.as_str(), style_for(entry))))
            .collect()
    } else {
        app.conn_logs
            .iter()
            .map(|entry| ListItem::new(Span::styled(entry.as_str(), style_for(entry))))
            .collect()
    };

    let title = if app.conn_logs.is_empty() {
        " SSH Connectivity ".to_string()
    } else if use_filter {
        format!(
            " SSH Connectivity ({}/{} events) ",
            app.conn_log_indices.len(),
            app.conn_logs.len()
        )
    } else {
        format!(" SSH Connectivity ({} events) ", app.conn_logs.len())
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

    f.render_stateful_widget(list, area, &mut app.conn_log_state);
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

// ─── Current status + ping monitor ───────────────────────────────────────────

fn draw_status_panel(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = vec![];
    for r in &app.routers {
        let (dot, dot_style, label) = match app.router_status.get(&r.id) {
            Some(ConnectionStatus::Connected) => {
                ("●", Style::default().fg(C_ESTABLISHED), "Online")
            }
            Some(ConnectionStatus::Connecting) => ("◌", Style::default().fg(C_WARN), "Connecting"),
            Some(ConnectionStatus::Error(_)) => ("✕", Style::default().fg(C_ERROR), "Error"),
            _ => ("○", Style::default().fg(C_DIM), "Offline"),
        };

        let stats = app.ping_stats.get(&r.id);
        let rtt_span = format_rtt_span(stats);
        let loss_span = format_loss_span(stats);

        lines.push(Line::from(vec![
            Span::styled(dot, dot_style),
            Span::raw(" "),
            Span::styled(format!("{:<14}", r.name), Style::default().fg(C_HEADER)),
            Span::styled(format!("{:<16}", r.hostname), Style::default().fg(C_DIM)),
            Span::styled(format!("{:<8}", label), dot_style),
            rtt_span,
            Span::raw("  "),
            loss_span,
        ]));

        let sparkline_line = build_sparkline_line(stats);
        lines.push(sparkline_line);
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(
                " Ping Monitor ",
                Style::default().fg(C_HEADER),
            )),
    );
    f.render_widget(para, area);
}

fn format_rtt_span(stats: Option<&PingStats>) -> Span<'static> {
    match stats.and_then(|s| s.last_rtt) {
        Some(d) => {
            let ms = d.as_secs_f64() * 1000.0;
            let color = if ms < 20.0 {
                C_ESTABLISHED
            } else if ms < 100.0 {
                C_WARN
            } else {
                C_ERROR
            };
            Span::styled(format!("{ms:>6.1}ms"), Style::default().fg(color))
        }
        None => {
            if stats.map_or(true, |s| s.history.is_empty()) {
                Span::styled("   ---  ", Style::default().fg(C_DIM))
            } else {
                Span::styled(" timeout", Style::default().fg(C_ERROR))
            }
        }
    }
}

fn format_loss_span(stats: Option<&PingStats>) -> Span<'static> {
    match stats {
        Some(s) if !s.history.is_empty() => {
            let pct = s.loss_pct();
            let color = if pct < 1.0 {
                C_ESTABLISHED
            } else if pct < 25.0 {
                C_WARN
            } else {
                C_ERROR
            };
            Span::styled(format!("loss:{pct:>5.1}%"), Style::default().fg(color))
        }
        _ => Span::styled("           ", Style::default().fg(C_DIM)),
    }
}

const SPARK_CHARS: &[char] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

fn build_sparkline_line(stats: Option<&PingStats>) -> Line<'static> {
    let mut spans = vec![Span::raw("  ")];

    let stats = match stats {
        Some(s) if !s.history.is_empty() => s,
        _ => {
            spans.push(Span::styled(
                "  awaiting probes…",
                Style::default().fg(C_DIM),
            ));
            return Line::from(spans);
        }
    };

    let data = stats.sparkline_data();
    let max_val = data.iter().copied().max().unwrap_or(1).max(1) as f64;

    spans.push(Span::styled("  rtt ", Style::default().fg(C_DIM)));

    for val in &data {
        let (ch, style) = if *val == 0 {
            ('_', Style::default().fg(C_ERROR))
        } else {
            let idx = ((*val as f64 / max_val) * 7.0).round() as usize;
            let idx = idx.min(7);
            let ms = *val as f64;
            let color = if ms < 20.0 {
                C_ESTABLISHED
            } else if ms < 100.0 {
                C_WARN
            } else {
                C_ERROR
            };
            (SPARK_CHARS[idx], Style::default().fg(color))
        };
        spans.push(Span::styled(ch.to_string(), style));
    }

    if let (Some(min), Some(avg), Some(max)) =
        (stats.min_rtt_ms(), stats.avg_rtt_ms(), stats.max_rtt_ms())
    {
        spans.push(Span::styled(
            format!("  min:{min:.0} avg:{avg:.0} max:{max:.0}ms"),
            Style::default().fg(C_DIM),
        ));
    }

    Line::from(spans)
}
