mod app;
mod bgp;
mod config;
mod db;
mod events;
mod router;
mod tui;
mod ui;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let passphrase = read_passphrase()?;
    let (cfg, router_db) = config::AppConfig::load_with_key(&passphrase)?;
    let mut app = app::App::new(cfg, router_db);
    tui::run_tui(&mut app).await
}

/// Full-screen TUI passphrase prompt using ratatui.
fn read_passphrase() -> Result<String> {
    use crossterm::{
        event::{read, Event, KeyCode, KeyEvent, KeyModifiers},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::{
        backend::CrosstermBackend,
        layout::{Alignment, Constraint, Direction, Layout},
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, Clear, Paragraph},
        Terminal,
    };
    use std::io;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;
    term.hide_cursor()?;

    let mut buf = String::new();
    let mut error_msg: Option<String> = None;

    let result = loop {
        term.draw(|f| {
            let area = f.area();

            // Background fill
            f.render_widget(Clear, area);

            // Center the dialog vertically
            let vert = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Min(0),
                    Constraint::Length(14),
                    Constraint::Min(0),
                ])
                .split(area);

            // Center horizontally
            let horiz = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Min(0),
                    Constraint::Length(56),
                    Constraint::Min(0),
                ])
                .split(vert[1]);

            let dialog_area = horiz[1];

            // Inner rows
            let inner = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // title
                    Constraint::Length(1), // spacer
                    Constraint::Length(1), // ascii art line 1
                    Constraint::Length(1), // ascii art line 2
                    Constraint::Length(1), // spacer
                    Constraint::Length(1), // label
                    Constraint::Length(3), // input box
                    Constraint::Length(1), // error / hint
                    Constraint::Min(0),   // rest
                ])
                .split(centered_inner(dialog_area, 1, 2));

            // Outer border
            let border = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(Span::styled(
                    " BGP Link Manager ",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ))
                .title_alignment(Alignment::Center);
            f.render_widget(border, dialog_area);

            // Title
            let title = Paragraph::new(Line::from(vec![
                Span::styled(
                    "BGP Link Manager",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" v0.1.0", Style::default().fg(Color::DarkGray)),
            ]))
            .alignment(Alignment::Center);
            f.render_widget(title, inner[0]);

            // ASCII art / decoration
            let art1 = Paragraph::new(Line::from(Span::styled(
                "╔══════════════════════════════════════╗",
                Style::default().fg(Color::DarkGray),
            )))
            .alignment(Alignment::Center);
            f.render_widget(art1, inner[2]);

            let art2 = Paragraph::new(Line::from(Span::styled(
                "║   Encrypted Router Configuration DB  ║",
                Style::default().fg(Color::DarkGray),
            )))
            .alignment(Alignment::Center);
            f.render_widget(art2, inner[3]);

            // Label
            let label = Paragraph::new(Line::from(Span::styled(
                "Enter encryption passphrase:",
                Style::default().fg(Color::Yellow),
            )))
            .alignment(Alignment::Center);
            f.render_widget(label, inner[5]);

            // Input field
            let dots = "●".repeat(buf.len());
            let input_text = format!(" {dots}▌");
            let input = Paragraph::new(Line::from(Span::styled(
                &input_text,
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            )))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            );
            f.render_widget(input, inner[6]);

            // Error or hint
            if let Some(ref err) = error_msg {
                let err_line = Paragraph::new(Line::from(Span::styled(
                    err.as_str(),
                    Style::default().fg(Color::Red),
                )))
                .alignment(Alignment::Center);
                f.render_widget(err_line, inner[7]);
            } else {
                let hint = Paragraph::new(Line::from(Span::styled(
                    "Enter: confirm  ·  Esc: quit",
                    Style::default().fg(Color::DarkGray),
                )))
                .alignment(Alignment::Center);
                f.render_widget(hint, inner[7]);
            }
        })?;

        if let Event::Key(KeyEvent { code, modifiers, .. }) = read()? {
            error_msg = None;
            match code {
                KeyCode::Enter => {
                    if buf.is_empty() {
                        error_msg = Some("Passphrase cannot be empty".into());
                    } else {
                        break Ok(buf);
                    }
                }
                KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                    break Err(anyhow::anyhow!("Cancelled"));
                }
                KeyCode::Esc => {
                    break Err(anyhow::anyhow!("Cancelled"));
                }
                KeyCode::Char(c) => buf.push(c),
                KeyCode::Backspace => { buf.pop(); }
                _ => {}
            }
        }
    };

    // Restore terminal
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;

    result
}

/// Shrink a Rect by margin_x columns and margin_y rows on each side.
fn centered_inner(area: ratatui::layout::Rect, margin_y: u16, margin_x: u16) -> ratatui::layout::Rect {
    ratatui::layout::Rect {
        x:      area.x + margin_x,
        y:      area.y + margin_y,
        width:  area.width.saturating_sub(margin_x * 2),
        height: area.height.saturating_sub(margin_y * 2),
    }
}
