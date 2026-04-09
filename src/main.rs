mod app;
mod bgp;
mod config;
mod db;
mod events;
mod export;
mod fetch;
mod logging;
mod router;
mod ssh;
mod tui;
mod ui;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let _log_guard = logging::init();

    let passphrase = read_passphrase()?;
    let (mut cfg, router_db) = config::AppConfig::load_with_key(&passphrase)?;
    tracing::info!(
        routers = cfg.routers.len(),
        projects = cfg.projects.len(),
        "config loaded"
    );

    // Ask user to pick or create a project (required)
    {
        let selected_id = select_project(&mut cfg.projects, &router_db)?;
        cfg.selected_project = Some(selected_id);
        if let Some(p) = cfg.projects.iter().find(|p| p.id == selected_id) {
            tracing::info!(project = %p.name, "project selected");
        }
    }

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
                    Constraint::Min(0),    // rest
                ])
                .split(centered_inner(dialog_area, 1, 2));

            // Outer border
            let border = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(Span::styled(
                    " BGP Link Manager ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ))
                .title_alignment(Alignment::Center);
            f.render_widget(border, dialog_area);

            // Title
            let title = Paragraph::new(Line::from(vec![
                Span::styled(
                    "BGP Link Manager",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
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
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
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

        if let Event::Key(KeyEvent {
            code, modifiers, ..
        }) = read()?
        {
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
                KeyCode::Backspace => {
                    buf.pop();
                }
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
fn centered_inner(
    area: ratatui::layout::Rect,
    margin_y: u16,
    margin_x: u16,
) -> ratatui::layout::Rect {
    ratatui::layout::Rect {
        x: area.x + margin_x,
        y: area.y + margin_y,
        width: area.width.saturating_sub(margin_x * 2),
        height: area.height.saturating_sub(margin_y * 2),
    }
}

/// Full-screen TUI project selector shown after passphrase entry.
/// Returns the UUID of the selected (or newly created) project.
fn select_project(projects: &mut Vec<router::Project>, db: &db::RouterDb) -> Result<uuid::Uuid> {
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
        widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
        Terminal,
    };
    use std::io;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;
    term.hide_cursor()?;

    let mut state = ListState::default();
    if !projects.is_empty() {
        state.select(Some(0));
    }
    let mut naming = false;
    let mut name_buf = String::new();

    let result = loop {
        let total_items = projects.len() + 1; // +1 for "+ New Project"
        term.draw(|f| {
            let area = f.area();
            f.render_widget(Clear, area);

            let list_height = (total_items as u16).min(14) + 6;
            let vert = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Min(0),
                    Constraint::Length(list_height),
                    Constraint::Min(0),
                ])
                .split(area);

            let horiz = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Min(0),
                    Constraint::Length(50),
                    Constraint::Min(0),
                ])
                .split(vert[1]);

            let dialog_area = horiz[1];
            let inner = centered_inner(dialog_area, 1, 1);

            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(0), Constraint::Length(2)])
                .split(inner);

            let mut items: Vec<ListItem> = projects
                .iter()
                .map(|p| {
                    let count = p.router_ids.len();
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("  {} ", p.name), Style::default().fg(Color::Cyan)),
                        Span::styled(
                            format!("({count} routers)"),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]))
                })
                .collect();

            // "+ New Project" entry (or inline name editor)
            if naming {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("  Name: ", Style::default().fg(Color::Green)),
                    Span::styled(
                        format!("{}▌", name_buf),
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                ])));
            } else {
                items.push(ListItem::new(Line::from(Span::styled(
                    "  + New Project",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ))));
            }

            let list = List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Cyan))
                        .title(Span::styled(
                            " Select Project ",
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        ))
                        .title_alignment(Alignment::Center),
                )
                .highlight_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("▶ ");

            f.render_stateful_widget(list, rows[0], &mut state);

            let hint = if naming {
                Paragraph::new(Line::from(vec![
                    Span::styled(" Enter", Style::default().fg(Color::Yellow)),
                    Span::styled(":create  ", Style::default().fg(Color::DarkGray)),
                    Span::styled("Esc", Style::default().fg(Color::Yellow)),
                    Span::styled(":cancel", Style::default().fg(Color::DarkGray)),
                ]))
            } else {
                Paragraph::new(Line::from(vec![
                    Span::styled(" ↑↓", Style::default().fg(Color::Yellow)),
                    Span::styled(":navigate  ", Style::default().fg(Color::DarkGray)),
                    Span::styled("Enter", Style::default().fg(Color::Yellow)),
                    Span::styled(":select  ", Style::default().fg(Color::DarkGray)),
                    Span::styled("Esc", Style::default().fg(Color::Yellow)),
                    Span::styled(":quit", Style::default().fg(Color::DarkGray)),
                ]))
            };
            f.render_widget(hint, rows[1]);
        })?;

        if let Event::Key(KeyEvent {
            code, modifiers, ..
        }) = read()?
        {
            if naming {
                // Inline name editor mode
                match code {
                    KeyCode::Enter => {
                        let name = name_buf.trim().to_string();
                        if !name.is_empty() {
                            let proj = router::Project::new(name);
                            let _ = db.upsert_project(&proj);
                            let id = proj.id;
                            projects.push(proj);
                            break Ok(id);
                        }
                    }
                    KeyCode::Esc => {
                        naming = false;
                        name_buf.clear();
                    }
                    KeyCode::Backspace => {
                        name_buf.pop();
                    }
                    KeyCode::Char(c) => name_buf.push(c),
                    _ => {}
                }
            } else {
                match code {
                    KeyCode::Enter => {
                        if let Some(idx) = state.selected() {
                            if idx < projects.len() {
                                break Ok(projects[idx].id);
                            } else {
                                // "+ New Project" selected
                                naming = true;
                            }
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        let next = match state.selected() {
                            Some(0) | None => total_items - 1,
                            Some(i) => i - 1,
                        };
                        state.select(Some(next));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let next = match state.selected() {
                            Some(i) => (i + 1) % total_items,
                            None => 0,
                        };
                        state.select(Some(next));
                    }
                    KeyCode::Char('n') => {
                        state.select(Some(projects.len()));
                        naming = true;
                    }
                    KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                        break Err(anyhow::anyhow!("Cancelled"));
                    }
                    KeyCode::Esc => {
                        break Err(anyhow::anyhow!("Cancelled"));
                    }
                    _ => {}
                }
            }
        }
    };

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;

    result
}
