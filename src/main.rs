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

/// Read a passphrase from the terminal without echoing it.
/// Uses the `crossterm` raw-mode infrastructure already in scope.
fn read_passphrase() -> Result<String> {
    use crossterm::{
        event::{read, Event, KeyCode, KeyEvent},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode},
    };
    use std::io::{self, Write};

    print!("Enter encryption passphrase: ");
    io::stdout().flush()?;

    enable_raw_mode()?;
    let mut buf = String::new();
    loop {
        if let Event::Key(KeyEvent { code, .. }) = read()? {
            match code {
                KeyCode::Enter => break,
                KeyCode::Char(c) => buf.push(c),
                KeyCode::Backspace => { buf.pop(); }
                KeyCode::Esc => {
                    disable_raw_mode()?;
                    execute!(io::stdout(), crossterm::cursor::MoveToNextLine(1))?;
                    return Err(anyhow::anyhow!("Cancelled"));
                }
                _ => {}
            }
        }
    }
    disable_raw_mode()?;
    execute!(io::stdout(), crossterm::cursor::MoveToNextLine(1))?;
    Ok(buf)
}
