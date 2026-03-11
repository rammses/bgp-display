use crate::{app::App, events::{AppEvent, EventHandler}, ui};
use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{io, time::Duration};

pub async fn run_tui(app: &mut App) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend  = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;
    term.hide_cursor()?;

    let mut events = EventHandler::new(Duration::from_millis(200));
    app.set_event_tx(events.sender());
    app.spawn_ping();           // initial reachability probe
    app.spawn_bgp_fetch_selected(); // immediate BGP fetch for selected router
    // Pre-fetch BGP data for all routers so switching is instant
    for router in app.routers.clone() {
        app.spawn_bgp_fetch_for(router);
    }
    let result     = run_loop(&mut term, app, &mut events).await;

    // Gracefully close persistent SSH master connections
    crate::router::cleanup_ssh_sessions(&app.all_routers).await;

    // Always restore terminal even on error
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    term.show_cursor()?;

    result
}

async fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app:      &mut App,
    events:   &mut EventHandler,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        match events.next().await? {
            AppEvent::Key(key)              => crate::app::handle_key(app, key),
            AppEvent::Tick                  => app.tick(),
            AppEvent::Resize(_, _)          => {}
            AppEvent::PingResult(id, reach) => app.handle_ping_result(id, reach),
            AppEvent::BgpData(id, summary)  => app.handle_bgp_data(id, *summary),
            AppEvent::BgpError(id, err)     => app.handle_bgp_error(id, err),
            AppEvent::RouteData(id, routes) => app.handle_route_data(id, routes),
            AppEvent::RouteMapDetail(id, d) => app.handle_routemap_detail(id, *d),
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}
