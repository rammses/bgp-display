use crate::{
    app::App,
    events::{AppEvent, EventHandler, FetchRequest},
    ui,
};
use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

use crate::logging::thresholds;
use crate::ssh::SshSessionManager;

pub async fn run_tui(app: &mut App) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;
    term.hide_cursor()?;

    // ── Event system ────────────────────────────────────────────────────────
    let mut events = EventHandler::new(Duration::from_millis(200));
    app.set_event_tx(events.sender());

    // ── SSH session manager ─────────────────────────────────────────────────
    // Only warm connections for the routers visible in the active project.
    let ssh = SshSessionManager::new(&app.routers);

    // Pre-warm all SSH connections in the background
    let ssh_warm = Arc::clone(&ssh);
    let warm_tx = events.sender();
    tokio::spawn(async move {
        ssh_warm.warm_all(&warm_tx).await;
    });

    // Periodic health checks (every 60 s)
    let ssh_health = Arc::clone(&ssh);
    let health_tx = events.sender();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await; // skip the immediate first tick
        loop {
            interval.tick().await;
            ssh_health.health_check_all(&health_tx).await;
        }
    });

    // ── Data fetch service ──────────────────────────────────────────────────
    let (fetch_tx, fetch_rx) = mpsc::unbounded_channel::<FetchRequest>();
    app.set_fetch_tx(fetch_tx);

    let fetch_ssh = Arc::clone(&ssh);
    let fetch_event_tx = events.sender();
    tokio::spawn(async move {
        crate::fetch::run_data_fetch_service(fetch_ssh, fetch_event_tx, fetch_rx).await;
    });

    // ── Initial data fetch ──────────────────────────────────────────────────
    app.request_ping();
    let all_ids: Vec<uuid::Uuid> = app.routers.iter().map(|r| r.id).collect();
    if !all_ids.is_empty() {
        app.send_fetch(FetchRequest::RefreshMany(all_ids));
    }

    tracing::info!("entering main event loop");

    // ── Main loop ───────────────────────────────────────────────────────────
    let result = run_loop(&mut term, app, &mut events).await;

    tracing::info!("exiting — cleaning up SSH connections");
    ssh.cleanup_all().await;

    // Always restore terminal even on error
    disable_raw_mode()?;
    execute!(
        term.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    term.show_cursor()?;

    result
}

async fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    events: &mut EventHandler,
) -> Result<()> {
    loop {
        // ── Draw phase ──────────────────────────────────────────────────────
        let draw_start = Instant::now();
        terminal.draw(|f| ui::draw(f, app))?;
        let draw_us = draw_start.elapsed().as_micros();

        if draw_us > thresholds::DRAW_WARN_US {
            tracing::warn!(
                draw_ms = draw_us / 1000,
                tab = ?app.current_tab,
                "UI draw exceeded frame budget"
            );
        } else {
            tracing::trace!(draw_us, "draw");
        }

        // ── Event phase ─────────────────────────────────────────────────────
        let event = events.next().await?;
        let event_label = event_name(&event);
        let event_start = Instant::now();

        match event {
            AppEvent::Key(key) => crate::app::handle_key(app, key),
            AppEvent::Tick => app.tick(),
            AppEvent::Resize => {}
            AppEvent::PingResult(id, reach) => app.handle_ping_result(id, reach),
            AppEvent::BgpData(id, summary, rendered) => app.handle_bgp_data(id, *summary, rendered),
            AppEvent::BgpError(id, err) => app.handle_bgp_error(id, err),
            AppEvent::RouteData(id, routes) => app.handle_route_data(id, routes),
            AppEvent::RouteMapDetail(id, d) => app.handle_routemap_detail(id, *d),
            AppEvent::PeerRoutes(id, ip, dir, routes) => {
                app.handle_peer_routes(id, ip, dir, routes)
            }
            AppEvent::PeerRoutesError(id, ip, dir, err) => {
                app.handle_peer_routes_error(id, ip, dir, err)
            }
            AppEvent::MtuProbeResult(id, ip, max_bytes) => {
                app.handle_mtu_probe_result(id, ip, max_bytes)
            }
            AppEvent::MtuProbeError(id, ip, err) => app.handle_mtu_probe_error(id, ip, err),
            AppEvent::SshWarmComplete(ready, failed) => app.handle_ssh_warm_complete(ready, failed),
            AppEvent::SshHealthReport {
                healthy,
                rewarmed,
                dead,
            } => app.handle_ssh_health_report(healthy, rewarmed, dead),
            AppEvent::PolicyData {
                router_id,
                prefix_lists,
                community_lists,
            } => {
                app.handle_policy_data(router_id, prefix_lists, community_lists);
            }
            AppEvent::ConfigApplied {
                router_id,
                description,
            } => {
                app.handle_config_applied(router_id, description);
            }
            AppEvent::ConfigError {
                router_id,
                description,
                error,
            } => {
                app.handle_config_error(router_id, description, error);
            }
        }

        let event_us = event_start.elapsed().as_micros();
        if event_us > thresholds::EVENT_WARN_US {
            tracing::warn!(
                event = %event_label,
                event_ms = event_us / 1000,
                "event handler exceeded budget"
            );
        } else {
            tracing::trace!(event = %event_label, event_us, "event handled");
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}

fn event_name(ev: &AppEvent) -> &'static str {
    match ev {
        AppEvent::Key(_) => "Key",
        AppEvent::Tick => "Tick",
        AppEvent::Resize => "Resize",
        AppEvent::PingResult(..) => "PingResult",
        AppEvent::BgpData(..) => "BgpData",
        AppEvent::BgpError(..) => "BgpError",
        AppEvent::RouteData(..) => "RouteData",
        AppEvent::RouteMapDetail(..) => "RouteMapDetail",
        AppEvent::PeerRoutes(..) => "PeerRoutes",
        AppEvent::PeerRoutesError(..) => "PeerRoutesError",
        AppEvent::MtuProbeResult(..) => "MtuProbeResult",
        AppEvent::MtuProbeError(..) => "MtuProbeError",
        AppEvent::SshWarmComplete(..) => "SshWarmComplete",
        AppEvent::SshHealthReport { .. } => "SshHealthReport",
        AppEvent::PolicyData { .. } => "PolicyData",
        AppEvent::ConfigApplied { .. } => "ConfigApplied",
        AppEvent::ConfigError { .. } => "ConfigError",
    }
}
