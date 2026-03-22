use anyhow::Result;
use crossterm::event::{Event, EventStream, KeyEvent};
use futures::StreamExt;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;

// ─── App Events ───────────────────────────────────────────────────────────────

pub enum AppEvent {
    Key(KeyEvent),
    Tick,
    Resize,
    /// Result of a background TCP reachability probe.
    PingResult(Uuid, bool),
    /// BGP summary fetched successfully (includes pre-rendered config stanza).
    BgpData(Uuid, Box<crate::bgp::BgpSummary>, String),
    /// BGP fetch failed for a router.
    BgpError(Uuid, String),
    /// BGP route table fetched successfully.
    RouteData(Uuid, Vec<crate::bgp::BgpRoute>),
    /// Route-map detail (entries + expanded prefix/community lists) fetched.
    RouteMapDetail(Uuid, Box<crate::bgp::RouteMapDetail>),
    /// Per-peer routes fetched (received or advertised).
    PeerRoutes(
        Uuid,
        IpAddr,
        crate::bgp::PeerRouteDirection,
        Vec<crate::bgp::BgpRoute>,
    ),
    /// Per-peer routes fetch failed.
    PeerRoutesError(Uuid, IpAddr, crate::bgp::PeerRouteDirection, String),
    /// Path-MTU probe result. The u16 is the max IP-frame size that succeeded (0 = all failed).
    MtuProbeResult(Uuid, IpAddr, u16),
    /// Path-MTU probe could not be executed (SSH error etc.).
    MtuProbeError(Uuid, IpAddr, String),
    /// SSH ControlMaster warm-up completed: (ready_count, failed: Vec<(name, error)>).
    SshWarmComplete(usize, Vec<(String, String)>),
    /// Periodic SSH health-check report: (healthy, re-warmed, still_dead).
    SshHealthReport {
        healthy: usize,
        rewarmed: usize,
        dead: Vec<String>,
    },
}

// ─── Fetch Requests (App → DataFetchService) ────────────────────────────────

/// Messages sent from the App to the background DataFetchService.
pub enum FetchRequest {
    /// Full BGP refresh for a single router (summary + routes).
    RefreshRouter(Uuid),
    /// Refresh all connected routers (IDs supplied by caller).
    RefreshMany(Vec<Uuid>),
    /// Fetch route-map detail for a router.
    FetchRouteMap { router_id: Uuid, rm_name: String },
    /// Fetch per-peer received/advertised routes.
    FetchPeerRoutes {
        router_id: Uuid,
        ip: IpAddr,
        dir: crate::bgp::PeerRouteDirection,
    },
    /// Run a DF-bit MTU probe from a router to target.
    FetchMtu { router_id: Uuid, target: IpAddr },
    /// TCP reachability probes: vec of (router_id, "host:port").
    Ping(Vec<(Uuid, String)>),
}

// ─── Event Handler ────────────────────────────────────────────────────────────

pub struct EventHandler {
    rx: mpsc::UnboundedReceiver<AppEvent>,
    /// Held so callers can clone it to inject events (e.g. ping results).
    pub tx: mpsc::UnboundedSender<AppEvent>,
}

impl EventHandler {
    pub fn new(tick_rate: Duration) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<AppEvent>();

        // ── Tick task ─────────────────────────────────────────────────────────
        let tx_tick = tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tick_rate);
            loop {
                interval.tick().await;
                if tx_tick.send(AppEvent::Tick).is_err() {
                    break;
                }
            }
        });

        // ── Crossterm event reader task ───────────────────────────────────────
        let tx_ev = tx.clone();
        tokio::spawn(async move {
            let mut stream = EventStream::new();
            while let Some(Ok(event)) = stream.next().await {
                let app_event = match event {
                    Event::Key(k) => AppEvent::Key(k),
                    Event::Resize(_, _) => AppEvent::Resize,
                    _ => continue,
                };
                if tx_ev.send(app_event).is_err() {
                    break;
                }
            }
        });

        Self { rx, tx }
    }

    /// Return a sender that can be used to inject events from background tasks.
    pub fn sender(&self) -> mpsc::UnboundedSender<AppEvent> {
        self.tx.clone()
    }

    pub async fn next(&mut self) -> Result<AppEvent> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Event channel closed"))
    }
}
