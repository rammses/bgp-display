---
description: "Project architecture context for bgp-link-manager — read this instead of ARCHITECTURE.md"
alwaysApply: true
---
# bgp-link-manager — Architecture Summary

Single-binary async Rust TUI for managing BGP sessions across multi-vendor routers.
Encrypted SQLite DB (Argon2id + AES-256-GCM), SSH via system OpenSSH with ControlMaster mux.

## Module Map

| File | Purpose | Notes |
|------|---------|-------|
| `main.rs` | Entry point, passphrase prompt, logging init | Minimal |
| `app.rs` | App state machine, all state, tick(), key handler | ~1900 lines — largest file |
| `tui.rs` | Terminal setup, run_loop() with lag timing, cleanup | Instruments draw + event timing |
| `events.rs` | AppEvent enum, FetchRequest enum, EventHandler (tick + key tasks) | MPSC unbounded channel |
| `logging.rs` | File-based tracing init, lag thresholds | `BGP_LM_LOG` env var control |
| `ssh.rs` | SshSessionManager — centralized SSH pool, warm-up, health checks | `Arc<SshSessionManager>` |
| `fetch.rs` | DataFetchService — background worker for SSH fetches | Processes `FetchRequest` via SSH manager |
| `config.rs` | AppConfig (loads from DB) | |
| `db.rs` | RouterDb — encrypted SQLite | Argon2id + AES-256-GCM |
| `bgp/mod.rs` | BgpSummary, BgpPeer, BgpRoute, parsers | Shared by all backends |
| `router/mod.rs` | RouterConfig, RouterVendor, RouterBackend dispatch, SSH mux | Enum dispatch, not trait objects |
| `router/cisco.rs` | CiscoBackend — delegates SSH to SshSessionManager | Primary backend |
| `router/vyos.rs` | VyOsBackend — vtysh via SshSessionManager | FRRouting |
| `router/citrix.rs` | CitrixVpxBackend — shell pipe via SshSessionManager | |
| `router/pfsense.rs` | PfSenseBackend — piped stdin via SshSessionManager | |
| `router/fortigate.rs` | FortiGateBackend — piped stdin, VDOM support | |
| `ui/mod.rs` | draw(), color palette, helpers | |
| `ui/dashboard.rs` | Tab 1 — router list + summary + sparkline | |
| `ui/peers.rs` | Tab 2 — peer table + detail pane | |
| `ui/routes.rs` | Tab 3 — route table + detail | |
| `ui/config_tab.rs` | Tab 4 — syntax-highlighted config + route-map detail | |
| `ui/logs.rs` | Tab 5 — scrollable event log | |
| `ui/router_editor.rs` | Tab 6 — add/edit/delete routers | |
| `ui/conn_log.rs` | Tab 7 — connectivity event history | |
| `ui/project_popup.rs` | Overlay — project list, router toggle | |

## Core Types (bgp/mod.rs)

- `BgpSummary` — router_id, local_as, table_version, peers: Vec<BgpPeer>, fetched_at
- `BgpPeer` — neighbor_ip, remote_as, state: BgpState, uptime, prefixes, route_maps, timers
- `BgpRoute` — status: RouteStatus, network, next_hop, metric, local_pref, as_path, origin
- `RouteMapDetail` — name, entries (seq/action/match/set), prefix_lists, community_lists
- `BgpState` — Idle | Connect | Active | OpenSent | OpenConfirm | Established | Unknown
- `RouterConfig` — id: Uuid, name, hostname, vendor: RouterVendor, ssh_port, username, password
- `RouterVendor` — Cisco | VyOs | CitrixVpx | PfSense | FortiGate
- `RouterBackend` — enum dispatch: Cisco | VyOs | CitrixVpx | PfSense (not trait objects)

## App Struct Key Field Groups

- **Navigation**: current_tab, should_quit
- **Routers**: routers, router_list_state, backends
- **BGP cache**: bgp_cache: HashMap<Uuid, BgpCache> (summary, peers, routes, config text per router)
- **Display**: current_summary/peers/routes, table states
- **Config tab**: rendered_config, routemap_cache, routemap_detail_scroll
- **Logs**: logs + conn_logs (500 entry cap)
- **Editor**: editor_mode, editor_field, editor_buf, editor_draft
- **Timers**: tick_counter, ping_tick (mod 25 = 5s), bgp_refresh_tick (mod 150 = 30s)
- **Background**: event_tx: Option<UnboundedSender<AppEvent>>, fetch_tx: Option<UnboundedSender<FetchRequest>>
- **Pending updates**: pending_bgp_update, pending_route_update (deferred if on Config tab)
- **Projects**: all_routers, projects, active_project

## Event System

AppEvent: Key | Tick | Resize | PingResult | BgpData | BgpError | RouteData | RouteMapDetail | PeerRoutes | PeerRoutesError | MtuProbeResult | MtuProbeError | SshWarmComplete | SshHealthReport

FetchRequest: RefreshRouter | RefreshMany | FetchRouteMap | FetchPeerRoutes | FetchMtu | Ping

Single-threaded state mutation loop. Background tasks push results via cloned MPSC sender.

## Key Architectural Patterns

- **SSH mux**: ControlMaster=auto, ControlPath=/tmp/bgp-lm-%C, ControlPersist=600
- **SshSessionManager** (`src/ssh.rs`): centralized SSH transport — `run_cmd()`, `run_piped()`, `run_shell_pipe()`. Pre-warms ControlMaster at startup, periodic health checks (60 s), auto mux-retry on stale sockets.
- **DataFetchService** (`src/fetch.rs`): background tokio task processing `FetchRequest` via `SshSessionManager`. App never spawns SSH directly — only sends `FetchRequest`.
- **Structured logging** (`src/logging.rs`): `tracing` crate with daily-rotating file appender. Lag thresholds: draw > 16 ms, event > 5 ms, SSH > 10 s, fetch > 15 s. SSH errors → file log only; UI gets truncated summaries.
- **Password auth**: sshpass -e with SSHPASS env var; key-based uses BatchMode=yes
- **Deferred updates**: BgpSummary::content_eq() skips fetched_at; changes deferred while user is on Config tab (y/n banner)
- **Route-map caching**: routemap_cache[(router_id, rm_name)] avoids redundant SSH fetches; invalidated on new BGP data
- **Vendor backend dispatch**: RouterBackend enum with match arms, not dyn Trait
- **Cache-only UI**: Tab/router switching reads from bgp_cache, never triggers SSH. All SSH is initiated by DataFetchService.

## Dependencies

ratatui 0.29, crossterm 0.28, tokio 1 (full), serde, anyhow, chrono, uuid, regex, dirs, futures, rusqlite 0.31 (bundled), aes-gcm 0.10, argon2 0.5, rand 0.8, base64 0.22, tracing 0.1, tracing-subscriber 0.3, tracing-appender 0.2

## Adding a New Vendor Backend

1. Create `src/router/<vendor>.rs` with connect/disconnect/refresh/get_routes/fetch_route_map_detail
2. Register in `router/mod.rs`: add module, RouterBackend variant, dispatch arms, RouterVendor variant
3. Wire in `app.rs`: spawn_bgp_fetch_for() + spawn_routemap_fetch() match arms
4. Handle in `db.rs`: load_all() deserialization
5. Handle in editor: Space cycle (editor_field == 5) + apply_buf_to_draft()
