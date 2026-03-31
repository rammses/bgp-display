# Architecture — bgp-link-manager

Deep-dive reference for contributors and maintainers. Covers every module, data flow, concurrency model, and extension point.

---

## Table of Contents

- [High-Level Overview](#high-level-overview)
- [Startup Sequence](#startup-sequence)
- [Module Map](#module-map)
- [Core Data Types](#core-data-types)
- [Application State (`App`)](#application-state-app)
- [Event System](#event-system)
- [TUI Event Loop](#tui-event-loop)
- [Key Handling](#key-handling)
- [SSH Execution Layer](#ssh-execution-layer)
- [Router Backends](#router-backends)
  - [Cisco IOS / IOS-XE](#cisco-ios--ios-xe)
  - [VyOS / FRRouting](#vyos--frrouting)
  - [Citrix NetScaler / VPX](#citrix-netscaler--vpx)
  - [pfSense](#pfsense)
  - [A10 Networks ADC](#a10-networks-adc)
  - [Mock](#mock)
- [BGP Parsing Pipeline](#bgp-parsing-pipeline)
- [Data Refresh Cycle](#data-refresh-cycle)
- [Change Detection & Deferred Updates](#change-detection--deferred-updates)
- [Route-Map Detail & Caching](#route-map-detail--caching)
- [Credential Storage](#credential-storage)
- [Project System](#project-system)
- [UI Architecture](#ui-architecture)
  - [Layout & Color Palette](#layout--color-palette)
  - [Tab 1 — Dashboard](#tab-1--dashboard)
  - [Tab 2 — Peers](#tab-2--peers)
  - [Tab 3 — Routes](#tab-3--routes)
  - [Tab 4 — Config](#tab-4--config)
  - [Tab 5 — Logs](#tab-5--logs)
  - [Tab 6 — Router Editor](#tab-6--router-editor)
  - [Tab 7 — Connectivity Log](#tab-7--connectivity-log)
  - [Project Popup](#project-popup)
- [Dependency Summary](#dependency-summary)
- [Adding a New Vendor Backend](#adding-a-new-vendor-backend)

---

## High-Level Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         Terminal (TUI)                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  ratatui / crossterm                                     │   │
│  │  7 tabs: Dashboard│Peers│Routes│Config│Logs│Routers│Conn │   │
│  └──────────────────────┬───────────────────────────────────┘   │
│                         │ draw()                                │
│  ┌──────────────────────▼───────────────────────────────────┐   │
│  │  App (state machine)                                     │   │
│  │  - router list, BGP cache, UI state, pending updates     │   │
│  │  - tick() drives periodic ping + BGP refresh             │   │
│  └───────┬──────────────────────────────┬───────────────────┘   │
│          │ tokio::spawn                 │ tokio::spawn           │
│  ┌───────▼──────────┐   ┌──────────────▼──────────────┐        │
│  │  Ping probes     │   │  Router backends            │        │
│  │  TCP connect/2s  │   │  SSH → parse → AppEvent     │        │
│  └──────────────────┘   └──────────────┬──────────────┘        │
│                                        │                        │
│           ┌────────────────────────────▼─┐                      │
│           │  OpenSSH ControlMaster mux   │                      │
│           │  /tmp/bgp-lm-%C              │                      │
│           └──────────────────────────────┘                      │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  RouterDb (SQLite + AES-256-GCM)                        │   │
│  │  ~/Library/Application Support/bgp-link-manager/        │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

The application is a single-binary async TUI that:

1. Opens an encrypted SQLite database (passphrase → Argon2id → AES-256-GCM).
2. Spawns background TCP ping probes and SSH-based BGP data fetches on a periodic timer.
3. Parses Cisco/FRR CLI output into structured types.
4. Renders everything through a 7-tab ratatui interface.
5. Reuses SSH connections via OpenSSH `ControlMaster` multiplexing.

---

## Startup Sequence

```
main()
  │
  ├─ read_passphrase()          Full-screen masked input dialog (ratatui)
  │
  ├─ AppConfig::load_with_key() Opens/creates SQLite DB, derives AES key,
  │                             loads routers + projects
  │
  ├─ App::new(cfg, router_db)   Builds state, selects first router,
  │                             calls reload_selected_router()
  │
  └─ tui::run_tui(&mut app)
       │
       ├─ Terminal setup         Raw mode, alternate screen, mouse capture
       ├─ EventHandler(200ms)    Spawns tick + crossterm reader tasks
       ├─ Initial fetches        spawn_ping(), spawn_bgp_fetch_selected(),
       │                         pre-fetch all routers
       ├─ run_loop()             Main draw → event → dispatch cycle
       │
       └─ Cleanup                cleanup_ssh_sessions(), restore terminal
```

---

## Module Map

```
src/
├── main.rs              Entry point, passphrase prompt, centered_inner() helper
├── tui.rs               Terminal setup, run_loop(), cleanup
├── events.rs            AppEvent enum, EventHandler (tick + key tasks)
├── app.rs               App struct, all state, tick(), key handler, spawners
├── config.rs            AppConfig (loads from DB, no file config)
├── db.rs                RouterDb — encrypted SQLite, Argon2id + AES-256-GCM
│
├── bgp/
│   └── mod.rs           BgpSummary, BgpPeer, BgpRoute, RouteMapDetail,
│                        parsers: parse_bgp_summary, parse_bgp_table, etc.
│
├── router/
│   ├── mod.rs           RouterConfig, RouterVendor, RouterBackend dispatch,
│   │                    ConnectionStatus, SSH_MUX_CONTROL_PATH, cleanup
│   ├── cisco.rs         CiscoBackend — ssh_run, refresh, parsers
│   ├── vyos.rs          VyOsBackend — raw_ssh_run + vtysh_run, sshpass
│   ├── citrix.rs        CitrixVpxBackend — interactive pipe pattern
│   ├── pfsense.rs       PfSenseBackend — menu option 8 shell entry
│   ├── a10.rs           A10Backend — direct shell + piped config
│   └── mock.rs          MockBackend — generated test data
│
└── ui/
    ├── mod.rs           draw(), color palette, state_style(), fmt_num()
    ├── dashboard.rs     Tab 1 — router list + summary + peer sparkline
    ├── peers.rs         Tab 2 — peer table + detail pane
    ├── routes.rs        Tab 3 — route table + detail pane
    ├── config_tab.rs    Tab 4 — syntax-highlighted config + route-map detail
    ├── logs.rs          Tab 5 — scrollable event log
    ├── router_editor.rs Tab 6 — add/edit/delete routers
    ├── conn_log.rs      Tab 7 — connectivity event history + status panel
    └── project_popup.rs Overlay — project list, name editor, router toggle
```

---

## Core Data Types

### BGP Enums

| Enum | Variants | Source |
|------|----------|--------|
| `BgpState` | `Idle`, `Connect`, `Active`, `OpenSent`, `OpenConfirm`, `Established`, `Unknown(String)` | `bgp/mod.rs` |
| `RouteOrigin` | `Igp` (i), `Egp` (e), `Incomplete` (?) | `bgp/mod.rs` |
| `RouteStatus` | `BestExternal` (*>), `Best` (>), `Valid` (*), `Internal` (i), `Suppressed` (s), `History` (h) | `bgp/mod.rs` |

### BGP Structs

```
BgpSummary
├── router_id: IpAddr                   Parsed from "BGP router identifier X.X.X.X"
├── local_as: u32                       Local autonomous system number
├── table_version: u64                  BGP table version
├── peers: Vec<BgpPeer>                 All BGP neighbors
└── fetched_at: DateTime<Utc>           Timestamp (excluded from content_eq)

BgpPeer
├── neighbor_ip: IpAddr                 Neighbor address
├── remote_as / local_as: u32           AS numbers → session_type() = iBGP|eBGP
├── state: BgpState                     Current BGP FSM state
├── uptime: Option<String>              e.g. "2d14h"
├── prefixes_received / _advertised     Prefix counters
├── description: Option<String>         From neighbor detail
├── route_map_in / _out: Option<String> Applied route-maps
├── update_source: Option<IpAddr>       update-source interface
├── next_hop_self / route_reflector_client / password_configured: bool
├── msg_rcvd / msg_sent: u64            Message counters
├── hold_time / keepalive: u16          Timer values
└── communities: Vec<String>            Negotiated communities

BgpRoute
├── status: RouteStatus                 Best / Valid / etc.
├── network: String                     CIDR prefix
├── next_hop: String                    Next-hop address
├── metric / local_pref / weight        Path attributes
├── as_path: Vec<u32>                   AS path
├── origin: RouteOrigin                 Origin code
└── communities: Vec<String>

RouteMapDetail
├── name: String                        Route-map name
├── entries: Vec<RouteMapEntry>         Ordered by sequence
│   ├── sequence: u32
│   ├── action: String                  "permit" | "deny"
│   ├── match_clauses: Vec<String>
│   └── set_clauses: Vec<String>
├── prefix_lists: HashMap<String, Vec<PrefixListEntry>>
│   └── PrefixListEntry { seq, action, prefix }
└── community_lists: HashMap<String, Vec<String>>
```

### Router / Infrastructure

```
RouterConfig
├── id: Uuid                            Stable identifier
├── name / hostname: String
├── vendor: RouterVendor                Cisco | VyOs | CitrixVpx | PfSense | FortiGate | A10
├── ssh_port: u16
├── username: String
├── password: Option<String>            Decrypted in-memory, encrypted at rest
├── local_as: Option<u32>               Discovered from BGP summary
└── router_id: Option<IpAddr>           Discovered from BGP summary

RouterVendor   { Cisco, VyOs, CitrixVpx, PfSense, FortiGate, A10 }
ConnectionStatus { Disconnected, Connecting, Connected, Error(String) }
Project        { id: Uuid, name: String, router_ids: Vec<Uuid> }
```

---

## Application State (`App`)

The `App` struct is the single source of truth. Key field groups:

| Group | Fields | Purpose |
|-------|--------|---------|
| **Navigation** | `current_tab`, `should_quit` | Active tab, quit signal |
| **Routers** | `routers`, `router_list_state`, `backends` | Router list + backend instances |
| **Connectivity** | `router_status: HashMap<Uuid, ConnectionStatus>` | Per-router TCP probe result |
| **BGP cache** | `bgp_cache: HashMap<Uuid, BgpCache>` | Full snapshot per router (summary, peers, routes, config text) |
| **Display** | `current_summary`, `current_peers`, `current_routes`, table states | What's rendered for the selected router |
| **Config tab** | `rendered_config`, `config_lines`, `config_list_state`, `config_rm_name`, `config_routemap`, `routemap_detail_scroll`, `routemap_cache` | Navigable config + route-map detail with caching and scrolling |
| **Logs** | `logs`, `log_list_state`, `conn_logs`, `conn_log_state` | Event + connectivity logs (500 entry cap, auto-scroll) |
| **Editor** | `editor_list_state`, `editor_mode`, `editor_field`, `editor_buf`, `editor_draft` | Router CRUD form state |
| **Timers** | `tick_counter`, `ping_tick`, `bgp_refresh_tick` | Counters for periodic background tasks |
| **Background** | `event_tx: Option<UnboundedSender<AppEvent>>` | Channel for async tasks to send events back |
| **Pending** | `pending_bgp_update`, `pending_route_update`, `has_pending_update` | Deferred update state for Config tab |
| **Projects** | `all_routers`, `projects`, `active_project`, popup state fields | Multi-project router grouping |
| **DB** | `router_db: Option<RouterDb>` | Encrypted persistence handle |

### Key Methods

| Method | Description |
|--------|-------------|
| `tick()` | Increments counters; every 25 ticks → `spawn_ping()`; every 150 ticks → `spawn_bgp_fetch_all_connected()` |
| `spawn_ping()` | TCP probe (host:port, 2s timeout) per router; result → `PingResult` event |
| `spawn_bgp_fetch_for(router)` | tokio::spawn: calls vendor backend `refresh()` + `get_routes()`, sends events |
| `reload_selected_router()` | Loads from `bgp_cache` instantly, then spawns async refresh |
| `handle_bgp_data(id, summary)` | Content-change detection, cache update, defers if on Config tab |
| `handle_route_data(id, routes)` | Cache + display update |
| `on_config_nav()` | Extracts route-map name from selected line, checks cache, spawns fetch |
| `handle_routemap_detail(id, detail)` | Caches + displays route-map detail |

---

## Event System

```rust
enum AppEvent {
    Key(KeyEvent),           // Keyboard input from crossterm
    Tick,                    // 200ms timer tick
    Resize(u16, u16),        // Terminal resize (currently unused)
    PingResult(Uuid, bool),  // TCP probe completed
    BgpData(Uuid, Box<BgpSummary>),   // BGP summary fetched
    BgpError(Uuid, String),           // BGP fetch failed
    RouteData(Uuid, Vec<BgpRoute>),   // Route table fetched
    RouteMapDetail(Uuid, Box<RouteMapDetail>), // Route-map detail fetched
}
```

`EventHandler` owns an MPSC unbounded channel and spawns two tokio tasks:

1. **Tick task** — sends `AppEvent::Tick` every 200ms.
2. **Key task** — reads crossterm `EventStream`, maps to `AppEvent::Key` / `AppEvent::Resize`.

Background SSH tasks (ping, BGP fetch, route-map fetch) get a cloned sender and push results directly into the same channel.

---

## TUI Event Loop

```
run_loop(terminal, app, events):
    loop {
        terminal.draw(|f| ui::draw(f, app))    ← render current state

        match events.next().await:              ← wait for next event
            Key(key)              → handle_key(app, key)
            Tick                  → app.tick()
            PingResult(id, ok)    → app.handle_ping_result(id, ok)
            BgpData(id, summary)  → app.handle_bgp_data(id, *summary)
            BgpError(id, err)     → app.handle_bgp_error(id, err)
            RouteData(id, routes) → app.handle_route_data(id, routes)
            RouteMapDetail(id, d) → app.handle_routemap_detail(id, *d)
            Resize                → (no-op, ratatui handles)

        if app.should_quit → break
    }
```

The loop is single-threaded for state mutation — all background work communicates through events.

---

## Key Handling

Priority chain (first match wins):

1. **Router editor field editing** — captures all input when `EditorMode::EditField` on Routers tab. Esc cancels, Tab/Enter advances, BackTab retreats, Space cycles vendor.
2. **Project popup** — captures all input when overlay is visible. Three sub-modes: `EditName`, `ToggleRouters`, `Browse`.
3. **Global quit** — `q`, `Q`, `Ctrl-C`.
4. **Tab switching** — `Tab`/`BackTab` cycle, `1`–`7` jump. Leaving Config tab auto-applies pending updates.
5. **Navigation** — `Up`/`k`, `Down`/`j` → per-tab list/table wrap-around navigation.
6. **Config scrolling** — `PageUp`/`PageDown` → scroll route-map detail panel ±10 lines.
7. **Refresh** — `r`/`F5` → reload selected router + ping.
8. **Pending update** — `y` accept, `n` dismiss (Config tab only).
9. **Project popup** — `p` opens overlay.
10. **Router editor** — `a` add, `d` delete, `s` save, `Enter` edit (Routers tab only).

---

## SSH Execution Layer

All SSH communication uses the system `ssh` binary via `tokio::process::Command`. There is **no embedded SSH library** — this keeps the binary lean and leverages the user's existing SSH config (keys, agent, ProxyJump, etc.).

### Connection Multiplexing

Every SSH invocation includes OpenSSH `ControlMaster` options:

```
-o ControlMaster=auto
-o ControlPath=/tmp/bgp-lm-%C      # %C = hash of %l%h%p%r
-o ControlPersist=600               # keep master alive 10 minutes
```

This means:
- The first SSH to a host opens a persistent master connection.
- Subsequent SSH commands to the same host reuse the existing TCP connection (near-zero latency).
- Masters are cleaned up on application exit via `ssh -O exit`.

### Password Authentication

When a router has a password configured, backends that need it use `sshpass -e` with the password in the `SSHPASS` environment variable. Key-based auth uses `BatchMode=yes` instead.

### Timeout & Safety

- `ConnectTimeout=5` — 5-second SSH connection timeout.
- `StrictHostKeyChecking=accept-new` — auto-accepts new host keys, rejects changed ones.
- `LogLevel=ERROR` — suppresses SSH banners.
- 15-second hard timeout on command execution via `tokio::time::timeout`.

---

## Router Backends

Each vendor backend is a struct with the same async interface. Dispatch is via `RouterBackend` enum, not dynamic trait objects:

```rust
enum RouterBackend {
    Cisco(CiscoBackend),
    VyOs(VyOsBackend),
    CitrixVpx(CitrixVpxBackend),
    PfSense(PfSenseBackend),
    A10(A10Backend),
}
```

All backends share the same struct shape:

```rust
struct XxxBackend {
    hostname: String,
    port: u16,
    username: String,
    password: Option<String>,
    router_id: IpAddr,
    local_as: u32,
    status: ConnectionStatus,
}
```

### Cisco IOS / IOS-XE

**SSH pattern:** Direct command execution. `ssh_run(cmd)` runs the command directly; `ssh_run_or_vtysh(cmd, marker)` tries direct first, falls back to `vtysh -c '<cmd>'` if the output lacks the expected marker.

**Refresh flow:**
```
show ip bgp summary  (with vtysh fallback)
    → parse_bgp_summary()
    → parallel: show ip bgp neighbors <ip>  ×N   (futures::join_all)
        → parse_neighbor_detail() × N
    → merge neighbor details into summary
```

**Config rendering:** `render_bgp_stanza(summary)` generates a Cisco-style `router bgp` config block from the parsed summary.

**Parsers exposed as `pub(crate)`:** `parse_neighbor_detail`, `parse_bgp_table`, `parse_route_map_entries`, `parse_prefix_list_entries`, `parse_community_list_entries`.

### VyOS / FRRouting

**SSH pattern:** Two-layer: `raw_ssh_run(shell_cmd)` for arbitrary shell commands, `vtysh_run(frr_cmd)` wraps in `vtysh -c '<escaped>'`. Supports `sshpass` for password auth.

**Refresh flow:** Tries multiple FRR summary commands in order (`show ip bgp summary` → `show bgp ipv4 unicast summary` → `show bgp summary`), with raw SSH fallback. Same parallel neighbor detail fetch. Reuses all Cisco parsers.

### Citrix NetScaler / VPX

**SSH pattern:** Interactive pipe — NetScaler SSH drops you into the NetScaler CLI, not a Unix shell. Commands are piped interactively:

```bash
# For shell commands:
{ printf 'shell\n'; sleep 1; printf '<cmd>\nexit\nexit\n'; } | ssh ...

# For vtysh commands:
{ printf 'vtysh\n'; sleep 1; printf '<cmd>\nexit\nexit\n'; } | ssh ...
```

**Output cleaning:** `strip_citrix_noise()` removes SSH banners, `WARNING: `, `Disconnect IMMEDIATELY`, NetScaler `> ` prompts, shell prompts, piped echo, vtysh banners.

### pfSense

**SSH pattern:** pfSense SSH presents a numbered menu. Shell access is option 8:

```bash
# Piped to stdin:
"8\n{cmd}\nexit\n"
```

Uses `-T` (no PTY) and writes to child stdin via `AsyncWriteExt`.

**Output cleaning:** `strip_menu_noise()` removes pfSense banner art (`***`), menu items (digit + `)`), `Enter an option:` prompts, WAN/LAN/OPT lines, shell prompts.

### A10 Networks ADC

**SSH pattern:** Direct command execution via `run_cmd()` for show commands (Cisco-like CLI). Config writes use `run_piped()` with `configure` / `end` / `write memory` framing.

**Refresh flow:** `show ip bgp summary` → `parse_bgp_summary()`, then `show ip bgp neighbors` → `parse_all_neighbor_details()`. Reuses all Cisco parsers — ACOS BGP output follows Cisco IOS conventions.

**Output cleaning:** `strip_a10_noise()` removes ACOS prompt lines and login banners.

### Mock

`MockBackend::for_router(cfg)` generates realistic test data based on router name patterns (`ATL-Core-01`, `NYC-Core-01`, `Edge-01`). Includes multi-peer setups with iBGP/eBGP, various states, route-maps, communities.

---

## BGP Parsing Pipeline

All backends ultimately produce the same types by reusing a shared parser chain:

```
Raw SSH output (text)
    │
    ├─ parse_bgp_summary(output)
    │       Regex: extracts router-id + local-AS from header
    │       Delegates to parse_cisco_bgp_summary()
    │           Regex per row: Neighbor, V, AS, MsgRcvd, MsgSent,
    │                          TblVer, InQ, OutQ, Up/Down, State/PfxRcd
    │       → BgpSummary
    │
    ├─ parse_neighbor_detail(output)
    │       Extracts: description, route-maps, next-hop-self,
    │       RR-client, update-source, password, hold/keepalive
    │       → NeighborDetail  (merged into BgpPeer fields)
    │
    ├─ parse_bgp_table(output)
    │       Parses `show ip bgp` output line by line
    │       Handles continuation lines (network on separate line)
    │       parse_status_flags() + looks_like_prefix()
    │       → Vec<BgpRoute>
    │
    └─ Route-map pipeline:
        ├─ parse_route_map_entries(output)  → Vec<RouteMapEntry>
        ├─ parse_prefix_list_entries(output) → Vec<PrefixListEntry>
        └─ parse_community_list_entries(output) → Vec<String>
```

---

## Data Refresh Cycle

```
                    200ms tick
                        │
            ┌───────────▼───────────┐
            │     app.tick()        │
            │                       │
            │  ping_tick++ (mod 25) │──── every 5s ───→ spawn_ping()
            │                       │                      │
            │  bgp_tick++ (mod 150) │── every 30s ──→ spawn_bgp_fetch_all_connected()
            └───────────────────────┘                      │
                                                           ▼
                                              ┌─────────────────────────┐
                                              │  Per-router tokio tasks │
                                              │  backend.refresh()      │
                                              │  backend.get_routes()   │
                                              └──────────┬──────────────┘
                                                         │
                                              AppEvent::BgpData / RouteData
                                                         │
                                              ┌──────────▼──────────────┐
                                              │  handle_bgp_data()      │
                                              │  - content_eq() check   │
                                              │  - cache update         │
                                              │  - defer if Config tab  │
                                              └─────────────────────────┘
```

**Ping:** TCP connect to `host:port` with 2s timeout. On state transition (offline→online), triggers immediate BGP fetch. Transitions are logged to `conn_logs`.

**BGP refresh:** Runs `refresh()` then `get_routes()` on the vendor backend. Results are sent as separate `BgpData` and `RouteData` events.

---

## Change Detection & Deferred Updates

When the user is on the Config tab examining route-maps, a background refresh arriving mid-inspection would reset their scroll position and lose context.

**Solution:**

1. `BgpSummary::content_eq(other)` compares all fields **except** `fetched_at`.
2. If content hasn't changed, the update is silently dropped.
3. If content changed **and** the user is on the Config tab, the update is stored in `pending_bgp_update` / `pending_route_update` and a yellow notification banner appears.
4. User presses `y` to accept or `n` to dismiss.
5. Switching away from the Config tab auto-applies any pending update.

---

## Route-Map Detail & Caching

When the user navigates to a `route-map` line in the Config tab:

```
on_config_nav()
    │
    ├─ Extract route-map name from line
    │
    ├─ Check cache: routemap_cache[(router_id, rm_name)]
    │       Hit  → display instantly, no SSH
    │       Miss → show loading panel, spawn_routemap_fetch()
    │
    └─ spawn_routemap_fetch(rm_name)
            │ (vendor dispatch)
            ├─ show route-map <name>           → parse_route_map_entries
            ├─ Extract referenced prefix-list / community-list names
            ├─ Parallel fetch (futures::join_all):
            │   ├─ show ip prefix-list <name>  → parse_prefix_list_entries
            │   └─ show ip community-list <name> → parse_community_list_entries
            └─ Send RouteMapDetail event
                    │
                    └─ handle_routemap_detail()
                            ├─ Cache in routemap_cache
                            └─ Display in right panel
```

**Cache invalidation:** When `apply_bgp_update()` runs (new BGP data from a router), the entire cache for that router is cleared.

**Scrolling:** The detail panel supports `PageUp`/`PageDown` (±10 lines). Scroll resets to 0 when navigating to a different route-map.

---

## Credential Storage

```
Passphrase (user input, never stored)
    │
    ├─ Argon2id(passphrase, salt) → 256-bit key
    │       salt: random 16 bytes, stored base64 in kv table
    │
    └─ AES-256-GCM per password field:
            encrypt: random 12-byte nonce ∥ ciphertext → base64
            decrypt: split nonce ∥ ciphertext, decrypt → plaintext
```

### Database Schema

```sql
kv(key TEXT PRIMARY KEY, value TEXT NOT NULL)
    -- stores: argon2_salt

routers(
    id TEXT PRIMARY KEY,
    name TEXT, hostname TEXT, vendor TEXT,
    ssh_port INTEGER, username TEXT,
    password_enc TEXT,          -- AES-256-GCM encrypted, base64
    local_as INTEGER, router_id TEXT
)

projects(id TEXT PRIMARY KEY, name TEXT NOT NULL)

project_routers(
    project_id TEXT, router_id TEXT,
    PRIMARY KEY(project_id, router_id)
)
```

**Location:**
- macOS: `~/Library/Application Support/bgp-link-manager/routers.db`
- Linux: `~/.local/share/bgp-link-manager/routers.db`

---

## Project System

Projects group routers into named sets. The active project filters which routers appear in the Dashboard.

| Operation | Key | Description |
|-----------|-----|-------------|
| Open popup | `p` | Opens centered overlay |
| Switch project | `Enter` | Activates selected project filter |
| Show all | `0` | Clears project filter |
| Add project | `a` | Creates new project, enters name editor |
| Delete project | `d` | Removes selected project |
| Edit membership | `e` | Enters toggle-routers mode with checkbox list |
| Toggle router | `Space` | Adds/removes router from project (in toggle mode) |

Data flow: `projects` + `project_routers` tables → `Vec<Project>` → `active_project: Option<Uuid>` → `apply_project_filter()` → `routers` (filtered view).

---

## UI Architecture

### Layout & Color Palette

Top-level layout:

```
┌─────────────────────────────────────┐
│  Title bar (3 rows)                 │
├─────────────────────────────────────┤
│  Tab bar (3 rows)   1│2│3│4│5│6│7  │
├─────────────────────────────────────┤
│                                     │
│  Content area (flex)                │
│  (dispatched per active tab)        │
│                                     │
├─────────────────────────────────────┤
│  Help / status bar (3 rows)         │
└─────────────────────────────────────┘
```

**Color constants** (defined in `ui/mod.rs`):

| Constant | Color | Usage |
|----------|-------|-------|
| `C_TITLE` | Cyan | Title bar |
| `C_SELECTED` | Yellow | Active selection |
| `C_BORDER` | DarkGray | Widget borders |
| `C_HEADER` | Cyan | Column headers |
| `C_ESTABLISHED` | Green | Established state, permit actions |
| `C_WARN` | Yellow | Route-map lines, warnings |
| `C_ERROR` | Red | Errors, deny actions |
| `C_IBGP` | LightBlue | iBGP sessions |
| `C_EBGP` | Magenta | eBGP sessions |
| `C_STATUS_OK` | Green | Online status |
| `C_DIM` | DarkGray | Disabled/secondary text |

**Shared helpers:**
- `state_style(BgpState)` — green for Established, yellow for transitional, red for Idle, gray for Unknown.
- `fmt_num(u64)` — thousands-separated number formatting.

### Tab 1 — Dashboard

Two-column split: router list (30 cols) | summary + peer sparkline.

- **Router list:** Status dots — `●` green (connected), `●` red (error), `○` (connecting), `◌` (disconnected), `✕` (error with message).
- **Summary:** Router ID, Local AS, Hostname, Vendor, Table Version, Peer counts, Prefix totals, Fetch timestamp.
- **Peer sparkline:** Per-peer row with IP, type (iBGP/eBGP color-coded), state, prefix count. Bottom bar shows established/total ratio as ASCII bar graph (`▓░`).

### Tab 2 — Peers

Two-row split: peer table (top) | peer detail (7 rows, bottom).

**Table columns:** Neighbor, Remote AS, Type, State, Uptime, Pfx/Rx, Pfx/Tx, RM-In, RM-Out, Description.

**Detail pane:** All peer attributes in two-column key-value layout (session type, timer values, auth, route-reflector-client, update-source, communities).

### Tab 3 — Routes

Two-row split: route table (top) | route detail (bottom).

**Table columns:** Status icon, Network, Next-Hop, Local Pref, MED, Weight, AS Path, Origin, Communities. Color-coded by status (best = green, valid = yellow) and origin.

### Tab 4 — Config

Two-column split (58% | 42%): navigable config list (left) | dynamic right panel.

**Left panel:** Syntax-highlighted BGP config stanza. Keywords are color-coded: `router bgp` = cyan, `route-map` = yellow bold, `remote-as` = light blue, `password` = red, etc.

**Right panel** shows one of:
1. **Route-map detail** — when a route-map line is selected and detail is loaded. Shows sequence entries with permit/deny, match clauses (with inline-expanded prefix-lists and community-lists), set clauses. Scrollable with PageUp/PageDown.
2. **Loading** — "Fetching route-map '…'…"
3. **CLI cheatsheet** — 20+ common BGP commands with descriptions (default view).

**Pending update banner** — yellow bar at bottom when background data arrived while user is inspecting.

### Tab 5 — Logs

Scrollable list of timestamped log entries. Color-coded: red for errors, yellow for warnings, green for refresh/started events, gray for others.

### Tab 6 — Router Editor

Three-area layout: router list (30 cols) | edit form | help bar.

**Edit form:** 6 fields: Name, Hostname, Port, Username, Password (masked with `●`), Vendor (Space to cycle). Active field shows `▶` prefix with cursor `▌`.

### Tab 7 — Connectivity Log

Two-row split: scrollable event log (top) | current status panel (bottom).

**Event log:** Timestamped ONLINE (green) / OFFLINE (red) / added (cyan) / removed (yellow) entries.

**Status panel:** All routers with current status dot + hostname + label.

### Project Popup

Centered overlay (60% × 70% of terminal). Two modes:

1. **Browse** — project list with active marker `▶`, router count, help bar.
2. **Toggle routers** — checkbox list `[✓]` / `[ ]` for all routers.

---

## Dependency Summary

| Crate | Version | Purpose |
|-------|---------|---------|
| `ratatui` | 0.29 | TUI framework |
| `crossterm` | 0.28 | Terminal I/O, async key events (`event-stream`) |
| `tokio` | 1 (full) | Async runtime, process, time, sync |
| `serde` | 1 (derive) | Serialization for config types |
| `toml` | 0.8 | TOML parsing |
| `anyhow` | 1 | Error handling with context |
| `chrono` | 0.4 (serde) | Timestamps with serde support |
| `uuid` | 1 (v4, serde) | Unique router/project IDs |
| `regex` | 1 | BGP output parsing |
| `dirs` | 5 | Platform-specific data directories |
| `futures` | 0.3 | `join_all` for parallel SSH fetches |
| `rusqlite` | 0.31 (bundled) | SQLite with bundled libsqlite3 |
| `aes-gcm` | 0.10 | AES-256-GCM password encryption |
| `argon2` | 0.5 | Argon2id key derivation |
| `rand` | 0.8 | Random nonce/salt generation |
| `base64` | 0.22 | Base64 encoding for encrypted blobs |

---

## Adding a New Vendor Backend

1. **Create** `src/router/<vendor>.rs` with a backend struct implementing:

   ```rust
   pub async fn connect(&mut self)    -> Result<()>
   pub async fn disconnect(&mut self) -> Result<()>
   pub async fn refresh(&mut self)    -> Result<BgpSummary>
   pub async fn get_routes(&mut self) -> Result<Vec<BgpRoute>>
   pub async fn fetch_route_map_detail(&self, name: &str) -> Result<RouteMapDetail>
   pub async fn apply_config(&mut self, config: &str) -> Result<()>
   ```

2. **Register** in `src/router/mod.rs`:
   - Add `pub mod <vendor>;`
   - Add `RouterBackend::<Vendor>(<Vendor>Backend)` variant
   - Add dispatch arms in every `RouterBackend` method
   - Add `RouterVendor::<Vendor>` variant with `Display` impl

3. **Wire up** in `src/app.rs`:
   - `spawn_bgp_fetch_for()` — add vendor match arm
   - `spawn_routemap_fetch()` — add vendor match arm

4. **Database** in `src/db.rs`:
   - Handle `"<vendor>"` string in `load_all()` deserialization

5. **Editor** in `src/app.rs`:
   - Add to the `Space` cycle in vendor field handling (`editor_field == 5`)
   - Handle in `apply_buf_to_draft()`

**Reuse the Cisco parsers** (`parse_neighbor_detail`, `parse_bgp_table`, `parse_route_map_entries`, etc.) — they work for any Cisco/FRR-style output.
