# bgp-link-manager — Agent Instructions

Rust TUI application for managing BGP sessions across Cisco, VyOS, Citrix VPX, pfSense, FortiGate, and A10 Networks ADC routers. Built with ratatui, crossterm, tokio, and rusqlite (AES-256-GCM encrypted).

## Specialized Agents


| Agent               | When to Use                                                 |
| ------------------- | ----------------------------------------------------------- |
| rust-reviewer       | After writing or modifying any `.rs` file                   |
| rust-build-resolver | When `cargo build` or `cargo check` fails                   |
| code-reviewer       | General code quality review                                 |
| security-reviewer   | Before commits touching crypto, SSH, or credential handling |
| planner             | Complex features spanning multiple modules                  |
| tdd-guide           | New features or bug fixes — write tests first               |


## Project Conventions

- **Error handling**: `anyhow::Result` with `.context()` throughout. Never `unwrap()` in production paths.
- **Async**: tokio runtime (full features). Background SSH tasks communicate via `UnboundedSender<AppEvent>`.
- **SSH**: System OpenSSH binary with ControlMaster mux. No embedded SSH library. Centralized `SshSessionManager` (`src/ssh.rs`) pre-warms connections at startup, provides `run_cmd()` / `run_piped()` / `run_shell_pipe()` — backends delegate all SSH transport to it.
- **Logging**: `tracing` crate with file-based appender (`src/logging.rs`). Lag detection thresholds for UI draw (16 ms), event handling (5 ms), SSH commands (10 s), fetches (15 s). Controlled via `BGP_LM_LOG` env var. SSH errors go to file log only; UI gets truncated summaries.
- **Vendor backends**: `RouterBackend` enum dispatch (not trait objects). All backends share Cisco parsers for FRR-compatible output.
- **UI decoupling**: App must never block on SSH. Tab/router switching reads from cache only. All SSH-triggered fetches go through a background `DataFetchService` (`src/fetch.rs`) that communicates via `AppEvent`.
- **State**: Single `App` struct owns all state. Single-threaded mutation in the event loop; background tasks are read-only and send events back.
- **Database**: rusqlite with bundled SQLite. Passwords encrypted with AES-256-GCM, key derived via Argon2id from user passphrase.
- **UI**: 7-tab ratatui layout. Color constants in `ui/mod.rs`. Deferred update pattern on Config tab.

## Before Any Commit

- `cargo check` passes
- `cargo clippy -- -D warnings` clean
- `cargo fmt --check` clean
- `cargo test` passes
- No hardcoded secrets (check password/key handling in `db.rs` and `router/`)

## Key Files to Know

- `src/app.rs` (~1900 lines) — central state machine, largest file. Key methods: `tick()`, `handle_bgp_data()`, `handle_bgp_error()`, `on_config_nav()`, `handle_ssh_warm_complete()`.
- `src/logging.rs` — file-based tracing init, lag-detection thresholds.
- `src/ssh.rs` — `SshSessionManager` — centralized SSH connection pool with warm-up, health checks, mux retry.
- `src/fetch.rs` — `DataFetchService` — background worker processing `FetchRequest` messages via `SshSessionManager`.
- `src/bgp/mod.rs` — all BGP types and parsers shared across vendor backends.
- `src/router/mod.rs` — RouterConfig, vendor dispatch, SSH mux constants.
- `src/router/fortigate.rs` — FortiGateBackend with piped stdin and VDOM support.
- `src/router/a10.rs` — A10Backend with direct shell commands and piped config mode.
- `src/db.rs` — encrypted SQLite persistence layer.
- `.cursor/rules/bgp-link-manager-context.md` — compact architecture summary (read this first).

## Adding a New Vendor Backend

1. Create `src/router/<vendor>.rs` (connect, disconnect, refresh, get_routes, fetch_route_map_detail)
2. Register in `router/mod.rs`: module, RouterBackend variant, dispatch arms, RouterVendor variant
3. Wire in `app.rs`: spawn_bgp_fetch_for() + spawn_routemap_fetch()
4. Handle in `db.rs`: load_all() deserialization
5. Handle in editor: Space cycle (editor_field == 5) + apply_buf_to_draft()
