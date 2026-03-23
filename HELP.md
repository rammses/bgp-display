# bgp-link-manager — User Guide

A window-by-window walkthrough of every tab, popup, and editor in the application.

Press **`?`** at any time to see a context-sensitive shortcut overlay.

---

## Table of contents

1. [First launch](#first-launch)
2. [Tab 1 — Dashboard](#tab-1--dashboard)
3. [Tab 2 — Peers](#tab-2--peers)
4. [Tab 3 — Routes](#tab-3--routes)
5. [Tab 4 — Config](#tab-4--config)
6. [Tab 5 — BGP Log](#tab-5--bgp-log)
7. [Tab 6 — Routers](#tab-6--routers)
8. [Tab 7 — SSH Log](#tab-7--ssh-log)
9. [Project popup](#project-popup)
10. [Neighbor wizard](#neighbor-wizard)
11. [Route-map editor](#route-map-editor)
12. [Prefix-list editor](#prefix-list-editor)
13. [Community-list editor](#community-list-editor)
14. [Config history](#config-history)
15. [Global shortcuts](#global-shortcuts)

---

## First launch

```bash
bgp-link-manager
```

You are prompted for an **encryption passphrase**. This passphrase derives the AES-256-GCM key that protects your router credentials on disk. It is never stored — you enter it each time.

The credential database is located at:

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/bgp-link-manager/routers.db` |
| Linux | `~/.local/share/bgp-link-manager/routers.db` |

To start fresh, rename or delete `routers.db` and relaunch.

After unlocking, press **`6`** to open the Routers tab and add your first router.

---

## Tab 1 — Dashboard

The main overview screen. It is split into two panels.

### Left panel — Router list

Each row shows:

| Glyph | Meaning |
|-------|---------|
| `●` green | Connected |
| `◌` yellow | Connecting |
| `✕` red | Error |
| `○` dim | Unknown / Offline |

Followed by the router **name**.

Navigate with **↑ / ↓** or **j / k** to select a router. The right panel updates immediately from the local cache (no SSH call).

### Right panel — BGP Summary

Displays for the selected router:

- **Router ID** and **Local AS**
- **Hostname** and **Vendor**
- **Table Version**
- **Total Peers** and **Established** count (with colour-coded ratio)
- **Total Prefixes** received
- **Last Fetched** timestamp

Below the summary is a **Peer States** bar showing each peer with its IP, session type (iBGP / eBGP), state, and prefix count. A horizontal bar at the bottom visualises the established / total ratio.

### Dashboard shortcuts

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Select router |
| `r` / `F5` | Refresh selected router |
| `n` | Create new BGP neighbor (opens wizard) |
| `p` | Open project popup |

---

## Tab 2 — Peers

The neighbor table for the currently selected router.

### Peer table columns

| Column | Description |
|--------|-------------|
| Neighbor | Peer IP address |
| Remote AS | Remote autonomous system number |
| Type | iBGP or eBGP (colour-coded) |
| State | BGP session state (Established = green, Active = yellow, etc.) |
| Uptime | How long the session has been up |
| Pfx/Rx | Prefixes received |
| Pfx/Tx | Prefixes sent |
| RM-In | Inbound route-map name |
| RM-Out | Outbound route-map name |
| Description | Neighbor description |

### Detail pane

When a peer is selected, a detail pane appears showing:

- Neighbor IP and session type
- State and uptime
- Messages received / sent
- Hold time, keepalive interval, authentication (yes/no)
- Next-hop-self, route-reflector client
- Inbound and outbound route-maps
- Update source and communities
- Reset count and last reset reason
- BFD status and MTU probe result
- State history (last 5 transitions with timestamps)

### Per-peer routes

Press **Enter** on a peer to drill down into its received routes. In that view:

| Key | Action |
|-----|--------|
| `i` | Show received (inbound) routes |
| `o` | Show advertised (outbound) routes |
| `Tab` | Toggle between received / advertised |
| `r` / `F5` | Refresh routes |
| `↑` / `↓` or `j` / `k` | Navigate routes |
| `Esc` | Return to peer table |

### Peers shortcuts

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Select peer |
| `Enter` | Drill into peer routes |
| `n` | Create new neighbor (wizard) |
| `e` | Edit selected neighbor (wizard) |
| `c` | Clone selected neighbor |
| `x` | Delete selected neighbor (with confirmation) |
| `s` | Toggle shutdown / no-shutdown |
| `m` | Run MTU probe on selected peer |
| `/` | Filter peers by keyword |
| `Esc` | Clear filter |

---

## Tab 3 — Routes

The full BGP RIB for the selected router.

### Route table columns

| Column | Description |
|--------|-------------|
| St | Route status indicator |
| Network | Destination prefix |
| Next-Hop | Next hop address |
| LP | Local preference |
| MED | Multi-exit discriminator |
| Wt | Weight |
| AS Path | AS path |
| Org | Origin (IGP / EGP / Incomplete) |
| Communities | BGP communities |

### Detail pane

Selecting a route shows:

- Network, next-hop, and origin
- Local preference, MED, and weight
- Full AS path and community strings

### Routes shortcuts

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Select route |
| `r` / `F5` | Refresh routes |
| `/` | Filter routes by keyword |
| `Esc` | Clear filter |

---

## Tab 4 — Config

A syntax-highlighted view of the live BGP configuration for the selected router, with inline route-map expansion.

### Left panel — Config lines

The running BGP configuration is displayed as a scrollable list. Lines are syntax-highlighted:

- `router bgp …` — cyan bold
- Lines containing `route-map` — yellow bold
- `remote-as`, `description`, `next-hop-self`, `update-source`, `password` — individual colours
- Section separators (`!`) — dim

### Right panel — Route-map detail

When you navigate to a line containing a `route-map` reference, the right panel automatically loads and expands that route-map inline:

- Route-map name
- Each **seq** entry with its action (permit / deny)
- **match** clauses — prefix-list references are expanded to show each permit/deny entry; community-list references expand similarly
- **set** clauses

Scroll the detail pane with **PageUp** / **PageDown**.

If no route-map is selected, the right panel shows a Cisco CLI reference cheat-sheet.

### Pending update banner

If new BGP data arrives while you are on the Config tab, a banner appears: _"BGP data updated — press y to apply, n to dismiss."_ This prevents the config view from shifting while you are reading it.

### Config shortcuts

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Navigate config lines |
| `e` | Edit the route-map, prefix-list, or community-list on the current line |
| `P` | Create a new prefix-list (opens editor) |
| `C` | Create a new community-list (opens editor) |
| `h` | Open config history popup |
| `PageUp` / `PageDown` | Scroll route-map detail pane |
| `/` | Filter config lines |
| `y` | Apply pending BGP update |
| `n` | Dismiss pending update |
| `Esc` | Clear filter |

---

## Tab 5 — BGP Log

A scrollable, colour-coded event log of application activity.

- **Red** — errors
- **Yellow** — warnings
- **Green** — refreshes and start events
- **Dim** — informational

The log is kept in memory (capped at 500 entries). The title shows the total count, or filtered matches when a filter is active.

### BGP Log shortcuts

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Scroll log |
| `/` | Filter log entries |
| `Esc` | Clear filter |

---

## Tab 6 — Routers

Add, edit, and delete routers. Changes persist immediately to the encrypted database.

### Editor fields

| # | Field | Notes |
|---|-------|-------|
| 1 | Name | Display name for the router |
| 2 | Hostname | IP address or DNS name |
| 3 | Port | SSH port (default 22) |
| 4 | Username | SSH username |
| 5 | Password | SSH password (stored encrypted) |
| 6 | Vendor | Press **Space** to cycle (see below) |
| 7 | VDOM | Virtual domain name (FortiGate only) |

### Vendor cycle (Space key on field 6)

Cisco → VyOs → CitrixVpx → PfSense → FortiGate → Cisco

### Routers shortcuts

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Select router |
| `Enter` | Edit selected router |
| `a` | Add new router |
| `d` | Delete selected router |

### While editing

| Key | Action |
|-----|--------|
| `Tab` / `Enter` | Next field |
| `Shift-Tab` | Previous field |
| `Space` | Cycle vendor (on Vendor field) |
| `Esc` | Cancel editing |

---

## Tab 7 — SSH Log

Connectivity event history and real-time ping monitor for all routers.

### Upper panel — Connectivity events

A timestamped log of TCP reachability changes:

- **ONLINE** — green
- **OFFLINE** — red
- Router added / updated / removed events

Probes run every 5 seconds automatically.

### Lower panel — Ping Monitor

For each router in the active project, a row displays:

| Element | Description |
|---------|-------------|
| Status dot | Green (online), red (error), yellow (connecting), dim (offline) |
| Name | Router name |
| Hostname | Router hostname |
| Status label | Online / Connecting / Error / Offline |
| RTT | Current round-trip time, colour-coded: green (< 50 ms), yellow (50–200 ms), red (> 200 ms), or `timeout` / `---` |
| Loss | Packet loss percentage |
| Sparkline | Visual RTT history using `▁▂▃▄▅▆▇█` block characters; failures shown as `_` |
| Min / Avg / Max | Summary statistics when data is available |

### SSH Log shortcuts

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Scroll events |
| `/` | Filter events |
| `Esc` | Clear filter |

---

## Project popup

Press **`p`** from any tab to open the project popup.

Projects let you group routers so only a subset is monitored at a time.

### Project list

- **All Routers** — shows every router (always available)
- Named projects with their router counts

### Project popup shortcuts

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Select project |
| `Enter` | Switch to selected project |
| `0` | Switch to All Routers |
| `a` | Add new project (prompts for name) |
| `e` | Edit routers in selected project (toggle screen) |
| `d` | Delete selected project |
| `Esc` / `p` | Close popup |

### Toggle routers screen

When editing a project's routers:

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate router list |
| `Space` | Toggle router in/out of project (`[✓]` / `[ ]`) |
| `Enter` / `Esc` | Done — return to project list |

---

## Neighbor wizard

The neighbor wizard guides you through creating, editing, or deleting a BGP neighbor. Open it with **`n`** (create), **`e`** (edit), or **`x`** (delete) on the Peers or Dashboard tabs.

### Wizard fields

| Field | Description |
|-------|-------------|
| Neighbor IP | Peer IP address |
| Remote AS | Remote autonomous system number |
| Description | Free-text description |
| Update Source | Source interface or IP |
| Addr Family | Address family (e.g. ipv4 unicast) |
| Next-hop-self | Toggle with Space |
| RR Client | Route-reflector client — toggle with Space |
| Hold Time | BGP hold timer (seconds) |
| Keepalive | Keepalive interval (seconds) |
| Password | Authentication password |
| BFD | Bidirectional forwarding detection — toggle with Space |
| Soft-reconfig | Soft reconfiguration inbound — toggle with Space |
| Max-Prefix | Maximum prefix limit |
| Max-Pfx Warn | Warning threshold (percentage) |
| Weight | Route weight |
| Local-Pref | Local preference |

### Wizard steps

1. **Fields** — fill in values. Space toggles boolean fields. Tab / arrow keys move between fields.
2. **Review** — preview the generated CLI commands. Press Enter to apply, Esc to go back.
3. **Applying** — the commands are pushed to the router over SSH.
4. **Result** — success or error message.

### Wizard shortcuts

| Key | Action |
|-----|--------|
| `Tab` / `↓` | Next field |
| `Shift-Tab` / `↑` | Previous field |
| `Space` | Toggle boolean field |
| `Enter` | Confirm / proceed to next step |
| `Esc` | Cancel / go back |

---

## Route-map editor

Edit route-map entries for the selected router. Opens when you press **`e`** on a route-map line in the Config tab.

### Layout

A centered popup showing the route-map name and a list of sequence entries. Each entry displays:

- **Seq** number
- **Action** (permit / deny)
- **Match** clauses
- **Set** clauses

### Editor shortcuts (browsing entries)

| Key | Action |
|-----|--------|
| `↑` / `↓` | Select entry |
| `Enter` | Edit selected entry |
| `a` | Add new entry |
| `d` | Delete selected entry |
| `s` | Save and push to router |
| `Esc` | Cancel and close |

### Editor shortcuts (editing an entry)

| Key | Action |
|-----|--------|
| `Tab` | Next field |
| `Space` | Toggle permit / deny (on action field) |
| `Enter` | Done editing entry |
| `Esc` | Cancel edit |

After saving, the changes are pushed to the router via SSH and the review / apply flow runs.

---

## Prefix-list editor

Edit prefix-list entries. Opens when you press **`e`** on a prefix-list line in the Config tab, or **`P`** to create a new one.

### Layout

A centered popup showing the prefix-list name and a table of entries:

| Column | Description |
|--------|-------------|
| Seq | Sequence number |
| Action | permit / deny |
| Prefix | Network prefix (e.g. `10.0.0.0/8 le 24`) |

### Prefix-list editor shortcuts

Same pattern as the route-map editor:

| Key | Action |
|-----|--------|
| `↑` / `↓` | Select entry |
| `Enter` | Edit selected entry |
| `a` | Add new entry |
| `d` | Delete selected entry |
| `N` | Rename the prefix-list |
| `s` | Save and push to router |
| `Esc` | Cancel and close |

### While editing an entry

| Key | Action |
|-----|--------|
| `Tab` | Next field |
| `Space` | Toggle permit / deny |
| `Enter` | Done |
| `Esc` | Cancel |

---

## Community-list editor

Edit community-list entries. Opens when you press **`e`** on a community-list line in the Config tab, or **`C`** to create a new one.

### Layout

Same as the prefix-list editor, with columns:

| Column | Description |
|--------|-------------|
| Seq | Sequence number |
| Action | permit / deny |
| Community | Community value (e.g. `65000:100`) |

### Shortcuts

Identical to the [prefix-list editor](#prefix-list-editor) shortcuts.

---

## Config history

Press **`h`** on the Config tab to open the config history popup. This shows a list of previously fetched configurations with timestamps.

### Config history shortcuts

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Select entry |
| `u` | Rollback to selected configuration |
| `Esc` / `h` | Close popup |

---

## Global shortcuts

These work from any tab (unless an editor or popup is open).

| Key | Action |
|-----|--------|
| `q` / `Q` / `Ctrl-C` | Quit |
| `Tab` | Next tab |
| `Shift-Tab` | Previous tab |
| `1` – `7` | Jump directly to tab |
| `↑` / `↓` or `j` / `k` | Navigate the active list |
| `r` / `F5` | Refresh selected router |
| `p` | Open project popup |
| `?` | Toggle keyboard shortcut overlay |
| `/` | Open filter (Peers, Routes, Config, BGP Log, SSH Log) |

---

## Diagnostics

Application logs are written to a daily-rotating file:

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/bgp-link-manager/logs/` |
| Linux | `~/.local/share/bgp-link-manager/logs/` |

Control verbosity with `BGP_LM_LOG`:

```bash
bgp-link-manager                    # default (info)
BGP_LM_LOG=debug bgp-link-manager   # SSH commands, fetch requests, event routing
BGP_LM_LOG=trace bgp-link-manager   # per-frame draw timing, per-event timing
```

Built-in lag detection warns when:

| Metric | Threshold |
|--------|-----------|
| UI draw time | > 16 ms |
| Event handler time | > 5 ms |
| SSH command time | > 10 s |
| Data fetch time | > 15 s |

Watch logs in real time:

```bash
tail -f ~/Library/Application\ Support/bgp-link-manager/logs/*.log   # macOS
tail -f ~/.local/share/bgp-link-manager/logs/*.log                     # Linux
```
