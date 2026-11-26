# bgp-link-manager — User Guide

A window-by-window walkthrough of every tab, popup, and editor in the application.

Outside an editor or popup, press **`?`** to see a context-sensitive shortcut overlay.

Vendor-specific limits matter: the legacy wizard/policy/MTU/rollback descriptions below do **not** apply to MikroTik. Use the [native RouterOS workflow](#mikrotik-routeros-7247-native-workflow) for its delivered controls and pending device-validation status.

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
16. [MikroTik RouterOS 7.24.7 native workflow](#mikrotik-routeros-7247-native-workflow)
17. [Deferred RouterOS lab checklist — all pending](#deferred-routeros-lab-checklist--all-pending)

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

For MikroTik, configured disabled/never-connected connections remain visible; administrative state is separate from observed runtime state. Unknown observations display `N/A`, not invented zeros; missing BFD telemetry is not measured Down/Up. IP is presentation, not native connection identity. The native section below replaces the legacy actions and route semantics.

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

**MikroTik exception:** native instance/connection/chain/rule summaries and source metadata replace Cisco pseudo-config and route-map expansion. `e` opens the metadata-backed native connection or filter editor; `P`/`C` and generic policy/list editing are unavailable. Deferred updates retain displayed text and its original metadata together until accepted.

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
| 8 | BGP Instance | MikroTik only; explicit existing main-table instance name; blank = discovery-only (not VDOM) |

### Vendor cycle (Space key on field 6)

Cisco → VyOs → Cumulus → CitrixVpx → PfSense → FortiGate → A10 → MikroTik → Cisco

The optional JSON import/export field is `mikrotik_instance`. Existing router entries without it remain discovery-only for MikroTik. A missing, renamed, disabled/unusable or non-main selected instance is an error, never permission to switch to another instance. Refresh, inspect candidates, and explicitly update the setting.

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

For MikroTik those entry points open a separate native editor; do not apply the legacy fields/generated-CLI steps below. See [native neighbor management](#native-neighbor-management).

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

**MikroTik:** history contains redacted, origin-correlated **operation receipts after results**, not executable configurations or inverse commands. Entries are encrypted and **non-replayable**, including after restart, forged rollback content or a later router-vendor change. `u` cannot replay a native receipt. Corrective changes require a fresh snapshot, new preview and explicit confirmation. Legacy entries retain their existing replay behavior.

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

## MikroTik RouterOS 7.24.7 native workflow

```text
MikroTik RouterOS 7.24.7: implemented and automated-tested,
pending RouterOS 7.24.7 device validation.
Scope: selected main-table instance, fixed-host neighbor management,
native filter-rule editing; no automatic transactional rollback.
```

The automated evidence exercises documentation-derived synthetic native transcripts, domain checks, App events, encrypted history, and actual terminal rendering. It is **not a captured RouterOS session, live-device validation, or a production-ready guarantee**. No credentials/devices were supplied for this work; all lab items below remain pending.

### Release, model and scope prerequisites

- Use **exactly 7.24.7**, including an installed channel suffix such as `7.24.7 (long-term)`. Other releases are unsupported; there is no guessed `7.x` compatibility range.
- MikroTik's [7.24 Understanding BGP manual](https://manual.mikrotik.com/docs/7.24/user-guides/routing-and-networking-protocols/unicast/bgp/understanding-bgp) states BGP is **not supported on SMIPS** (hAP lite, hAP lite TC, hAP mini). This is a vendor-documented exclusion, not an app-tested model matrix. Applicability of other target models/architectures remains pending lab evidence.
- Configure SSH using the existing system OpenSSH key/password workflow. Obtain operator authorization and backups **before any lab write**. Use secure credential channels, not source files, screenshots, issue text or command diagnostics.
- In Routers (`6`), choose `MikroTik`. Leave **BGP Instance** blank to discover eligible main-table candidates, then enter an **explicit existing instance name**. The app does not auto-select the first result or create instances. Selected instance AS/router ID are observations, not guessed defaults.
- A main-table instance does **not** authorize every connection: direct routing-table/VRF settings and recursively inherited template scope must independently resolve to `main`. Non-main, contradictory, cyclic, ambiguous or unreadable inheritance is read-only. Those audit rows are excluded from selected-main peer totals/RIBs; do not rewrite their scope to make them editable.
- Connections are identified by instance + name, observed menu-local item ID and snapshot generation. Sessions have separate IDs/names. Duplicate remote IPs or a session-name suffix cannot authorize a write. Missing/ambiguous session associations remain read-only runtime observations.

### Monitoring, availability and budgets

The seven tabs remain unchanged. Tab/router navigation reads the cache only; native SSH runs in the background fetch service and events mutate App state on the foreground thread. Refresh/polling obtains a new native generation, not an automatic rebase of an open draft.

| Observation/control | Delivered behavior |
| --- | --- |
| Peers | Configured connections plus native session observations; disabled flag is independent of Established/unobserved state |
| Unknown telemetry | `N/A` or explicitly partial known totals; no assumed local/remote AS, router ID, table version, prefix/reset/notification counts, weight or origin |
| Routes / Enter or `i` | Selected effective-main **stored session-associated BGP routes**, including filtered records when exposed; not full pre-policy Adj-RIB-In |
| AS path/status | Original native AS-path text (sets/confederations included) and flags retained; filtered/unreachable is not relabeled Cisco valid/best |
| Advertised routes / `o` | **Unavailable**: native capability/completeness/session association unproven; empty output is not a verified zero |
| MTU / `m` | **Unavailable**; no native MTU probe |
| Optional RIB failure | Successful peer/config snapshot survives; last-good routes retained with a stale/unavailable reason rather than an empty success |
| Config | Native source summaries and chain/rule metadata; no Cisco pseudo-config, policy parser or text-derived authorization |

The app makes **no** monitoring changes to `output.keep-sent-attributes`, advertisement dumping, files/PCAP or probe state. There is no hidden advertisement-retention setup. The documented native advertisement menu alone does not prove the app can safely associate/decode it.

Client-side budgets are **30 seconds and 64 MiB per native read command**, using bounded collection and explicit timeout/overflow errors; **32 KiB per generated command payload** is checked for the entire plan before the first write and again for actual materialized commands. These are application limits, **not universal RouterOS limits**. Existing over-budget filter source is viewable/clipped with an indication, retained intact and read-only, never truncated on save. Internet-scale RIB performance and target-device command limits remain unknown.

### Native neighbor management

From Dashboard/Peers use `n` to create; from Peers use `e` to patch, `s` to review an explicit enable/disable intention, or `x` to delete. Config `e` on a connection's source row opens its native form. No raw CLI is submitted by these controls.

1. **Fields:** Tab / Shift-Tab or arrows select fields; Space cycles supported choices. A new neighbor needs a unique name, fixed remote IPv4/IPv6 host, explicit remote ASN, role and AFI. AFI `ip`, `ipv6` or both is independent of transport address family. Supported initial roles are `ebgp`, `ibgp`, `ibgp-rr`, validated against observed effective local AS (iBGP same AS, eBGP different AS). Other existing roles/configurations may be viewed but not converted by this editor.
2. **Review:** Enter builds a native typed preview of exact intended nonsecret changes, original endpoint/instance, authentication intention, bindings and impact. Nothing is sent yet. Inspect all pages (`PageUp` / `PageDown` / `Home`). A **second Enter** confirms once; BackTab returns to fields and clears the preview; Esc cancels.
3. **Applying:** background sequential guarded operations; extra Enter is ignored. Esc hides the editor but **does not cancel/revoke an already launched remote operation**. Its receipt still belongs to the original router/endpoint, not a newly opened editor.
4. **Result:** inspect `VERIFIED`, `UNCERTAIN` and `UNAPPLIED` steps; refresh and open a new preview for further changes. Late results/reads do not overwrite another editor's draft/status.

**Creation is disabled and deny-all.** The app allocates unique operation-owned input/output chain names independently of the comment, creates/verifies each enabled `reject;` rule, then creates/verifies a **disabled** connection with both bindings and explicit main table/VRF. Do not expect adjacency or traffic from successful creation. Inspect/edit the intended policies and then **separately review and confirm enable** (`s`). Enabling discloses current AS/AFI/bindings and warns about deny-all or unbound stages. Never infer shutdown direction from runtime establishment.

**Patch only explicit changes.** Name, instance, remote endpoint, routing table and VRF are immutable in the edit flow. Untouched native/inherited/unsupported attributes remain untouched; there is no reconstruct/re-add shortcut. Supported optional fields accept `~` to explicitly unset their override where validated, with the inherited effect reviewed; blank/untouched does not mean clear an unknown value.

| Field | Native meaning / limit |
| --- | --- |
| Comment | Connection `comment`, not chain ownership |
| Source | `local.address`, fixed-address editing only; interface/unnumbered/subnet/dynamic/unresolved targets are read-only |
| Timers | `hold-time`, `keepalive-time`, duration-aware (e.g. `3m`, `00:03:00`, `infinity` as supported); preserve unset/inherited values |
| Next-hop | `nexthop-choice`: default / force-self / propagate, not a Cisco boolean |
| BFD | `use-bfd` request only; no global BFD configuration or operational-Up claim |
| Input/output | Explicit `input.filter` / `output.filter-chain`; creation uses generated bindings; removing an edit binding can remove that filter stage and expose ACCEPT behavior |
| MD5 | **Keep / Replace / Clear**, as described below |
| Process-route limits | Read-only per-AFI native processing limits; not a Cisco warning-only maximum-prefix equivalent |
| Unavailable | Connection-form weight/direct local-pref, Cisco soft-reconfiguration/max-prefix/warning threshold; express appropriate native route attributes in filter rules instead |

**MD5 never inferred:** Keep is the default and does not read/rewrite the sensitive key. Choose Replace explicitly before entering a hidden replacement; choose Clear explicitly to disable configured authentication. Hidden/masked/omitted/inaccessible values are **not proof of empty or correct**. Replace/Clear need private on-device comparison with trustworthy access to the real sensitive property, returning only target identity + boolean. Without that proof the write remains **Indeterminate**, even if SSH exited successfully. This never proves authentication/session establishment works. Replacement values are cleared from draft state at dispatch/cancellation/result; previews/logs/errors/receipts must not expose them. Do not paste credentials into ordinary comments/rule text.

**Delete is connection-only.** Revalidate and confirm the exact connection/impact. Templates, filters and lists are deliberately retained, including generated chains. Failed/partial create can leave named orphan chains; inspect manually. No automatic cleanup or inverse-command restoration occurs.

### Native ordered filter editing

On Config (`4`), select a **native chain metadata row** and press `e`. The list shows exact native source IDs/order, rule text/comment, disabled/inactive flags and available diagnostics. It does not use Cisco sequence numbers or parse rendered labels to select targets.

| Context | Key | Action |
| --- | --- | --- |
| Ordered list | arrows / `j` / `k` | Select rule |
| Ordered list | `a` / `e` / `c` | Add rule / edit raw text / edit comment |
| Ordered list | `Space` | Request explicit rule state in local draft |
| Ordered list | `U` / `D` | Move selected rule up/down within chain order (compiled as native move-before/end) |
| Ordered list | `d` | Delete selected rule locally, subject to enabled-rule survival |
| Ordered list | `s` | Distinct shared-chain acknowledgment, **not** save/apply |
| Ordered list | Enter / `r` | Build Review; no device write |
| Raw text/comment | Enter | Insert newline, **not** Review/apply |
| Raw text/comment | arrows / Home / End | Move UTF-8 cursor |
| Raw text/comment | Ctrl-S | Save field **locally** and return to list; no device write |
| Raw text/comment | Esc | Cancel field, keep original local rule |
| Review | Enter | Second confirmation, apply once |
| Review | Esc / BackTab | Back to local list, clear preview |
| List/Review/raw | PageUp / PageDown | Scroll view; display clipping never changes source |
| Applying / Result | Esc / Enter | Esc hides Applying (does not revoke); Enter/Esc closes Result |

Review shows original before/after text, order/state and known direct BGP/template consumers. **“live changes; not atomic; shared consumers may be affected.”** Shared consumers within selected effective-main scope require explicit acknowledgment. A known foreign-instance/non-main/unresolved connection consumer, unresolved template consumers, known other-protocol reference or incomplete required inventory makes the chain read-only. Nested script references and other protocol consumers may still exist: **this is not a complete dependency audit**.

Changed raw text is quoted as a RouterOS **property value**, not evaluated as arbitrary CLI or translated to Cisco/AS-path syntax. Syntax validation is best-effort, **not a device dry-run**. Untouched source/metadata is preserved. Minimal per-rule steps insert new rules **disabled**, independently verify ID/position, then apply the requested enabled state only as the confirmed final rule step. Existing enabled-rule text/order/state/deletion changes can affect traffic immediately. The app conservatively rejects deleting/disabling the last enabled rule and never temporarily unbinds the chain, renames chains or garbage-collects definitions. Prefix/community/AS-path list definitions and templates are not edited here.

### Guards, outcomes and history

Confirmation binds original router entry, endpoint registration, instance, generation, guard and typed intention. The worker serializes operations locally by hostname/port/username (including duplicate entries), re-reads version/scope/configuration/references, and rejects stale preview **before the first mutation**. Each later destructive step revalidates against independently verified own progress; external divergence is not absorbed as approved progress. Counters/uptime do not create false staleness; configuration/template/binding/order changes do.

| Outcome | Operator meaning |
| --- | --- |
| `RejectedBeforeWrite` | No mutation launched; refresh/re-preview to resolve invalid/stale/unavailable context |
| `VerifiedApplied` | Approved step postconditions, exact identity/effective scope and required private MD5 proof verified; **not** proof of traffic or successful authentication |
| `PartialApplication` | Earlier verified steps remain; a later step was not applied/confirmed; inspect step list/orphans |
| `Indeterminate` | A launched step's result/postcondition is uncertain; inspect and reconcile, do not assume success or failure |

Execution stops on the first error/timeout/disconnect/stderr/invalid envelope or postcondition mismatch. Reads used for reconciliation do **not** replay writes. There is **no automatic mutation retry, replay, legacy command fallback, automatic rollback, isolated candidate config or Safe Mode/atomicity guarantee**. Observable optimistic guards are not atomic compare-and-swap: another administrator can race between reads and writes, and concealed secrets cannot be compared. Manual corrective actions/restoration need new authorization/snapshot/preview/confirmation.

Receipts are stored only after outcomes in App-owned encrypted history, with original endpoint/instance and safe step evidence, **no executable command/raw intention/secret payload and no fabricated rollback list**. They are non-replayable after restart or vendor changes. A history persistence error is reported; an in-memory receipt does not imply durable storage.

### Remaining device unknowns and official references

Actual 7.24.7 JSON keys/types, installed sensitive visibility/permissions, complete exec/error envelopes, inherited-value representation, complex connection/session joins, advertisement prerequisites/completeness, session-reset/filter propagation/traffic behavior, model applicability and scale/command limits remain unknown. Missing evidence produces unavailable/read-only/error outcomes, not guessed device facts. Versioned documentation can contain stale examples; modeled tests cannot establish wire compatibility. Incompatible device evidence requires a reviewed scope/design change, not silently widened support.

- [7.24 SSH / executing remote commands](https://manual.mikrotik.com/docs/7.24/management-tools/ssh#executing-remote-commands): native noninteractive **single physical line**; do not assume newer multiline SSH behavior.
- [7.24 Scripting](https://manual.mikrotik.com/docs/7.24/developer-guides/scripting/): `print as-value` plus serialization/envelopes and RouterOS escapes; as-value alone is not JSON.
- [Connection](https://manual.mikrotik.com/docs/7.24/cli-reference/routing/bgp/connection), [template](https://manual.mikrotik.com/docs/7.24/cli-reference/routing/bgp/template), [session](https://manual.mikrotik.com/docs/7.24/cli-reference/routing/bgp/session/), [routing route](https://manual.mikrotik.com/docs/7.24/cli-reference/routing/route): scope overrides, separate configuration/runtime and stored-route association.
- [Advertisements](https://manual.mikrotik.com/docs/7.24/cli-reference/routing/bgp/advertisements), [native filter rule](https://manual.mikrotik.com/docs/7.24/cli-reference/routing/filter/rule), [Route Selection and Filtering](https://manual.mikrotik.com/docs/7.24/user-guides/routing-and-networking-protocols/route-selection-and-filtering): native availability/order/semantics, not permission for retention or list mutations.

## Deferred RouterOS lab checklist — all pending

**PENDING ONLY — not run, not passed.** Devices are to be supplied later through a secure channel. No real-router read/write/traffic test was performed. For each later authorized lab run, retain evidence and mark results only after actual observation; never use an unspecified production router.

- [ ] **Prerequisites/identity:** record model, architecture (exclude SMIPS BGP), exact installed version + channel, packages, operator/account privileges (including sensitive-read visibility), instance/table/VRF topology, inheritance and test scale (connections/rules/routes/families). Record terminal/client/platform details where relevant.
- [ ] **Authorization/backups:** obtain explicit operator authorization for each write/traffic-impact test, secure credentials, a pre-change backup/export and an operator-controlled restoration procedure/access path. Avoid credentials/secret exports in shared artifacts. Do not weaken host-key/auth policy for a test.
- [ ] **Actual transport/wire:** validate native warm probe and BGP permissions, single-line exec, complete correlated JSON envelopes (empty/unknown/native types included), actual error/stderr/exit-status behavior, timeout/disconnect/over-budget handling and absence of automatic mutation retries/fallback. Compare actual types/keys against modeled fixtures.
- [ ] **Inventory/session joins:** observe established, configured disabled, disconnected and never-connected peers; multiple instances, duplicate IPs, session caches/IDs and direct/inherited effective-main versus non-main cases. Confirm unavailable/ambiguous evidence stays read-only, not mis-associated by IP/name suffix.
- [ ] **IPv4/IPv6 RIB:** verify native raw AS paths/flags, filtered/active records, table/instance/session joins and per-peer stored routes; record read sizes/timing/scale and stale-last-good behavior on optional failure. Do not claim full pre-policy Adj-RIB-In or Internet-scale performance from small tests.
- [ ] **Optional advertisements:** record whether the read-only menu, decoder/session association and completeness are actually available and any prerequisites; keep unsupported cases unavailable. Do **not** enable sent-attribute retention, invoke dump/PCAP or add probe mutations to make this pass.
- [ ] **Disabled deny-all create:** verify both newly named enabled reject chains, both attached bindings, explicit effective-main scope and disabled connection in real post-reads. Record collision/partial-create/orphan observations without automatic cleanup. Inspect intended policy first; **separately authorize, review and confirm enable** and observe actual adjacency/traffic.
- [ ] **Field patch/admin/delete:** verify comment, supported role/AFI, fixed source, native timers/next-hop/BFD request and binding patches preserve untouched/inherited/unknown fields. Exercise explicit MD5 Keep/Replace/Clear with privileged proof and inaccessible/masked proof failure. Separately confirm disable/enable from configured state. Delete only the selected connection; confirm templates/chains/lists survive.
- [ ] **Native filters/traffic:** verify multiline quoted text/comment/state, disabled insertion, exact global/within-chain ordering/move/end, minimal update/delete and last-enabled-rule protection. Verify known shared consumers/acknowledgment and foreign/non-main/unresolved/incomplete-reference read-only gates; record nested/other-protocol audit limits. Measure actual traffic/filter propagation and what resets sessions; do not infer from config success.
- [ ] **Stale/error/outcomes:** introduce controlled template/target/order/reference changes between preview and apply and between own steps; verify zero writes before stale first step, stop on later divergence, partial/indeterminate step accounting and fresh preview requirement. Inspect current state after launched timeout/disconnect; no replay or automatic rollback. Test late origin events/new-editor isolation.
- [ ] **Secret absence/history:** verify sentinel secret absent from ordinary monitoring output, screenshots/previews, returned errors, echoed stderr/logs and persisted receipts; replacement state cleared. Verify real private proof never exports the key and native history remains encrypted/non-replayable after restart/vendor change. Do not retain sensitive test dumps in artifacts.
- [ ] **Restoration/evidence:** record before/after observations, actual resets/traffic effects, remaining orphans and all operator-controlled corrective/restoration actions, plus post-restoration observations. This is manual restoration, **not automatic transactional rollback**. Record deviations for reviewed follow-up rather than quietly changing compatibility claims.

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
BGP_LM_LOG=debug bgp-link-manager   # legacy SSH commands; native safe labels, event routing
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
