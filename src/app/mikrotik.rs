use super::{
    ActiveTab, App, BgpCache, NativeCache, NativeConfigTarget, NativePresentation,
    NativeRouteRequest, PeerRouteView,
};
use crate::bgp::{
    BgpPeer, BgpRoute, BgpState, BgpSummary, PeerKey, PeerRouteDirection, RouteOrigin, RouteStatus,
};
use crate::events::FetchRequest;
use crate::router::mikrotik::{
    presentation_text, MikroTikSnapshot, NativeDiscovery, NativePeerRow, NativeRead, NativeRecord,
    ScopeEligibility,
};
use crate::router::{ConnectionStatus, RouterConfig, RouterVendor};
use anyhow::{ensure, Context, Result};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

fn text<'a>(row: &'a NativeRecord, key: &str) -> Option<&'a str> {
    row.props.get(key)?.as_str()
}

fn number(row: &NativeRecord, key: &str) -> Option<u32> {
    u32::try_from(counter(row, key)?).ok()
}

fn counter(row: &NativeRecord, key: &str) -> Option<u64> {
    let value = row.props.get(key)?;
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}

fn flag(row: &NativeRecord, key: &str) -> Option<bool> {
    match row.props.get(key)? {
        Value::Bool(flag) => Some(*flag),
        Value::String(s) if s == "yes" || s == "true" => Some(true),
        Value::String(s) if s == "no" || s == "false" => Some(false),
        _ => None,
    }
}

/// Redact recursively before presentation. The original source Arc is untouched.
fn safe_value(value: &Value) -> Value {
    match value {
        Value::Object(props) => Value::Object(
            props
                .iter()
                .filter_map(|(key, value)| {
                    let lower = key.to_ascii_lowercase();
                    if ["password", "secret", "md5", "credential"]
                        .iter()
                        .any(|word| lower.contains(word))
                    {
                        None
                    } else {
                        Some((key.clone(), safe_value(value)))
                    }
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(safe_value).collect()),
        other => other.clone(),
    }
}

fn raw_record(record: &NativeRecord) -> String {
    // NativeRecord only contains JSON values; serialization cannot fail.
    let value = Value::Object(record.props.clone().into_iter().collect());
    presentation_text(&safe_value(&value).to_string())
}

pub(crate) fn native_peer_key(row: &NativePeerRow) -> PeerKey {
    if let Some(connection) = &row.connection {
        PeerKey::RouterOsConnection {
            instance: connection.instance.clone(),
            name: connection.name.clone(),
        }
    } else {
        PeerKey::RouterOsSession {
            instance: text(&row.record, "instance").unwrap_or("N/A").into(),
            id: row
                .session_id
                .clone()
                .unwrap_or_else(|| row.record.id.clone()),
        }
    }
}

pub(crate) fn project_native_routes(records: &[NativeRecord]) -> Result<Vec<BgpRoute>> {
    records
        .iter()
        .map(|record| {
            let network =
                text(record, "dst-address").context("native route destination unavailable")?;
            let status = if flag(record, "filtered") == Some(true)
                || text(record, "contribution") == Some("filtered")
            {
                Some(RouteStatus::Filtered)
            } else if flag(record, "unreachable") == Some(true)
                || text(record, "contribution") == Some("unreachable")
            {
                Some(RouteStatus::Unreachable)
            } else {
                // Active is a native RIB observation, not a verified BGP best flag.
                None
            };
            let origin = match text(record, "bgp.origin") {
                Some("igp") => Some(RouteOrigin::Igp),
                Some("egp") => Some(RouteOrigin::Egp),
                Some("incomplete") => Some(RouteOrigin::Incomplete),
                _ => None,
            };
            let communities = record
                .props
                .get("bgp.communities")
                .and_then(|value| match value {
                    Value::String(s) => Some(
                        s.split(',')
                            .filter(|s| !s.is_empty())
                            .map(presentation_text)
                            .collect(),
                    ),
                    Value::Array(values) => values
                        .iter()
                        .map(|v| v.as_str().map(presentation_text))
                        .collect(),
                    _ => None,
                });
            Ok(BgpRoute {
                status,
                native_flags: Some(raw_record(record)),
                network: presentation_text(network),
                next_hop: presentation_text(
                    text(record, "bgp.nexthop")
                        .or_else(|| text(record, "gateway"))
                        .unwrap_or("N/A"),
                ),
                metric: number(record, "bgp.med"),
                local_pref: number(record, "bgp.local-pref"),
                weight: number(record, "bgp.weight"),
                as_path: None,
                as_path_raw: text(record, "bgp.as-path").map(presentation_text),
                origin,
                communities,
            })
        })
        .collect()
}

type NativeProjection = (
    BgpSummary,
    NativeRead<Vec<BgpRoute>>,
    String,
    Vec<Option<NativeConfigTarget>>,
);

pub(crate) fn project_native(snapshot: &MikroTikSnapshot) -> Result<NativeProjection> {
    let instances: Vec<_> = snapshot
        .inventory
        .instances
        .iter()
        .filter(|row| text(row, "name") == Some(snapshot.instance.as_str()))
        .collect();
    ensure!(
        instances.len() == 1,
        "native selected instance unavailable or ambiguous"
    );
    let instance = instances[0];
    let mut peers = Vec::new();
    let mut lines = Vec::new();
    let mut targets = Vec::new();
    let mut push = |line: String, target| {
        lines.push(presentation_text(&line));
        targets.push(target);
    };
    push(
        format!(
            "RouterOS {} — instance {} / main",
            snapshot.inventory.version, snapshot.instance
        ),
        None,
    );
    push(
        "Native management unavailable (monitoring only)".into(),
        None,
    );
    push("Selected effective-main observations only; audit rows excluded from peer totals. Unknown counts: N/A.".into(), None);
    push("Audit warning: nested/other-protocol filter consumers are unknown, even with complete direct BGP references.".into(), None);
    if !snapshot.inventory.bgp_reference_inventory_complete {
        push(
            "Reference inventory incomplete — read-only; guard marker is NOT authorization.".into(),
            None,
        );
    }
    for row in &snapshot.peers {
        let target = row.connection.clone().map(NativeConfigTarget::Connection);
        let reason = row
            .read_only_reason
            .as_deref()
            .unwrap_or("monitoring only; management unavailable");
        push(
            format!(
                "connection {} [{}] — {reason}",
                text(&row.record, "name").unwrap_or(&row.record.id),
                text(&row.record, "instance").unwrap_or("N/A")
            ),
            target,
        );
        // Config presentation intentionally whitelists nonvolatile, nonsensitive
        // properties. Full original records remain in the immutable snapshot.
        for key in [
            "comment",
            "remote.address",
            "remote.as",
            "local.address",
            "local.role",
            "as",
            "afi",
            "disabled",
            "dynamic",
            "templates",
            "routing-table",
            "vrf",
            "input.filter",
            "output.filter-chain",
            "output.filter-select",
        ] {
            if let Some(value) = row.record.props.get(key) {
                push(format!("  {key}={}", safe_value(value)), None);
            }
        }
        if let Some(session) = &row.session {
            for key in [
                "established",
                "prefix-count",
                "hold-time",
                "keepalive-time",
                "remote.hold-time",
                "remote.afi",
                "local.afi",
                "uptime",
            ] {
                if let Some(value) = session.props.get(key) {
                    push(
                        format!("  observed {key}={value} (raw native; not Adj-RIB-In telemetry)"),
                        None,
                    );
                }
            }
        }
        // Inventory/audit contains foreign and unresolved rows. Never mix their
        // telemetry into the selected effective-main summary or transition log.
        if row.scope != ScopeEligibility::Main
            || row
                .connection
                .as_ref()
                .is_none_or(|c| c.instance != snapshot.instance)
        {
            continue;
        }
        let runtime = row.session.as_ref();
        let remote_as = runtime
            .and_then(|s| number(s, "remote.as"))
            .or_else(|| number(&row.record, "remote.as"));
        let local_as = runtime
            .and_then(|s| number(s, "local.as"))
            .or_else(|| number(&row.record, "as"));
        let state = match runtime.and_then(|session| flag(session, "established")) {
            Some(true) => BgpState::Established,
            Some(false) => BgpState::Unknown("not established (native)".into()),
            None => BgpState::Unknown("unobserved".into()),
        };
        let source = format!(
            "configured: {}; runtime: {}; scope: {:?}; read-only: {}",
            raw_record(&row.record),
            runtime
                .map(raw_record)
                .unwrap_or_else(|| "unobserved".into()),
            row.scope,
            reason
        );
        peers.push(BgpPeer {
            key: Some(native_peer_key(row)),
            admin_disabled: flag(&row.record, "disabled"),
            native_source: Some(presentation_text(&source)),
            neighbor_ip: presentation_text(
                runtime
                    .and_then(|s| text(s, "remote.address"))
                    .or_else(|| text(&row.record, "remote.address"))
                    .unwrap_or("N/A"),
            ),
            remote_as,
            local_as,
            state,
            uptime: runtime
                .and_then(|s| text(s, "uptime"))
                .map(presentation_text),
            prefixes_received: None,
            prefixes_advertised: None,
            description: text(&row.record, "comment").map(presentation_text),
            update_source: None,
            next_hop_self: None,
            route_reflector_client: None,
            password_configured: None,
            msg_rcvd: runtime.and_then(|s| counter(s, "remote.messages")),
            msg_sent: runtime.and_then(|s| counter(s, "local.messages")),
            hold_time: None,
            keepalive: None,
            communities: vec![],
            route_map_in: None,
            route_map_out: None,
            reset_count: None,
            last_reset_reason: None,
            notifs_sent: None,
            notifs_rcvd: None,
            bfd_state: None,
            mtu_probe: None,
        });
    }
    let mut chains = std::collections::BTreeSet::new();
    for rule in &snapshot.inventory.rules {
        if let Some(chain) = text(rule, "chain") {
            if chains.insert(chain.to_owned()) {
                push(
                    format!("filter chain {chain} — native management unavailable"),
                    Some(NativeConfigTarget::Chain(chain.into())),
                );
            }
            push(
                format!(
                    "  rule {}: {} (disabled={})",
                    rule.id,
                    text(rule, "rule").unwrap_or("N/A"),
                    crate::bgp::known_text(flag(rule, "disabled"))
                ),
                None,
            );
        }
    }
    let routes = match &snapshot.routes {
        NativeRead::Available(records) => NativeRead::Available(project_native_routes(records)?),
        NativeRead::Unavailable(reason) => NativeRead::Unavailable(presentation_text(reason)),
    };
    push(
        format!(
            "Stored native routes: {}",
            match &routes {
                NativeRead::Available(routes) =>
                    format!("{} observed; not full pre-policy Adj-RIB-In", routes.len()),
                NativeRead::Unavailable(reason) => format!("unavailable — {reason}"),
            }
        ),
        None,
    );
    push(
        "Native advertisements and MTU unavailable; no hidden probes or retention.".into(),
        None,
    );
    Ok((
        BgpSummary {
            router_id: text(instance, "router-id").and_then(|s| s.parse().ok()),
            local_as: number(instance, "as"),
            table_version: None,
            peers,
            fetched_at: snapshot.fetched_at,
        },
        routes,
        lines.join("\n"),
        targets,
    ))
}

fn matches_config(config: &RouterConfig, registration: &crate::ssh::NativeRegistration) -> bool {
    config.vendor == RouterVendor::MikroTik
        && config.id == registration.router_id
        && config.hostname == registration.endpoint.hostname
        && config.username == registration.endpoint.username
        && config.ssh_port == registration.endpoint.ssh_port
}

fn selected_instance(config: &RouterConfig) -> Option<&str> {
    config
        .mikrotik_instance
        .as_deref()
        .filter(|name| !name.trim().is_empty())
}

pub(crate) fn native_stored_peer_routes(
    source: &MikroTikSnapshot,
    key: &PeerKey,
) -> Result<Vec<BgpRoute>> {
    let rows: Vec<_> = source
        .peers
        .iter()
        .filter(|row| native_peer_key(row) == *key)
        .collect();
    ensure!(
        rows.len() == 1,
        "native peer identity unavailable or ambiguous"
    );
    let row = rows[0];
    let connection = row
        .connection
        .as_ref()
        .context("native configured association unavailable")?;
    ensure!(
        connection.generation == source.generation
            && connection.instance == source.instance
            && row.scope == ScopeEligibility::Main,
        "native peer scope unavailable"
    );
    ensure!(
        connection.observed_id == row.record.id
            && source
                .inventory
                .connections
                .iter()
                .filter(|record| **record == row.record)
                .count()
                == 1,
        "native configured object changed"
    );
    let session = row
        .session
        .as_ref()
        .context("native runtime association unavailable")?;
    ensure!(
        row.session_id.as_deref() == Some(session.id.as_str()),
        "native session changed"
    );
    ensure!(
        source
            .inventory
            .sessions
            .iter()
            .any(|record| record == session),
        "native observed session changed"
    );
    let name = text(session, "name").context("native runtime name unavailable")?;
    ensure!(
        source
            .inventory
            .sessions
            .iter()
            .filter(|s| text(s, "name") == Some(name) && s.id == session.id)
            .count()
            == 1
            && source
                .inventory
                .sessions
                .iter()
                .filter(|s| text(s, "name") == Some(name))
                .count()
                == 1,
        "native session association ambiguous"
    );
    let NativeRead::Available(routes) = &source.routes else {
        anyhow::bail!("native stored routes unavailable")
    };
    let selected: Vec<_> = routes
        .iter()
        .filter(|route| text(route, "bgp.session") == Some(name))
        .cloned()
        .collect();
    project_native_routes(&selected)
}

impl App {
    pub(crate) fn is_native_selected(&self) -> bool {
        self.selected_router()
            .is_some_and(|r| r.vendor == RouterVendor::MikroTik)
    }

    pub(crate) fn is_native_router(&self, id: Uuid) -> bool {
        self.all_routers
            .iter()
            .any(|router| router.id == id && router.vendor == RouterVendor::MikroTik)
    }

    pub(crate) fn reject_native_management(&mut self) -> bool {
        if self.is_native_selected() {
            self.set_status("MikroTik native management unavailable — monitoring only");
            true
        } else {
            false
        }
    }

    pub fn request_native_refresh(&mut self, router_id: Uuid) {
        let Some(router) = self
            .all_routers
            .iter()
            .find(|r| r.id == router_id && r.vendor == RouterVendor::MikroTik)
        else {
            return;
        };
        let instance = selected_instance(router).map(str::to_owned);
        let request = Uuid::new_v4();
        let previous_request = self
            .native_cache
            .get(&router_id)
            .map(|cache| cache.latest_request);
        let previous_pending = self.native_refresh_pending.insert(router_id, request);
        self.native_cache
            .entry(router_id)
            .or_insert_with(|| NativeCache {
                snapshot: None,
                discovered_instances: None,
                latest_request: request,
                stale_reason: None,
            })
            .latest_request = request;
        let dispatched = self.fetch_tx.as_ref().is_some_and(|tx| {
            tx.send(FetchRequest::RefreshMikroTik {
                router_id,
                request,
                instance,
            })
            .is_ok()
        });
        if !dispatched {
            // A failed send is not outstanding work and must not supersede a
            // request that really was sent. Keep initial cache metadata usable
            // even without a service, but never strand automatic polling.
            match previous_pending {
                Some(previous) => {
                    self.native_refresh_pending.insert(router_id, previous);
                }
                None => {
                    self.native_refresh_pending.remove(&router_id);
                }
            }
            if let Some(cache) = self.native_cache.get_mut(&router_id) {
                if let Some(previous) = previous_request {
                    cache.latest_request = previous;
                }
                cache.stale_reason =
                    Some("Native refresh not dispatched: fetch service unavailable".into());
            }
        }
    }

    pub(crate) fn request_native_refresh_automatic(&mut self, router_id: Uuid) {
        if !self.native_refresh_pending.contains_key(&router_id) {
            self.request_native_refresh(router_id);
        }
    }

    fn finish_native_refresh(&mut self, router_id: Uuid, request: Uuid) {
        if self.native_refresh_pending.get(&router_id) == Some(&request) {
            self.native_refresh_pending.remove(&router_id);
        }
    }

    /// Invalidate BEFORE registration control and any subsequent tracked read.
    pub(crate) fn invalidate_native(&mut self, id: Uuid) {
        self.native_refresh_pending.remove(&id);
        self.native_cache.remove(&id);
        self.bgp_cache.remove(&id);
        self.routemap_cache
            .retain(|(router_id, _), _| *router_id != id);
        self.prefix_list_cache
            .retain(|(router_id, _), _| *router_id != id);
        self.community_list_cache
            .retain(|(router_id, _), _| *router_id != id);
        if self
            .pending_native_view
            .as_ref()
            .is_some_and(|view| view.snapshot.router_id == id)
        {
            self.pending_native_view = None;
            self.has_pending_update = false;
        }
        if self
            .native_view
            .as_ref()
            .is_some_and(|view| view.snapshot.router_id == id)
        {
            self.native_view = None;
        }
        if self.selected_router().is_some_and(|r| r.id == id) {
            self.current_summary = None;
            self.current_peers.clear();
            self.current_routes.clear();
            self.config_lines.clear();
            self.rendered_config.clear();
            self.pending_bgp_update = None;
            self.pending_route_update = None;
            self.peer_route_view = None;
            self.config_rm_name = None;
            self.config_routemap = None;
            self.config_pl_name = None;
            self.routemap_fetch_queued = None;
            // Task4 never opens native drafts. Discard any legacy preview on a
            // vendor/endpoint change rather than letting it target a new device.
            self.wizard_close();
            self.clone_draft = None;
            self.clone_target_router = None;
        }
    }

    pub fn handle_native_data(&mut self, id: Uuid, request: Uuid, discovery: NativeDiscovery) {
        self.finish_native_refresh(id, request);
        if !self
            .native_cache
            .get(&id)
            .is_some_and(|cache| cache.accepts(request))
        {
            return;
        }
        let Some(config) = self.all_routers.iter().find(|r| r.id == id) else {
            return;
        };
        let snapshot = match discovery {
            NativeDiscovery::Instances {
                router_id,
                registration,
                request: source_request,
                names,
            } => {
                if router_id != id
                    || source_request != request
                    || !matches_config(config, &registration)
                    || selected_instance(config).is_some()
                {
                    return;
                }
                if let Some(cache) = self.native_cache.get_mut(&id) {
                    cache.discovered_instances = Some(names);
                    cache.snapshot = None;
                    cache.stale_reason = None;
                }
                if self.selected_router().is_some_and(|r| r.id == id) {
                    self.reload_native_selected(id);
                }
                return;
            }
            NativeDiscovery::Snapshot(snapshot) => snapshot,
        };
        if snapshot.router_id != id
            || snapshot.request != request
            || !matches_config(config, &snapshot.registration)
            || selected_instance(config) != Some(snapshot.instance.as_str())
        {
            return;
        }
        let (summary, routes, rendered, targets) = match project_native(&snapshot) {
            Ok(projection) => projection,
            Err(_) => {
                self.handle_native_error(id, request, "native projection unavailable".into());
                return;
            }
        };
        self.record_peer_transitions(id, &summary);
        let snapshot = Arc::new(snapshot);
        let Some(cache) = self.native_cache.get_mut(&id) else {
            return;
        };
        if !cache.accept_snapshot(request, Arc::clone(&snapshot)) {
            return;
        }
        let last_routes = self
            .bgp_cache
            .get(&id)
            .map(|c| c.routes.clone())
            .unwrap_or_default();
        let routes = match routes {
            NativeRead::Available(routes) => routes,
            NativeRead::Unavailable(reason) => {
                cache.stale_reason = Some(format!("Stored routes unavailable/stale: {reason}"));
                last_routes
            }
        };
        self.bgp_cache.insert(
            id,
            BgpCache {
                summary: summary.clone(),
                peers: summary.peers.clone(),
                routes,
                config: rendered,
            },
        );
        self.router_status.insert(id, ConnectionStatus::Connected);
        if self.selected_router().is_none_or(|r| r.id != id) {
            return;
        }
        let presentation = NativePresentation {
            snapshot,
            config_targets: targets,
        };
        if self.current_tab == ActiveTab::Config && self.native_view.is_some() {
            self.pending_native_view = Some(presentation);
            self.has_pending_update = true;
        } else {
            self.apply_native_presentation(presentation);
        }
    }

    pub fn handle_native_error(&mut self, id: Uuid, request: Uuid, safe_error: String) {
        self.finish_native_refresh(id, request);
        let Some(cache) = self
            .native_cache
            .get_mut(&id)
            .filter(|c| c.accepts(request))
        else {
            return;
        };
        cache.stale_reason = Some(presentation_text(&safe_error));
        if self.selected_router().is_some_and(|r| r.id == id) {
            self.set_status(format!(
                "Native data stale/unavailable: {}",
                presentation_text(&safe_error)
            ));
        }
    }

    pub(crate) fn apply_native_presentation(&mut self, view: NativePresentation) {
        let id = view.snapshot.router_id;
        if self
            .selected_router()
            .is_none_or(|r| r.id != id || r.vendor != RouterVendor::MikroTik)
        {
            return;
        }
        let Ok((summary, routes, rendered, targets)) = project_native(&view.snapshot) else {
            return;
        };
        // Every displayed line and target comes from this exact immutable source.
        self.current_peers = summary.peers.clone();
        self.current_summary = Some(summary);
        self.rendered_config = rendered;
        self.config_lines = self.rendered_config.lines().map(str::to_owned).collect();
        self.native_view = Some(NativePresentation {
            snapshot: view.snapshot,
            config_targets: targets,
        });
        match routes {
            NativeRead::Available(routes) => self.current_routes = routes,
            NativeRead::Unavailable(_) => {
                self.current_routes = self
                    .bgp_cache
                    .get(&id)
                    .map(|c| c.routes.clone())
                    .unwrap_or_default();
            }
        }
        self.config_rm_name = None;
        self.config_routemap = None;
        self.config_pl_name = None;
        self.routemap_fetch_queued = None;
        self.config_list_state
            .select((!self.config_lines.is_empty()).then_some(0));
        self.peer_route_view = None;
        self.update_peer_filter();
        self.update_route_filter();
        self.update_config_filter();
    }

    pub(crate) fn reload_native_selected(&mut self, id: Uuid) {
        self.current_summary = None;
        self.current_peers.clear();
        self.current_routes.clear();
        self.config_lines.clear();
        self.rendered_config.clear();
        self.native_view = None;
        self.config_rm_name = None;
        self.config_routemap = None;
        self.config_pl_name = None;
        self.routemap_fetch_queued = None;
        if let Some(snapshot) = self.native_cache.get(&id).and_then(|c| c.snapshot.clone()) {
            if let Ok((_, _, _, targets)) = project_native(&snapshot) {
                self.apply_native_presentation(NativePresentation {
                    snapshot,
                    config_targets: targets,
                });
            }
        } else {
            let names = self
                .native_cache
                .get(&id)
                .and_then(|c| c.discovered_instances.as_ref());
            self.rendered_config = format!("Native discovery only — select an explicit BGP Instance in router settings.\nMain-table candidates: {}\nNative management unavailable",
                names.map(|names| names.iter().map(|s| presentation_text(s)).collect::<Vec<_>>().join(", ")).unwrap_or_else(|| "N/A (refresh required)".into()));
            self.config_lines = self.rendered_config.lines().map(str::to_owned).collect();
        }
        self.update_peer_filter();
        self.update_route_filter();
        self.update_config_filter();
    }

    pub fn displayed_native_target(&self) -> Option<(&MikroTikSnapshot, &NativeConfigTarget)> {
        let view = self.native_view.as_ref()?;
        let index = self.config_list_state.selected()?;
        let index = if self.config_filter_mode != super::FilterMode::Off {
            *self.config_indices.get(index)?
        } else {
            index
        };
        Some((&view.snapshot, view.config_targets.get(index)?.as_ref()?))
    }

    pub(crate) fn open_native_peer_routes(&mut self, direction: PeerRouteDirection) {
        let Some(view) = self.native_view.as_ref() else {
            return;
        };
        let Some(peer) = self
            .peer_table_state
            .selected()
            .and_then(|i| self.peer_indices.get(i))
            .and_then(|&i| self.current_peers.get(i))
        else {
            return;
        };
        let source = Arc::clone(&view.snapshot);
        let request = NativeRouteRequest {
            router_id: source.router_id,
            request: Uuid::new_v4(),
            registration: source.registration.clone(),
            generation: source.generation,
            peer: peer.identity(),
            direction,
        };
        let error = (direction == PeerRouteDirection::Advertised)
            .then(|| "Native advertisements unavailable (no retention or hidden probes)".into());
        self.peer_route_view = Some(PeerRouteView {
            peer_ip: peer.neighbor_ip.clone(),
            direction,
            routes: None,
            error,
            native_request: Some(request.clone()),
            native_source: Some(Arc::clone(&source)),
        });
        if direction == PeerRouteDirection::Received {
            self.send_fetch(FetchRequest::FetchNativeRoutes { request, source });
        }
    }

    pub fn handle_native_routes(
        &mut self,
        request: NativeRouteRequest,
        routes: NativeRead<Vec<BgpRoute>>,
    ) {
        if self
            .selected_router()
            .is_none_or(|r| r.id != request.router_id || r.vendor != RouterVendor::MikroTik)
            || self.native_view.as_ref().is_none_or(|view| {
                view.snapshot.generation != request.generation
                    || view.snapshot.registration != request.registration
            })
        {
            return;
        }
        let Some(view) = self
            .peer_route_view
            .as_mut()
            .filter(|view| view.native_request.as_ref() == Some(&request))
        else {
            return;
        };
        if self
            .native_cache
            .get(&request.router_id)
            .and_then(|c| c.snapshot.as_ref())
            .is_none_or(|s| s.generation != request.generation)
        {
            view.error = Some("Displayed native source is stale — accept pending data or refresh before drill-down".into());
            return;
        }
        match routes {
            NativeRead::Available(routes) => {
                view.routes = Some(routes);
                view.error = None;
            }
            NativeRead::Unavailable(reason) => {
                view.error = Some(presentation_text(&reason));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{ActiveTab, App, NativeCache};
    use crate::bgp::{BgpState, PeerKey, PeerRouteDirection, RouteStatus};
    use crate::config::AppConfig;
    use crate::db::RouterDb;
    use crate::events::FetchRequest;
    use crate::router::mikrotik::{test_support::*, NativeDiscovery, NativeRead};
    use crate::router::{RouterConfig, RouterVendor};
    use std::sync::Arc;
    use uuid::Uuid;

    pub(crate) fn app() -> (App, tokio::sync::mpsc::UnboundedReceiver<FetchRequest>) {
        let router = RouterConfig {
            id: Uuid::nil(),
            vendor: RouterVendor::MikroTik,
            hostname: "lab.invalid".into(),
            username: "tester".into(),
            mikrotik_instance: Some("blue".into()),
            ..RouterConfig::default()
        };
        let mut app = App::new(
            AppConfig {
                routers: vec![router],
                ..AppConfig::default()
            },
            RouterDb::in_memory().unwrap(),
        );
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        app.set_fetch_tx(tx);
        (app, rx)
    }

    fn deliver(app: &mut App, mut snapshot: crate::router::mikrotik::MikroTikSnapshot) {
        let id = snapshot.router_id;
        snapshot.request = app.native_cache[&id].latest_request;
        app.handle_native_data(id, snapshot.request, NativeDiscovery::Snapshot(snapshot));
    }

    fn automatic_poll(app: &mut App) {
        // Withhold terminal events while advancing the actual 30s timer, not
        // wall-clock time. Ping requests are only queued; no worker is running.
        for _ in 0..150 {
            app.tick();
        }
    }

    fn take_native_requests(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<FetchRequest>,
    ) -> Vec<(Uuid, Option<String>)> {
        let mut requests = Vec::new();
        while let Ok(request) = rx.try_recv() {
            if let FetchRequest::RefreshMikroTik {
                request, instance, ..
            } = request
            {
                requests.push((request, instance));
            }
        }
        requests
    }

    #[test]
    fn mikrotik_rev_001_slow_automatic_read_publishes_without_poll_starvation() {
        let (mut app, mut rx) = app();
        app.router_status
            .insert(Uuid::nil(), ConnectionStatus::Connected);
        automatic_poll(&mut app);
        let first = take_native_requests(&mut rx);
        assert_eq!(first.len(), 1);
        let request = first[0].0;
        for _ in 0..4 {
            automatic_poll(&mut app);
        }
        assert!(
            take_native_requests(&mut rx).is_empty(),
            "automatic polls must coalesce while the original read is outstanding"
        );
        assert_eq!(app.native_cache[&Uuid::nil()].latest_request, request);
        assert_eq!(app.tick_counter, 750);
        let mut snapshot = documented_snapshot();
        snapshot.request = request;
        let generation = snapshot.generation;
        app.handle_native_data(Uuid::nil(), request, NativeDiscovery::Snapshot(snapshot));
        assert_eq!(
            app.native_view.as_ref().unwrap().snapshot.generation,
            generation
        );
        automatic_poll(&mut app);
        let next = take_native_requests(&mut rx);
        assert_eq!(next.len(), 1);
        assert_ne!(next[0].0, request);
    }

    #[test]
    fn mikrotik_rev_001_manual_supersession_and_stale_terminal_do_not_release_new_read() {
        let (mut app, mut rx) = app();
        app.router_status
            .insert(Uuid::nil(), ConnectionStatus::Connected);
        app.request_native_refresh(Uuid::nil());
        let a = take_native_requests(&mut rx)[0].0;
        app.request_refresh_selected();
        let b = take_native_requests(&mut rx)[0].0;
        assert_ne!(a, b);
        let mut old = documented_snapshot();
        old.request = a;
        app.handle_native_data(Uuid::nil(), a, NativeDiscovery::Snapshot(old));
        app.handle_native_error(Uuid::nil(), a, "old error".into());
        automatic_poll(&mut app);
        assert!(
            take_native_requests(&mut rx).is_empty(),
            "old A cannot clear the outstanding B"
        );
        assert!(app.current_summary.is_none());
        assert_eq!(app.native_cache[&Uuid::nil()].latest_request, b);
        let mut current = documented_snapshot();
        current.request = b;
        let generation = current.generation;
        app.handle_native_data(Uuid::nil(), b, NativeDiscovery::Snapshot(current));
        assert_eq!(
            app.native_view.as_ref().unwrap().snapshot.generation,
            generation
        );
        automatic_poll(&mut app);
        let next = take_native_requests(&mut rx);
        assert_eq!(next.len(), 1);
        assert_ne!(next[0].0, b);
    }

    #[test]
    fn mikrotik_rev_001_matching_invalid_terminal_releases_without_publishing() {
        let (mut app, mut rx) = app();
        app.router_status
            .insert(Uuid::nil(), ConnectionStatus::Connected);
        for instances in [false, true] {
            app.request_native_refresh(Uuid::nil());
            let request = take_native_requests(&mut rx)[0].0;
            let discovery = if instances {
                NativeDiscovery::Instances {
                    router_id: Uuid::nil(),
                    request,
                    registration: documented_registration(),
                    names: vec!["blue".into()],
                }
            } else {
                let mut snapshot = documented_snapshot();
                snapshot.request = request;
                snapshot.instance = "wrong-scope".into();
                NativeDiscovery::Snapshot(snapshot)
            };
            app.handle_native_data(Uuid::nil(), request, discovery);
            assert!(app.current_summary.is_none());
            automatic_poll(&mut app);
            assert_eq!(
                take_native_requests(&mut rx).len(),
                1,
                "a terminal payload rejected by correlation must not strand automatic retries"
            );
        }
    }

    #[test]
    fn mikrotik_rev_001_discovery_config_invalidation_vendor_and_delete_reset_pending() {
        let (mut app, mut rx) = app();
        let id = Uuid::nil();
        app.router_status.insert(id, ConnectionStatus::Connected);
        app.request_native_refresh(id);
        let old = take_native_requests(&mut rx)[0].0;
        app.invalidate_native(id);
        app.routers[0].mikrotik_instance = None;
        app.all_routers[0].mikrotik_instance = None;
        automatic_poll(&mut app);
        let discovery_request = take_native_requests(&mut rx);
        assert_eq!(discovery_request.len(), 1);
        let request = discovery_request[0].0;
        assert_eq!(discovery_request[0].1, None);
        app.handle_native_data(
            id,
            request,
            NativeDiscovery::Instances {
                router_id: id,
                request,
                registration: documented_registration(),
                names: vec!["blue".into()],
            },
        );
        automatic_poll(&mut app);
        let next = take_native_requests(&mut rx);
        assert_eq!(
            next.len(),
            1,
            "discovery terminal must release automatic polling"
        );
        app.invalidate_native(id);
        for router in [&mut app.routers[0], &mut app.all_routers[0]] {
            router.hostname = "replacement.invalid".into();
            router.mikrotik_instance = Some("red".into());
        }
        automatic_poll(&mut app);
        let replacement = take_native_requests(&mut rx);
        assert_eq!(replacement.len(), 1);
        assert_eq!(replacement[0].1.as_deref(), Some("red"));
        app.handle_native_error(id, old, "old registration error".into());
        app.handle_native_error(id, next[0].0, "old scope error".into());
        automatic_poll(&mut app);
        assert!(take_native_requests(&mut rx).is_empty());
        app.invalidate_native(id);
        app.routers[0].vendor = RouterVendor::Cisco;
        app.all_routers[0].vendor = RouterVendor::Cisco;
        automatic_poll(&mut app);
        assert!(take_native_requests(&mut rx).is_empty());
        app.routers[0].vendor = RouterVendor::MikroTik;
        app.all_routers[0].vendor = RouterVendor::MikroTik;
        automatic_poll(&mut app);
        assert_eq!(take_native_requests(&mut rx).len(), 1);
        app.invalidate_native(id);
        app.routers.clear();
        app.all_routers.clear();
        automatic_poll(&mut app);
        assert!(take_native_requests(&mut rx).is_empty());
    }

    #[test]
    fn mikrotik_rev_001_unavailable_or_closed_channel_does_not_strand_automatic_dispatch() {
        let (mut app, _) = app();
        app.router_status
            .insert(Uuid::nil(), ConnectionStatus::Connected);
        app.fetch_tx = None;
        app.request_native_refresh(Uuid::nil());
        for closed in [false, true] {
            if closed {
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                drop(rx);
                app.set_fetch_tx(tx);
                app.request_native_refresh(Uuid::nil());
            }
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            app.set_fetch_tx(tx);
            automatic_poll(&mut app);
            let requests = take_native_requests(&mut rx);
            assert_eq!(requests.len(), 1);
            app.handle_native_error(Uuid::nil(), requests[0].0, "synthetic terminal".into());
        }
    }

    #[test]
    fn mikrotik_rev_001_failed_manual_send_preserves_dispatched_read_and_online_retry_coalesces() {
        let (mut app, mut rx) = app();
        let id = Uuid::nil();
        app.request_native_refresh(id);
        let request = take_native_requests(&mut rx)[0].0;
        let working_tx = app.fetch_tx.clone().unwrap();
        let (closed_tx, closed_rx) = tokio::sync::mpsc::unbounded_channel();
        drop(closed_rx);
        app.set_fetch_tx(closed_tx);
        app.request_native_refresh(id);
        assert_eq!(
            app.native_cache[&id].latest_request, request,
            "failed manual dispatch must not supersede work that was actually sent"
        );
        app.set_fetch_tx(working_tx);
        app.router_status.insert(id, ConnectionStatus::Disconnected);
        app.handle_ping_result(id, Some(std::time::Duration::from_millis(1)));
        assert!(
            take_native_requests(&mut rx).is_empty(),
            "came-online automatic retry must coalesce with the outstanding read"
        );
        app.handle_native_error(id, request, "matching terminal".into());
        automatic_poll(&mut app);
        assert_eq!(take_native_requests(&mut rx).len(), 1);
    }

    #[test]
    fn mikrotik_unknowns_do_not_become_measured_zero() {
        let snapshot = documented_snapshot();
        let (summary, routes, text, targets) = project_native(&snapshot).unwrap();
        assert!(summary.table_version.is_none());
        assert!(summary
            .peers
            .iter()
            .all(|p| p.prefixes_advertised.is_none()));
        assert!(summary.total_prefixes().is_none());
        let NativeRead::Available(routes) = routes else {
            panic!("fixture routes must be known")
        };
        assert_eq!(routes[0].as_path_str(), "65001,{65002,65003}");
        assert_eq!(routes[0].status, Some(RouteStatus::Filtered));
        assert!(routes[0].as_path.is_none());
        assert!(routes[0].weight.is_none());
        assert_eq!(summary.peers[1].admin_disabled, Some(true));
        assert!(matches!(summary.peers[1].state, BgpState::Unknown(_)));
        assert_eq!(
            summary.peers[0].identity(),
            PeerKey::RouterOsConnection {
                instance: "blue".into(),
                name: "peer-a".into()
            }
        );
        assert_eq!(text.lines().count(), targets.len());
        assert!(text.contains("other-protocol"));
        assert!(text.contains("unavailable"));
    }

    #[test]
    fn mikrotik_unknowns_scope_and_ambiguous_prefix_count_are_not_totals() {
        let mut snapshot = documented_snapshot();
        snapshot.inventory.sessions[0]
            .props
            .insert("prefix-count".into(), serde_json::json!(42));
        let mut foreign = snapshot.inventory.connections[0].clone();
        foreign.id = "*FF".into();
        foreign
            .props
            .insert("instance".into(), serde_json::json!("red"));
        snapshot.inventory.connections.push(foreign);
        snapshot.peers = crate::router::mikrotik::join_native_peers(
            &snapshot.inventory,
            "blue",
            snapshot.generation,
        )
        .unwrap();
        let (summary, _, text, _) = project_native(&snapshot).unwrap();
        assert_eq!(summary.peers.len(), 2);
        assert_eq!(summary.total_prefixes(), None);
        assert!(text.contains("red"));
        assert!(text.contains("42"));
        assert!(text.contains("prefix-count"));
    }

    #[test]
    fn mikrotik_unknowns_projection_redacts_nested_secrets_and_escapes_communities() {
        let mut snapshot = documented_snapshot();
        let NativeRead::Available(routes) = &mut snapshot.routes else {
            panic!("known fixture")
        };
        routes[0].props.insert(
            "bgp.communities".into(),
            serde_json::json!(["65000:1\u{1b}[2J"]),
        );
        routes[0].props.insert(
            "future".into(),
            serde_json::json!({"tcp-md5-key":"synthetic-hidden"}),
        );
        let original = snapshot.clone();
        let (_, projected, _, _) = project_native(&snapshot).unwrap();
        let NativeRead::Available(routes) = projected else {
            panic!("known fixture")
        };
        assert!(!routes[0].communities.as_ref().unwrap()[0].contains('\u{1b}'));
        assert!(!routes[0]
            .native_flags
            .as_ref()
            .unwrap()
            .contains("synthetic-hidden"));
        assert_eq!(snapshot, original);
    }

    #[test]
    fn mikrotik_unknowns_representable_native_message_counters_keep_u64_range() {
        let mut snapshot = documented_snapshot();
        snapshot.inventory.sessions[0].props.insert(
            "remote.messages".into(),
            serde_json::json!(4_294_967_299u64),
        );
        snapshot.inventory.sessions[0].props.insert(
            "local.messages".into(),
            serde_json::json!("18446744073709551615"),
        );
        snapshot.peers = crate::router::mikrotik::join_native_peers(
            &snapshot.inventory,
            "blue",
            snapshot.generation,
        )
        .unwrap();
        let (summary, _, _, _) = project_native(&snapshot).unwrap();
        assert_eq!(summary.peers[0].msg_rcvd, Some(4_294_967_299));
        assert_eq!(summary.peers[0].msg_sent, Some(u64::MAX));
    }

    #[test]
    fn mikrotik_cache_request_replacement_and_error_keep_last_good() {
        let snapshot = Arc::new(documented_snapshot());
        let a = snapshot.request;
        let mut cache = NativeCache {
            snapshot: None,
            discovered_instances: None,
            latest_request: a,
            stale_reason: None,
        };
        assert!(cache.accept_snapshot(a, Arc::clone(&snapshot)));
        let b = Uuid::new_v4();
        cache.latest_request = b;
        assert!(!cache.accepts(a));
        assert!(!cache.accept_snapshot(a, Arc::clone(&snapshot)));
        assert!(Arc::ptr_eq(cache.snapshot.as_ref().unwrap(), &snapshot));
        let (mut app, _) = app();
        app.native_cache.insert(Uuid::nil(), cache);
        app.handle_native_error(Uuid::nil(), a, "old error".into());
        assert!(app.native_cache[&Uuid::nil()].stale_reason.is_none());
        app.handle_native_error(Uuid::nil(), b, "unavailable".into());
        assert_eq!(
            app.native_cache[&Uuid::nil()].stale_reason.as_deref(),
            Some("unavailable")
        );
        assert!(app.native_cache[&Uuid::nil()].snapshot.is_some());
    }

    #[test]
    fn mikrotik_cache_rf5_other_router_and_deferred_rows_keep_source_pairing() {
        let (mut app, mut rx) = app();
        app.request_native_refresh(Uuid::nil());
        assert!(
            matches!(rx.try_recv().unwrap(), FetchRequest::RefreshMikroTik { request, .. }
            if request == app.native_cache[&Uuid::nil()].latest_request)
        );
        let old = documented_snapshot();
        let old_gen = old.generation;
        let old_guard = old.guard.clone();
        let old_registration = old.registration.clone();
        deliver(&mut app, old.clone());
        app.current_tab = ActiveTab::Config;
        let lines = app.config_lines.clone();
        let targets = app.native_view.as_ref().unwrap().config_targets.clone();
        let mut new = documented_snapshot();
        new.inventory.connections.reverse();
        new.inventory.rules.reverse();
        new.guard = crate::router::mikrotik::config_guard(&new.inventory, &new.instance).unwrap();
        new.peers.reverse();
        app.request_native_refresh(Uuid::nil());
        deliver(&mut app, new);
        assert_eq!(app.config_lines, lines);
        assert_eq!(
            app.native_view.as_ref().unwrap().snapshot.generation,
            old_gen
        );
        assert_eq!(app.native_view.as_ref().unwrap().config_targets, targets);
        let connection_line = targets
            .iter()
            .position(|target| matches!(target, Some(NativeConfigTarget::Connection(_))))
            .unwrap();
        app.config_list_state.select(Some(connection_line));
        let (displayed_source, displayed_target) = app.displayed_native_target().unwrap();
        assert_eq!(displayed_source.generation, old_gen);
        assert_eq!(displayed_source.guard, old_guard);
        assert_eq!(displayed_source.registration, old_registration);
        assert!(
            matches!(displayed_target, NativeConfigTarget::Connection(connection) if connection.name == "peer-a" && connection.observed_id == "*2")
        );
        app.dismiss_pending_update();
        assert_eq!(app.config_lines, lines);
        assert_eq!(
            app.native_view.as_ref().unwrap().snapshot.generation,
            old_gen
        );
        deliver(&mut app, documented_snapshot());
        let pending_gen = app
            .pending_native_view
            .as_ref()
            .unwrap()
            .snapshot
            .generation;
        app.accept_pending_update();
        assert_eq!(
            app.native_view.as_ref().unwrap().snapshot.generation,
            pending_gen
        );
        let other = RouterConfig {
            name: "other".into(),
            ..RouterConfig::default()
        };
        app.routers.push(other.clone());
        app.all_routers.push(other);
        app.router_list_state.select(Some(1));
        app.reload_selected_router();
        let display = app.config_lines.clone();
        app.editor_start_edit();
        let draft = app.editor_draft.as_ref().unwrap().hostname.clone();
        deliver(&mut app, documented_snapshot());
        assert_eq!(app.config_lines, display);
        assert_eq!(app.editor_draft.as_ref().unwrap().hostname, draft);
        assert!(app.native_view.is_none());
    }

    #[test]
    fn mikrotik_cache_navigation_is_read_only_and_actions_reject_legacy_paths() {
        let (mut app, mut rx) = app();
        app.request_native_refresh(Uuid::nil());
        rx.try_recv().unwrap();
        deliver(&mut app, documented_snapshot());
        app.current_tab = ActiveTab::Config;
        for i in 0..app.config_lines.len() {
            app.config_list_state.select(Some(i));
            app.on_config_nav();
        }
        app.reload_selected_router();
        app.toggle_peer_shutdown();
        app.start_clone_peer();
        app.wizard_open_create();
        app.request_mtu_probe("192.0.2.2".parse().unwrap());
        assert!(rx.try_recv().is_err());
        assert!(app.clone_draft.is_none());
        assert!(app.wizard_draft.is_none());
        app.open_peer_route_view(PeerRouteDirection::Advertised);
        assert!(rx.try_recv().is_err());
        assert!(app.peer_route_view.as_ref().unwrap().error.is_some());
    }

    #[test]
    fn mikrotik_cache_initial_manual_timed_retry_record_before_dispatch() {
        let (mut app, mut rx) = app();
        let id = Uuid::nil();
        let mut previous = Uuid::nil();
        for phase in 0..4 {
            match phase {
                0 => app.request_refresh_ids(vec![id]),
                1 => app.request_refresh_selected(),
                2 => {
                    app.router_status.insert(id, ConnectionStatus::Connected);
                    app.native_refresh_tick = 149;
                    app.tick();
                }
                _ => {
                    app.router_status.insert(id, ConnectionStatus::Disconnected);
                    app.handle_ping_result(id, Some(std::time::Duration::from_millis(1)));
                }
            }
            let FetchRequest::RefreshMikroTik {
                router_id,
                request,
                instance,
            } = rx.try_recv().unwrap()
            else {
                panic!("native must not use generic refresh")
            };
            assert_eq!(router_id, id);
            assert_eq!(instance.as_deref(), Some("blue"));
            assert_ne!(request, previous);
            assert_eq!(app.native_cache[&id].latest_request, request);
            let mut stale = documented_snapshot();
            stale.request = previous;
            app.handle_native_data(id, previous, NativeDiscovery::Snapshot(stale));
            assert!(app.native_cache[&id].snapshot.is_none());
            previous = request;
            // Each phase represents a completed worker request; explicit
            // supersession while outstanding is covered separately.
            app.handle_native_error(id, request, "synthetic terminal completion".into());
        }
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn mikrotik_cache_scope_endpoint_switch_and_delete_invalidate_before_controls() {
        let (mut app, mut rx) = app();
        let id = Uuid::nil();
        app.request_native_refresh(id);
        rx.try_recv().unwrap();
        let old_request = app.native_cache[&id].latest_request;
        deliver(&mut app, documented_snapshot());
        app.editor_start_edit();
        let draft = app.editor_draft.as_mut().unwrap();
        draft.hostname = "replacement.invalid".into();
        app.editor_field = 7;
        app.editor_buf = "red".into();
        app.editor_commit_and_advance();
        let FetchRequest::UpdateNativeRegistration(config) = rx.try_recv().unwrap() else {
            panic!("registration must precede refresh")
        };
        assert_eq!(config.hostname, "replacement.invalid");
        assert_eq!(config.mikrotik_instance.as_deref(), Some("red"));
        assert!(app.native_view.is_none());
        assert!(app.native_cache[&id].snapshot.is_none());
        let FetchRequest::RefreshMikroTik {
            request, instance, ..
        } = rx.try_recv().unwrap()
        else {
            panic!("tracked refresh required")
        };
        assert_eq!(instance.as_deref(), Some("red"));
        assert_ne!(request, old_request);
        let lines = app.config_lines.clone();
        let mut old = documented_snapshot();
        old.request = old_request;
        app.handle_native_data(id, old_request, NativeDiscovery::Snapshot(old));
        app.handle_native_error(id, old_request, "old endpoint error".into());
        assert_eq!(app.config_lines, lines);
        assert!(app.native_cache[&id].stale_reason.is_none());
        // Even a matching request cannot change the declared source scope/endpoint.
        let mut wrong = documented_snapshot();
        wrong.request = request;
        app.handle_native_data(id, request, NativeDiscovery::Snapshot(wrong));
        assert!(app.native_cache[&id].snapshot.is_none());
        app.editor_delete_selected();
        assert!(
            matches!(rx.try_recv().unwrap(), FetchRequest::RemoveNativeRegistration(removed) if removed == id)
        );
        assert!(!app.native_cache.contains_key(&id));
        app.handle_native_error(id, request, "deleted".into());
        assert!(app.current_summary.is_none());
    }

    #[test]
    fn mikrotik_cache_vendor_switch_and_import_order_registration_controls() {
        let (mut app, mut rx) = app();
        let id = Uuid::nil();
        app.request_native_refresh(id);
        rx.try_recv().unwrap();
        deliver(&mut app, documented_snapshot());
        app.editor_start_edit();
        app.editor_draft.as_mut().unwrap().vendor = RouterVendor::Cisco;
        app.editor_field = 6;
        app.editor_buf.clear();
        app.editor_commit_and_advance();
        assert!(
            matches!(rx.try_recv().unwrap(), FetchRequest::UpdateNativeRegistration(config) if config.vendor == RouterVendor::Cisco)
        );
        assert!(
            matches!(rx.try_recv().unwrap(), FetchRequest::RefreshMany(ids) if ids == vec![id])
        );
        assert!(app.native_view.is_none());
        assert!(!app.native_cache.contains_key(&id));
        let json = r#"{"version":"test","routers":[{"name":"imported-native","hostname":"import.invalid","vendor":"mIkRoTiK","ssh_port":2222,"username":"tester","local_as":null,"vdom":null,"mikrotik_instance":"green"}],"projects":[],"neighbors":[],"peer_templates":[]}"#;
        app.import_config(json).unwrap();
        let FetchRequest::UpdateNativeRegistration(config) = rx.try_recv().unwrap() else {
            panic!("import registration first")
        };
        assert_eq!(config.vendor, RouterVendor::MikroTik);
        assert_eq!(config.mikrotik_instance.as_deref(), Some("green"));
        assert!(
            matches!(rx.try_recv().unwrap(), FetchRequest::RefreshMikroTik { router_id, request, .. }
            if router_id == config.id && request == app.native_cache[&config.id].latest_request)
        );
        assert_eq!(app.router_db.as_ref().unwrap().load_all().unwrap().len(), 2);
    }

    #[test]
    fn mikrotik_cache_partial_import_still_registers_each_persisted_native_router() {
        let (mut app, mut rx) = app();
        app.router_db.as_ref().unwrap().conn.execute_batch(
            "CREATE TRIGGER reject_project BEFORE INSERT ON projects BEGIN SELECT RAISE(ABORT, 'synthetic import failure'); END;"
        ).unwrap();
        let json = r#"{"version":"test","routers":[{"name":"partial-native","hostname":"import.invalid","vendor":"MikroTik","ssh_port":22,"username":"tester","local_as":null,"vdom":null,"mikrotik_instance":"blue"}],"projects":[{"name":"rejected","router_names":["partial-native"]}],"neighbors":[],"peer_templates":[]}"#;
        assert!(app.import_config(json).is_err());
        assert_eq!(app.router_db.as_ref().unwrap().load_all().unwrap().len(), 1);
        let FetchRequest::UpdateNativeRegistration(config) = rx.try_recv().expect(
            "persisted native registration control required even if a later import step fails",
        ) else {
            panic!("ordered native registration")
        };
        assert!(
            matches!(rx.try_recv().unwrap(), FetchRequest::RefreshMikroTik { router_id, .. } if router_id == config.id)
        );
    }

    #[test]
    fn mikrotik_cache_optional_rib_failure_keeps_last_good_routes_stale() {
        let (mut app, mut rx) = app();
        app.request_native_refresh(Uuid::nil());
        rx.try_recv().unwrap();
        deliver(&mut app, documented_snapshot());
        let routes = app.current_routes.clone();
        let mut new = documented_snapshot();
        new.routes = NativeRead::Unavailable("native route budget exceeded".into());
        app.request_native_refresh(Uuid::nil());
        deliver(&mut app, new);
        assert_eq!(app.current_routes, routes);
        assert_eq!(app.bgp_cache[&Uuid::nil()].routes, routes);
        assert!(app.native_cache[&Uuid::nil()]
            .stale_reason
            .as_deref()
            .unwrap()
            .contains("stale"));
        assert!(app
            .config_lines
            .iter()
            .any(|line| line.contains("unavailable")));
        assert!(app.peer_state_history.is_empty());
        assert!(app.peer_down_alert_tick.is_none());
    }

    #[test]
    fn mikrotik_cache_displayed_source_not_latest_metadata_drives_drilldown() {
        let (mut app, mut rx) = app();
        let id = Uuid::nil();
        app.request_native_refresh(id);
        rx.try_recv().unwrap();
        deliver(&mut app, documented_snapshot());
        let displayed = Arc::clone(&app.native_view.as_ref().unwrap().snapshot);
        app.current_tab = ActiveTab::Config;
        app.request_native_refresh(id);
        rx.try_recv().unwrap();
        deliver(&mut app, documented_snapshot());
        assert_ne!(
            app.native_cache[&id].snapshot.as_ref().unwrap().generation,
            displayed.generation
        );
        app.open_peer_route_view(PeerRouteDirection::Received);
        let FetchRequest::FetchNativeRoutes { request, source } = rx.try_recv().unwrap() else {
            panic!("typed context required")
        };
        assert!(Arc::ptr_eq(&source, &displayed));
        assert_eq!(request.registration, displayed.registration);
        assert_eq!(request.generation, displayed.generation);
        assert_eq!(
            request.peer,
            PeerKey::RouterOsConnection {
                instance: "blue".into(),
                name: "peer-a".into()
            }
        );
        app.handle_native_routes(request, NativeRead::Available(vec![]));
        assert!(app.peer_route_view.as_ref().unwrap().routes.is_none());
        assert!(app
            .peer_route_view
            .as_ref()
            .unwrap()
            .error
            .as_deref()
            .unwrap()
            .contains("stale"));
    }

    #[test]
    fn mikrotik_cache_legacy_refresh_remains_single_router_dispatch() {
        let (mut app, mut rx) = app();
        app.routers[0].vendor = RouterVendor::Cisco;
        app.all_routers[0].vendor = RouterVendor::Cisco;
        app.request_refresh_selected();
        assert!(matches!(rx.try_recv().unwrap(), FetchRequest::RefreshRouter(id) if id.is_nil()));
        assert!(app.native_cache.is_empty());
    }

    #[test]
    fn mikrotik_cache_navigation_keys_and_native_rejections_send_no_ssh() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let (mut app, mut rx) = app();
        app.request_native_refresh(Uuid::nil());
        rx.try_recv().unwrap();
        deliver(&mut app, documented_snapshot());
        for key in ['1', '2', '3', '4', '5', '6', '7'] {
            crate::app::handle_key(
                &mut app,
                KeyEvent::new(KeyCode::Char(key), KeyModifiers::NONE),
            );
            app.tick();
            assert!(
                rx.try_recv().is_err(),
                "navigation key {key} must be cache-only"
            );
        }
        app.current_tab = ActiveTab::Peers;
        crate::app::handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE),
        );
        assert!(app
            .current_peers
            .iter()
            .all(|peer| peer.mtu_probe.is_none()));
        app.wizard_open_edit("192.0.2.2".into());
        app.wizard_open_delete("192.0.2.2".into());
        app.open_routemap_editor("blue-in");
        app.open_prefixlist_editor("existing");
        app.open_communitylist_editor("existing");
        app.apply_template_to_draft(0);
        assert!(app.wizard_draft.is_none());
        assert_eq!(app.wizard_mode, super::super::WizardMode::Closed);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn mikrotik_cache_legacy_tab_navigation_does_not_accelerate_native_refresh() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let (mut app, mut rx) = app();
        let legacy = RouterConfig {
            name: "legacy".into(),
            ..RouterConfig::default()
        };
        let legacy_id = legacy.id;
        app.routers.push(legacy.clone());
        app.all_routers.push(legacy);
        app.router_status
            .insert(Uuid::nil(), ConnectionStatus::Connected);
        app.router_status
            .insert(legacy_id, ConnectionStatus::Connected);
        app.router_list_state.select(Some(1));
        app.reload_selected_router();
        crate::app::handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE),
        );
        app.tick();
        let mut legacy_refreshed = false;
        while let Ok(request) = rx.try_recv() {
            match request {
                FetchRequest::RefreshMikroTik { .. } => {
                    panic!("legacy navigation must not accelerate native I/O")
                }
                FetchRequest::RefreshMany(ids) => {
                    assert_eq!(ids, vec![legacy_id]);
                    legacy_refreshed = true;
                }
                _ => {}
            }
        }
        assert!(legacy_refreshed);
        assert!(app.native_cache.is_empty());
    }

    #[test]
    fn mikrotik_cache_discovery_is_typed_and_never_selects_first_instance() {
        let (mut app, mut rx) = app();
        app.routers[0].mikrotik_instance = None;
        app.all_routers[0].mikrotik_instance = None;
        app.request_native_refresh(Uuid::nil());
        let FetchRequest::RefreshMikroTik {
            request, instance, ..
        } = rx.try_recv().unwrap()
        else {
            panic!("native discovery")
        };
        assert_eq!(instance, None);
        app.handle_native_data(
            Uuid::nil(),
            request,
            NativeDiscovery::Instances {
                router_id: Uuid::nil(),
                registration: documented_registration(),
                request,
                names: vec!["blue\u{1b}[2J".into(), "green".into()],
            },
        );
        assert!(app.current_summary.is_none());
        assert!(app.routers[0].mikrotik_instance.is_none());
        assert!(app.config_lines.iter().any(|line| line.contains("green")));
        assert!(app.config_lines.iter().all(|line| !line.contains('\u{1b}')));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn mikrotik_cache_blank_exported_scope_is_discovery_only() {
        let (mut app, mut rx) = app();
        for blank in ["", "  "] {
            app.routers[0].mikrotik_instance = Some(blank.into());
            app.all_routers[0].mikrotik_instance = Some(blank.into());
            app.request_native_refresh(Uuid::nil());
            let FetchRequest::RefreshMikroTik {
                request, instance, ..
            } = rx.try_recv().unwrap()
            else {
                panic!("typed discovery")
            };
            assert!(instance.is_none());
            app.handle_native_data(
                Uuid::nil(),
                request,
                NativeDiscovery::Instances {
                    router_id: Uuid::nil(),
                    registration: documented_registration(),
                    request,
                    names: vec!["blue".into()],
                },
            );
            assert_eq!(
                app.native_cache[&Uuid::nil()]
                    .discovered_instances
                    .as_ref()
                    .unwrap(),
                &vec!["blue".to_owned()]
            );
        }
    }

    #[test]
    fn mikrotik_export_editor_vendor_cycle_and_instance_field_are_independent() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let (mut app, _) = app();
        app.current_tab = ActiveTab::Routers;
        app.editor_start_add();
        app.editor_field = 5;
        for name in [
            "VyOs",
            "Cumulus",
            "CitrixVpx",
            "PfSense",
            "FortiGate",
            "A10",
            "MikroTik",
            "Cisco",
        ] {
            crate::app::handle_key(
                &mut app,
                KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
            );
            assert_eq!(app.editor_buf, name);
        }
        let mut config = RouterConfig {
            vendor: RouterVendor::MikroTik,
            vdom: Some("root".into()),
            ..RouterConfig::default()
        };
        crate::app::apply_buf_to_draft(&mut config, 7, "blue");
        assert_eq!(config.mikrotik_instance.as_deref(), Some("blue"));
        assert_eq!(config.vdom.as_deref(), Some("root"));
        config.vendor = RouterVendor::FortiGate;
        crate::app::apply_buf_to_draft(&mut config, 7, "not-applicable");
        assert_eq!(config.mikrotik_instance.as_deref(), Some("blue"));
        assert_eq!(crate::app::editor_field_value(&config, 7), "");
    }
}
