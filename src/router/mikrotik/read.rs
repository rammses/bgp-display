//! Documentation-modeled RouterOS 7.24 programs, not observed target transcripts.
//! Only the request UUID is executable input. All selected-scope associations
//! happen client-side against the actual all-device inventory.

use super::{
    config_guard, connection_scope, require_target_version, ros_string, ConfigGuard,
    MikroTikSnapshot, NativeConnectionRef, NativeDiscovery, NativeInventory, NativePeerRow,
    NativeRead, NativeRecord, Properties, ScopeEligibility,
};
use crate::ssh::{NativeCommand, NativeCommandKind, NativeExecutor, NativeRegistration};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeMenu {
    Version,
    Instances,
    Connections,
    Templates,
    Sessions,
    Rules,
    Routes,
    Advertisements,
}

// S4: versioned 7.24 Scripting (foreach, ->, local :set, array concatenation,
// serialize) and CLI Reference (as-value). No API .proplist assumption. S5/S6/S7
// supply the property names below. Projection occurs ON DEVICE, before the
// envelope is serialized: no connection dictionary (including MD5) goes on wire.
// :set assigns only local script variables, never RouterOS configuration.
const CONFIG_FIELDS: &[&str] = &[
    ".id",
    "name",
    "comment",
    "disabled",
    "inactive",
    "dynamic",
    "instance",
    "remote.address",
    "remote.port",
    "remote.as",
    "remote.ttl",
    "remote.allowed-as",
    "local.address",
    "local.default-address",
    "local.port",
    "local.ttl",
    "local.role",
    "connect",
    "listen",
    "routing-table",
    "vrf",
    "templates",
    "as",
    "nexthop-choice",
    "multihop",
    "hold-time",
    "keepalive-time",
    "afi",
    "cisco-vpls-nlri-len-fmt",
    "use-bfd",
    "output.remove-private-as",
    "output.as-override",
    "output.add-path",
    "output.affinity",
    "output.redistribute",
    "output.filter-select",
    "output.filter-chain",
    "output.network",
    "output.network-blackhole",
    "output.default-originate",
    "output.default-prepend",
    "output.no-client-to-client-reflection",
    "output.no-early-cut",
    "input.add-path",
    "input.attr-error-handling",
    "input.affinity",
    "input.filter",
    "input.filter-nlri",
    "input.allow-as",
    "input.accept-nlri",
    "input.filter-communities",
    "input.filter-ext-communities",
    "input.filter-large-communities",
    "input.filter-unknown",
    "input.limit-process-routes-ipv4",
    "input.limit-process-routes-ipv6",
];
const SESSION_FIELDS: &[&str] = &[
    ".id",
    "name",
    "instance",
    "established",
    "remote.address",
    "remote.port",
    "remote.as",
    "remote.id",
    "remote.refused-cap-opt",
    "remote.capabilities",
    "remote.afi",
    "remote.role",
    "remote.hold-time",
    "remote.messages",
    "remote.bytes",
    "remote.eor",
    "remote.gr-restart",
    "remote.gr-time",
    "remote.gr-afi",
    "remote.gr-afi-fwp",
    "local.role",
    "local.address",
    "local.port",
    "local.as",
    "local.id",
    "local.cluster-id",
    "local.capabilities",
    "local.afi",
    "local.messages",
    "local.bytes",
    "local.eor",
    "input.procid",
    "output.procid",
    "input.last-notification",
    "output.last-notification",
    "input.filter",
    "output.filter-chain",
    "output.filter-select",
    "vrf",
    "routing-table",
    "ibgp",
    "ebgp",
    "limit-exceeded",
    "stopped",
    "hold-time",
    "keepalive-time",
    "use-bfd",
    "uptime",
    "last-started",
    "last-stopped",
    "prefix-count",
    "keepalive-timer",
    "restart-timer",
];
const ROUTE_FIELDS: &[&str] = &[
    ".id",
    "afi",
    "contribution",
    "dst-address",
    "routing-table",
    "gateway",
    "immediate-gw",
    "distance",
    "scope",
    "target-scope",
    "belongs-to",
    "local-address",
    "rpki",
    "bgp.session",
    "bgp.as-path",
    "bgp.aggregator",
    "bgp.cluster-list",
    "bgp.communities",
    "bgp.ext-communities",
    "bgp.large-communities",
    "bgp.unknown",
    "bgp.originator-id",
    "bgp.nexthop",
    "bgp.out-nexthop",
    "bgp.weight",
    "bgp.local-pref",
    "bgp.igp-metric",
    "bgp.med",
    "bgp.atomic-aggregate",
    "bgp.origin",
    "bgp.esi",
    "bgp.otc",
    "route-distinguisher",
    "disabled",
    "filtered",
    "unreachable",
    "active",
    "bgp",
    "bgp-net",
    "ecmp",
    "blackhole",
    "copy",
    "hw-offloaded",
    "connect",
    "static",
    "rip",
    "ospf",
    "isis",
    "dhcp",
    "vpn",
    "modem",
    "ldp-address",
    "ldp-mapping",
    "slaac",
    "bgp-mpls-vpn",
    "evpn",
];

impl NativeMenu {
    fn label(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Instances => "instances",
            Self::Connections => "connections",
            Self::Templates => "templates",
            Self::Sessions => "sessions",
            Self::Rules => "rules",
            Self::Routes => "routes",
            Self::Advertisements => "advertisements",
        }
    }

    fn selection(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Self::Version => ("", &[]),
            Self::Instances => (
                "/routing/bgp/instance/print as-value detail",
                &[
                    ".id",
                    "name",
                    "comment",
                    "disabled",
                    "inactive",
                    "routing-table",
                    "vrf",
                    "router-id",
                    "as",
                    "cluster-id",
                    "ignore-as-path-len",
                    "multipath",
                ],
            ),
            Self::Connections => (
                "/routing/bgp/connection/print as-value detail",
                CONFIG_FIELDS,
            ),
            Self::Templates => ("/routing/bgp/template/print as-value detail", CONFIG_FIELDS),
            Self::Sessions => ("/routing/bgp/session/print as-value detail", SESSION_FIELDS),
            Self::Rules => (
                "/routing/filter/rule/print as-value detail",
                &[".id", "chain", "rule", "comment", "disabled", "inactive"],
            ),
            Self::Routes => (
                "/routing/route/print as-value detail where routing-table=\"main\"",
                ROUTE_FIELDS,
            ),
            Self::Advertisements => (
                "/routing/bgp/advertisements/print as-value detail",
                &[
                    ".id",
                    "peer",
                    "dst",
                    "afi",
                    "local-pref",
                    "med",
                    "nexthop",
                    "nlri",
                    "withdrawn",
                    "origin",
                    "as-path",
                    "as4-path",
                    "communities",
                    "ext-communities",
                    "large-communities",
                    "atomic-aggregate",
                    "aggregator",
                    "as4-aggregator",
                    "originator-id",
                    "cluster-list",
                    "igp-metric",
                    "otc",
                ],
            ),
        }
    }
}

fn read_script(request: Uuid, menu: NativeMenu) -> String {
    let request = ros_string(&request.to_string());
    let (prefix, data) = if menu == NativeMenu::Version {
        (String::new(), "[/system/resource/get version]")
    } else {
        let (command, fields) = menu.selection();
        let keys = fields
            .iter()
            .map(|key| ros_string(key))
            .collect::<Vec<_>>()
            .join(";");
        (format!(
            ":local mtdata [:toarray \"\"]; :foreach mtrow in=[{command}] do={{ :local mtitem [:toarray \"\"]; :foreach mtkey,mtvalue in=$mtrow do={{ :foreach mtallowed in={{{keys}}} do={{ :if ($mtkey=$mtallowed) do={{ :set ($mtitem->$mtkey) $mtvalue }} }} }}; :set mtdata ($mtdata,{{$mtitem}}) }}; "
        ), "$mtdata")
    };
    format!("{prefix}:local mtresult {{\"request\"={request};\"ok\"=true;\"data\"={data}}}; :put [:serialize value=$mtresult to=json options=json.no-string-conversion]")
}

pub fn native_read_command(request: Uuid, menu: NativeMenu) -> Result<NativeCommand> {
    NativeCommand::checked(
        request,
        menu.label(),
        NativeCommandKind::Read,
        read_script(request, menu),
    )
}

fn text<'a>(record: &'a NativeRecord, key: &str) -> Option<&'a str> {
    record
        .props
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn required_text<'a>(record: &'a NativeRecord, key: &str) -> Result<&'a str> {
    text(record, key).context("missing or invalid native identity/scope field")
}

fn flag(record: &NativeRecord, key: &str) -> Option<bool> {
    match record.props.get(key) {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::String(value)) if value == "true" || value == "yes" => Some(true),
        Some(Value::String(value)) if value == "false" || value == "no" => Some(false),
        _ => None,
    }
}

fn validate_records(records: &[NativeRecord], fields: &[&str], identity: &[&str]) -> Result<()> {
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for record in records {
        ensure!(
            !record.id.trim().is_empty() && !record.props.contains_key(".id"),
            "invalid native item identity"
        );
        ensure!(ids.insert(&record.id), "duplicate native item identity");
        for key in fields {
            required_text(record, key)?;
        }
        if !identity.is_empty() {
            let identity = identity
                .iter()
                .map(|key| required_text(record, key))
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                names.insert(identity),
                "duplicate native configuration identity"
            );
        }
    }
    Ok(())
}

fn instance_eligible(instance: &NativeRecord) -> Result<()> {
    for key in ["disabled", "inactive"] {
        if instance.props.contains_key(key) {
            ensure!(
                flag(instance, key) == Some(false),
                "selected native instance is unusable or state is unknown"
            );
        }
    }
    for key in ["routing-table", "vrf"] {
        if instance.props.contains_key(key) {
            ensure!(
                text(instance, key) == Some("main"),
                "selected native instance is not effective main"
            );
        }
    }
    Ok(())
}

fn validate_selected<'a>(inv: &'a NativeInventory, selected: &str) -> Result<&'a NativeRecord> {
    require_target_version(&inv.version)?;
    validate_records(&inv.instances, &["name"], &["name"])?;
    ensure!(
        !selected.trim().is_empty(),
        "an existing BGP instance must be explicitly selected"
    );
    let instance = inv
        .instances
        .iter()
        .find(|row| text(row, "name") == Some(selected))
        .context(
            "selected native instance is unavailable; explicitly select an existing main instance",
        )?;
    instance_eligible(instance)?;
    Ok(instance)
}

fn validate_inventory(inv: &NativeInventory, selected: &str) -> Result<()> {
    validate_selected(inv, selected)?;
    validate_records(
        &inv.connections,
        &["name", "instance", "local.role"],
        &["instance", "name"],
    )?;
    validate_records(&inv.templates, &["name"], &["name"])?;
    validate_records(&inv.sessions, &["name", "instance"], &[])?;
    validate_records(&inv.rules, &["chain", "rule"], &[])?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct Endpoint {
    address: IpAddr,
    zone: Option<String>,
}

fn endpoint(value: &str) -> Option<Endpoint> {
    let (address, zone) = value
        .split_once('%')
        .map_or((value, None), |(ip, zone)| (ip, Some(zone)));
    let address = address.parse::<IpAddr>().ok()?;
    if zone.is_some_and(|zone| zone.is_empty() || zone.contains(['%', '@', '/', ' '])) {
        return None;
    }
    // No loss of IPv6 zone qualifiers, no interface-name/VRF/subnet coercion.
    if address.is_ipv4() && zone.is_some() {
        return None;
    }
    if matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local()) && zone.is_none() {
        return None;
    }
    Some(Endpoint {
        address,
        zone: zone.map(str::to_owned),
    })
}

fn asn(value: &Value) -> Option<u32> {
    match value {
        Value::Number(number) => u32::try_from(number.as_u64()?).ok(),
        Value::String(value) => {
            if let Some((high, low)) = value.split_once('.') {
                let high = high.parse::<u16>().ok()?;
                let low = low.parse::<u16>().ok()?;
                Some((u32::from(high) << 16) | u32::from(low))
            } else {
                value.parse().ok()
            }
        }
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Match {
    No,
    Possible,
    Proven,
}

fn template_refs(record: &NativeRecord) -> Result<Vec<&str>> {
    let names = match record.props.get("templates") {
        None => Vec::new(),
        Some(Value::String(names)) => names.split(',').collect(),
        Some(Value::Array(names)) => names
            .iter()
            .map(|name| {
                name.as_str()
                    .context("native template references unreadable")
            })
            .collect::<Result<Vec<_>>>()?,
        _ => anyhow::bail!("native template references unreadable"),
    };
    ensure!(
        names.iter().all(|name| !name.trim().is_empty()),
        "empty native template reference"
    );
    Ok(names)
}

fn inherit_as(
    record: &NativeRecord,
    resolved: &BTreeMap<&str, Option<u32>>,
) -> Result<Option<u32>> {
    let mut inherited = None;
    for name in template_refs(record)? {
        if let Some(value) = resolved
            .get(name)
            .context("native AS template unavailable")?
        {
            ensure!(
                inherited.is_none_or(|prior| prior == *value),
                "conflicting inherited native AS"
            );
            inherited = Some(*value);
        }
    }
    if let Some(value) = record.props.get("as") {
        return Ok(Some(asn(value).context("effective native AS unreadable")?));
    }
    Ok(inherited)
}

fn effective_local_as(inv: &NativeInventory, connection: &NativeRecord) -> Result<Option<u32>> {
    let templates = inv
        .templates
        .iter()
        .map(|row| Ok((required_text(row, "name")?, row)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut pending = template_refs(connection)?
        .into_iter()
        .map(|name| (name, false))
        .collect::<Vec<_>>();
    let mut visiting = BTreeSet::new();
    let mut resolved = BTreeMap::new();
    while let Some((name, exiting)) = pending.pop() {
        let template = templates
            .get(name)
            .context("native AS template unavailable")?;
        if exiting {
            resolved.insert(name, inherit_as(template, &resolved)?);
            visiting.remove(name);
        } else if !resolved.contains_key(name) {
            ensure!(visiting.insert(name), "cyclic native AS templates");
            pending.push((name, true));
            for parent in template_refs(template)? {
                pending.push((parent, false));
            }
        }
    }
    if let Some(value) = inherit_as(connection, &resolved)? {
        return Ok(Some(value));
    }
    let instance = inv
        .instances
        .iter()
        .find(|instance| text(instance, "name") == text(connection, "instance"))
        .context("native AS instance unavailable")?;
    instance
        .props
        .get("as")
        .map(|value| asn(value).context("native instance AS unreadable"))
        .transpose()
}

fn session_endpoints_match(connection: &NativeRecord, session: &NativeRecord) -> Match {
    if text(connection, "instance") != text(session, "instance") {
        return Match::No;
    }
    let mut proven = true;
    for key in ["remote.address", "local.address"] {
        let configured = text(connection, key)
            .or_else(|| {
                if key == "local.address" {
                    text(connection, "local.default-address")
                } else {
                    None
                }
            })
            .and_then(endpoint);
        let observed = text(session, key).and_then(endpoint);
        match (configured, observed) {
            (Some(left), Some(right)) if left != right => return Match::No,
            (Some(_), Some(_)) => (),
            _ => proven = false,
        }
    }
    if proven {
        Match::Proven
    } else {
        Match::Possible
    }
}

fn session_match(
    inv: &NativeInventory,
    connection: &NativeRecord,
    session: &NativeRecord,
) -> Match {
    let mut proven = match session_endpoints_match(connection, session) {
        Match::No => return Match::No,
        Match::Possible => false,
        Match::Proven => true,
    };
    if session.props.contains_key("local.role") {
        match text(session, "local.role") {
            Some(role) if Some(role) != text(connection, "local.role") => return Match::No,
            Some(_) => (),
            None => proven = false,
        }
    }
    match (
        connection.props.get("remote.as").and_then(asn),
        session.props.get("remote.as").and_then(asn),
    ) {
        (Some(left), Some(right)) if left != right => return Match::No,
        (Some(_), Some(_)) => (),
        _ => proven = false,
    }
    if let Some(observed) = session.props.get("local.as") {
        match (
            effective_local_as(inv, connection).ok().flatten(),
            asn(observed),
        ) {
            (Some(left), Some(right)) if left != right => return Match::No,
            (Some(_), Some(_)) => (),
            _ => proven = false,
        }
    }
    for key in ["vrf", "routing-table"] {
        if session.props.contains_key(key) && text(session, key) != Some("main") {
            proven = false;
        }
    }
    for key in ["local.port", "remote.port"] {
        if let Some(expected) = connection.props.get(key) {
            match session.props.get(key) {
                Some(observed) if observed != expected => return Match::No,
                Some(_) => (),
                None => proven = false,
            }
        }
    }
    if proven {
        Match::Proven
    } else {
        Match::Possible
    }
}

fn peer_reason(
    inv: &NativeInventory,
    record: &NativeRecord,
    scope: &ScopeEligibility,
    runtime_ambiguous: bool,
) -> Option<String> {
    if !inv.bgp_reference_inventory_complete {
        return Some("native reference inventory incomplete; editing unavailable".into());
    }
    if let ScopeEligibility::ReadOnly(reason) = scope {
        return Some(reason.clone());
    }
    if flag(record, "dynamic") != Some(false) {
        return Some("dynamic or unknown native connection kind is read-only".into());
    }
    if flag(record, "disabled").is_none() {
        return Some("native administrative state is unknown".into());
    }
    if !matches!(
        text(record, "local.role"),
        Some("ebgp" | "ibgp" | "ibgp-rr")
    ) {
        return Some("native role is unsupported for editing".into());
    }
    if text(record, "remote.address").and_then(endpoint).is_none() {
        return Some("subnet, dynamic or unresolved remote endpoint is read-only".into());
    }
    if text(record, "local.address").is_some_and(|address| endpoint(address).is_none()) {
        return Some("unnumbered or unresolved local endpoint is read-only".into());
    }
    if runtime_ambiguous {
        return Some("native session association is unavailable or ambiguous".into());
    }
    None
}

pub fn join_native_peers(
    inv: &NativeInventory,
    selected: &str,
    generation: Uuid,
) -> Result<Vec<NativePeerRow>> {
    validate_inventory(inv, selected)?;
    // Match both ways. Unknown competitors block uniqueness; neither row order
    // nor session name substrings/suffixes are connection back-links.
    let candidates = inv
        .sessions
        .iter()
        .map(|session| {
            inv.connections
                .iter()
                .enumerate()
                .map(|(index, connection)| (index, session_match(inv, connection, session)))
                .filter(|(_, evidence)| *evidence != Match::No)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let matches = candidates
        .iter()
        .map(|candidates| {
            if candidates.len() == 1 && candidates[0].1 == Match::Proven {
                Some(candidates[0].0)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let mut linked = BTreeSet::new();
    let mut rows = Vec::new();
    for (index, connection) in inv.connections.iter().enumerate() {
        let candidates = matches
            .iter()
            .enumerate()
            .filter(|(_, candidate)| **candidate == Some(index))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let possible_sessions = inv
            .sessions
            .iter()
            .filter(|session| session_match(inv, connection, session) != Match::No)
            .count();
        let session = if candidates.len() == 1 && possible_sessions == 1 {
            linked.insert(candidates[0]);
            Some(inv.sessions[candidates[0]].clone())
        } else {
            None
        };
        let scope = connection_scope(inv, selected, connection);
        // Configured identity, not a live cache, is the management target. No
        // relevant runtime evidence is different from a failed/ambiguous join;
        // same-endpoint AS/role conflicts remain relevant even when Match::No.
        let runtime_ambiguous = session.is_none()
            && inv
                .sessions
                .iter()
                .any(|runtime| session_endpoints_match(connection, runtime) != Match::No);
        let read_only_reason = peer_reason(inv, connection, &scope, runtime_ambiguous);
        rows.push(NativePeerRow {
            connection: Some(NativeConnectionRef {
                instance: required_text(connection, "instance")?.into(),
                name: required_text(connection, "name")?.into(),
                observed_id: connection.id.clone(),
                generation,
            }),
            session_id: session.as_ref().map(|session| session.id.clone()),
            record: connection.clone(),
            session,
            scope,
            read_only_reason,
        });
    }
    for (index, session) in inv.sessions.iter().enumerate() {
        if !linked.contains(&index) {
            let reason =
                "runtime-only native session; configuration association unavailable or ambiguous"
                    .to_string();
            rows.push(NativePeerRow {
                connection: None,
                session_id: Some(session.id.clone()),
                record: session.clone(),
                session: Some(session.clone()),
                scope: ScopeEligibility::ReadOnly(reason.clone()),
                read_only_reason: Some(reason),
            });
        }
    }
    Ok(rows)
}

fn sensitive(value: &Value) -> bool {
    match value {
        Value::Object(props) => props.iter().any(|(key, value)| {
            matches!(
                key.rsplit('.').next().unwrap_or(key),
                "tcp-md5-key"
                    | "password"
                    | "passphrase"
                    | "private-key"
                    | "secret"
                    | "authentication-key"
            ) || sensitive(value)
        }),
        Value::Array(values) => values.iter().any(sensitive),
        _ => false,
    }
}

fn records(data: Value) -> Result<Vec<NativeRecord>> {
    ensure!(!sensitive(&data), "unexpected sensitive native property");
    // Never attach a serde error that can include source/device text.
    serde_json::from_value::<Vec<NativeRecord>>(data)
        .map_err(|_| anyhow::anyhow!("invalid native record collection"))
}

async fn execute<E: NativeExecutor>(io: &E, request: Uuid, menu: NativeMenu) -> Result<Value> {
    io.exec(native_read_command(request, menu)?)
        .await
        .context("native read failed")
}

async fn required_records<E: NativeExecutor>(
    io: &E,
    request: Uuid,
    menu: NativeMenu,
) -> Result<Vec<NativeRecord>> {
    records(execute(io, request, menu).await?).context("cannot decode native inventory")
}

async fn references<E: NativeExecutor>(
    io: &E,
    request: Uuid,
    menu: NativeMenu,
    complete: &mut bool,
) -> Result<Vec<NativeRecord>> {
    match execute(io, request, menu).await {
        Ok(data) => records(data).context("cannot decode native reference inventory"),
        Err(_) => {
            *complete = false;
            Ok(Vec::new())
        }
    }
}

fn read_guard(inv: &NativeInventory, selected: &str) -> Result<ConfigGuard> {
    if inv.bgp_reference_inventory_complete {
        return config_guard(inv, selected);
    }
    // Not a writable guard, no fabricated complete empty reference set. This
    // marker can never equal config_guard (which errors for this inventory).
    Ok(ConfigGuard(Properties::from([
        ("bgp_reference_inventory_complete".into(), json!(false)),
        ("read_only_reason".into(), json!("native reference inventory incomplete; editing unavailable")),
        ("reference_audit_warning".into(), json!("nested script and other-protocol consumers unknown; not a complete dependency audit")),
    ])))
}

fn route_read_prerequisites(inv: &NativeInventory, peers: &[NativePeerRow]) -> Result<()> {
    ensure!(
        inv.bgp_reference_inventory_complete,
        "native route scope unresolved: reference inventory incomplete"
    );
    ensure!(
        peers.iter().any(|peer| peer.scope == ScopeEligibility::Main
            && peer.connection.is_some()
            && peer.session.is_some()),
        "native route association unavailable: no eligible linked session"
    );
    Ok(())
}

fn scoped_routes(
    data: Value,
    inv: &NativeInventory,
    peers: &[NativePeerRow],
) -> Result<Vec<NativeRecord>> {
    route_read_prerequisites(inv, peers)?;
    let routes = records(data)?;
    validate_records(&routes, &["routing-table"], &[])?;
    let mut selected = Vec::new();
    for route in routes {
        if text(&route, "routing-table") != Some("main") {
            continue;
        }
        let known_other_protocol = [
            "connect",
            "static",
            "rip",
            "ospf",
            "isis",
            "dhcp",
            "vpn",
            "modem",
            "slaac",
            "ldp-address",
            "ldp-mapping",
        ]
        .iter()
        .any(|key| flag(&route, key) == Some(true));
        // Positive other-protocol evidence may exclude a row, but neither an
        // explicit bgp=false nor an LDP flag may conceal BGP attributes or
        // mixed/unknown BGP-related flags. Copy alone proves no protocol.
        let bgp_evidence = route.props.keys().any(|key| key.starts_with("bgp."))
            || ["bgp", "bgp-net", "bgp-mpls-vpn", "evpn"]
                .iter()
                .any(|key| route.props.contains_key(*key) && flag(&route, key) != Some(false));
        ensure!(
            !bgp_evidence
                || !["ldp-address", "ldp-mapping"]
                    .iter()
                    .any(|key| flag(&route, key) == Some(true)),
            "native route protocol evidence is mixed or unresolved"
        );
        if !bgp_evidence && (flag(&route, "bgp") == Some(false) || known_other_protocol) {
            continue;
        }
        let name =
            text(&route, "bgp.session").context("native route session association unavailable")?;
        let sessions = inv
            .sessions
            .iter()
            .filter(|session| text(session, "name") == Some(name))
            .collect::<Vec<_>>();
        ensure!(
            sessions.len() == 1,
            "native route session association unavailable or ambiguous"
        );
        let peer = peers
            .iter()
            .find(|peer| peer.session_id.as_deref() == Some(sessions[0].id.as_str()))
            .context("native route session association unavailable")?;
        // Positively out-of-scope data can be excluded. Unresolved associations
        // must NOT turn into a successful empty/partial selected RIB.
        if let ScopeEligibility::ReadOnly(reason) = &peer.scope {
            if matches!(
                reason.as_str(),
                "connection belongs to another native instance"
                    | "effective connection routing table is not main"
                    | "effective connection VRF is not main"
            ) {
                continue;
            }
            anyhow::bail!("native route effective scope or session linkage unresolved");
        }
        // Monitoring needs a proven configured/session link in effective-main
        // scope, not eligibility to edit the configured administrative record.
        ensure!(
            peer.connection.is_some() && peer.session.is_some(),
            "native route effective scope or session linkage unresolved"
        );
        for key in ["routing-table", "vrf"] {
            if sessions[0].props.contains_key(key) {
                ensure!(
                    text(sessions[0], key) == Some("main"),
                    "native route session scope conflicts with selected main scope"
                );
            }
        }
        required_text(&route, "dst-address")?;
        required_text(&route, "afi")?;
        selected.push(route);
    }
    Ok(selected)
}

pub async fn fetch_native<E: NativeExecutor>(
    io: &E,
    registration: &NativeRegistration,
    request: Uuid,
    instance: Option<&str>,
) -> Result<NativeDiscovery> {
    let version = execute(io, request, NativeMenu::Version).await?;
    let version = version
        .as_str()
        .context("native installed version is unavailable")?;
    require_target_version(version)?; // No routing query before exact validation.
    let mut inventory = NativeInventory {
        version: version.into(),
        instances: required_records(io, request, NativeMenu::Instances).await?,
        connections: Vec::new(),
        templates: Vec::new(),
        sessions: Vec::new(),
        rules: Vec::new(),
        bgp_reference_inventory_complete: false,
        known_other_protocol_chains: BTreeSet::new(),
    };
    validate_records(&inventory.instances, &["name"], &["name"])?;
    let Some(instance) = instance.filter(|instance| !instance.trim().is_empty()) else {
        let mut names = inventory
            .instances
            .iter()
            .filter(|row| instance_eligible(row).is_ok())
            .map(|row| required_text(row, "name").map(str::to_owned))
            .collect::<Result<Vec<_>>>()?;
        names.sort();
        return Ok(NativeDiscovery::Instances {
            router_id: registration.router_id,
            registration: registration.clone(),
            request,
            names,
        });
    };
    validate_selected(&inventory, instance)?;
    inventory.connections = required_records(io, request, NativeMenu::Connections).await?;
    let mut complete = true;
    inventory.templates = references(io, request, NativeMenu::Templates, &mut complete).await?;
    inventory.sessions = required_records(io, request, NativeMenu::Sessions).await?;
    inventory.rules = references(io, request, NativeMenu::Rules, &mut complete).await?;
    inventory.bgp_reference_inventory_complete = complete;
    let generation = Uuid::new_v4();
    let peers = join_native_peers(&inventory, instance, generation)?;
    let guard = read_guard(&inventory, instance)?;
    let routes = match route_read_prerequisites(&inventory, &peers) {
        Err(error) => NativeRead::Unavailable(error.to_string()),
        Ok(()) => match execute(io, request, NativeMenu::Routes).await {
            Ok(data) => match scoped_routes(data, &inventory, &peers) {
                Ok(routes) => NativeRead::Available(routes),
                Err(error) => NativeRead::Unavailable(error.to_string()),
            },
            Err(_) => NativeRead::Unavailable("native stored-route read unavailable".into()),
        },
    };
    // S7 exposes a peer enum but does not establish its session-link encoding or
    // reconcile retention prerequisites. Do not treat an IP/name guess or an
    // empty response as proven association/capability, and never enable retention.
    // There is no usable decoder/association yet: do not fetch a discarded table.
    let advertisements = NativeRead::Unavailable(
        "native advertisement capability and peer/session association unproven".into(),
    );
    Ok(NativeDiscovery::Snapshot(MikroTikSnapshot {
        router_id: registration.router_id,
        registration: registration.clone(),
        request,
        generation,
        instance: instance.into(),
        inventory,
        guard,
        peers,
        routes,
        advertisements,
        fetched_at: chrono::Utc::now(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::mikrotik::test_support::{
        documented_inventory, documented_registration, record, Reply, TranscriptExecutor,
    };
    use crate::router::mikrotik::{
        config_guard, fetch_native, join_native_peers, native_read_command, MikroTikBackend,
        NativeDiscovery, NativeMenu, NativeRead, ScopeEligibility,
    };
    use serde_json::{json, Value};
    use uuid::Uuid;

    // All fixtures in this module are synthetic documentation-derived, not
    // device captures. The executor replaces only SSH, never joins/read logic.
    const INVENTORY_READS: &[&str] = &[
        "version",
        "instances",
        "connections",
        "templates",
        "sessions",
        "rules",
    ];
    const WITH_ROUTES: &[&str] = &[
        "version",
        "instances",
        "connections",
        "templates",
        "sessions",
        "rules",
        "routes",
    ];

    // Callers explicitly choose six or seven replies for their hand-built
    // fixture; no production eligibility predicate determines expectations.
    fn replies(inv: &NativeInventory, routes: Option<Reply>) -> Vec<Reply> {
        let mut replies = vec![
            Reply::Data(json!(inv.version)),
            Reply::Data(json!(inv.instances)),
            Reply::Data(json!(inv.connections)),
            Reply::Data(json!(inv.templates)),
            Reply::Data(json!(inv.sessions)),
            Reply::Data(json!(inv.rules)),
        ];
        if let Some(routes) = routes {
            replies.push(routes);
        }
        replies
    }

    async fn snapshot(
        io: &TranscriptExecutor,
        expected: &[&str],
    ) -> crate::router::mikrotik::MikroTikSnapshot {
        let snapshot = match fetch_native(
            io,
            &documented_registration(),
            Uuid::from_u128(2),
            Some("blue"),
        )
        .await
        .unwrap()
        {
            NativeDiscovery::Snapshot(snapshot) => snapshot,
            _ => panic!("selected instance must return a snapshot"),
        };
        assert_eq!(io.seen_labels(), expected);
        snapshot
    }

    #[test]
    fn mikrotik_identity_is_not_remote_ip_or_session_suffix() {
        let mut inventory = documented_inventory();
        inventory.connections[1]
            .props
            .insert("remote.address".into(), json!("192.0.2.2"));
        let rows = join_native_peers(&inventory, "blue", Uuid::nil()).unwrap();
        assert_eq!(rows.iter().filter(|r| r.connection.is_some()).count(), 2);
        assert!(rows.iter().any(|r| r.read_only_reason.is_some()));
        assert!(rows
            .iter()
            .filter(|r| r.connection.is_some())
            .all(|r| r.session.is_none()));
        assert_eq!(rows.iter().filter(|r| r.connection.is_none()).count(), 1);
    }

    #[test]
    fn mikrotik_identity_sessionless_fixed_config_is_actionable() {
        for no_sessions in [false, true] {
            let mut inv = documented_inventory();
            if no_sessions {
                inv.sessions.clear();
            }
            let generation = Uuid::from_u128(88);
            let rows = join_native_peers(&inv, "blue", generation).unwrap();
            let peer = &rows[1]; // Disabled peer-b; any peer-a cache is unrelated.
            assert_eq!(
                peer.connection,
                Some(NativeConnectionRef {
                    instance: "blue".into(),
                    name: "peer-b".into(),
                    observed_id: "*3".into(),
                    generation,
                })
            );
            assert_eq!(peer.scope, ScopeEligibility::Main);
            assert!(peer.session.is_none());
            assert!(peer.session_id.is_none());
            assert_eq!(peer.record.props["disabled"], true);
            assert_eq!(peer.record, inv.connections[1]);
            assert!(peer.read_only_reason.is_none(), "no_sessions={no_sessions}");
            assert_eq!(
                peer.connection,
                join_native_peers(&inv, "blue", generation).unwrap()[1].connection
            );
            if no_sessions {
                assert!(rows.iter().all(|row| row.connection.is_some()
                    && row.scope == ScopeEligibility::Main
                    && row.session.is_none()
                    && row.read_only_reason.is_none()));
            }
        }
    }

    #[test]
    fn mikrotik_identity_kind_requires_positive_static_evidence() {
        for sessions_present in [false, true] {
            for observed in [
                None,
                Some(json!(null)),
                Some(json!("unknown")),
                Some(json!(0)),
                Some(json!(true)),
                Some(json!(false)),
            ] {
                let mut inv = documented_inventory();
                if !sessions_present {
                    inv.sessions.clear();
                }
                match &observed {
                    Some(value) => {
                        inv.connections[0]
                            .props
                            .insert("dynamic".into(), value.clone());
                    }
                    None => {
                        inv.connections[0].props.remove("dynamic");
                    }
                }
                let rows = join_native_peers(&inv, "blue", Uuid::from_u128(88)).unwrap();
                assert_eq!(rows[0].scope, ScopeEligibility::Main);
                assert_eq!(rows[0].record, inv.connections[0]);
                assert_eq!(rows[0].connection.as_ref().unwrap().observed_id, "*2");
                assert_eq!(rows[0].session.is_some(), sessions_present);
                let static_proven = observed == Some(json!(false));
                assert_eq!(
                    rows[0].read_only_reason.is_none(),
                    static_proven,
                    "dynamic={observed:?}, sessions_present={sessions_present}"
                );
            }
        }
    }

    #[test]
    fn mikrotik_identity_conflicting_or_uncertain_runtime_is_not_absent_evidence() {
        for (key, value) in [
            ("remote.as", json!(65099)),
            ("local.as", json!(65099)),
            ("local.role", json!("ibgp")),
            ("routing-table", json!("customer")),
            ("remote.as", json!(null)),
            ("local.address", json!(null)),
        ] {
            let mut inv = documented_inventory();
            inv.sessions[0].props.insert(key.into(), value);
            let rows = join_native_peers(&inv, "blue", Uuid::nil()).unwrap();
            assert!(rows[0].session.is_none(), "{key}");
            assert!(rows[0].read_only_reason.is_some(), "{key}");
            assert!(rows
                .iter()
                .any(|row| row.connection.is_none() && row.read_only_reason.is_some()));
        }
    }

    #[test]
    fn mikrotik_identity_unique_endpoints_and_as_not_names() {
        let mut inv = documented_inventory();
        inv.connections[1]
            .props
            .insert("remote.address".into(), json!("192.0.2.2"));
        inv.connections[1]
            .props
            .insert("local.address".into(), json!("192.0.2.9"));
        inv.sessions[0]
            .props
            .insert("name".into(), json!("peer-b-999"));
        let rows = join_native_peers(&inv, "blue", Uuid::from_u128(4)).unwrap();
        assert_eq!(rows[0].session_id.as_deref(), Some("*4"));
        assert_eq!(rows[0].connection.as_ref().unwrap().name, "peer-a");
        assert_eq!(
            rows[0].connection.as_ref().unwrap().generation,
            Uuid::from_u128(4)
        );
        assert!(rows[0].read_only_reason.is_none());
        assert!(rows[1].session.is_none());
        inv.sessions[0]
            .props
            .insert("remote.as".into(), json!(65002));
        assert!(join_native_peers(&inv, "blue", Uuid::nil()).unwrap()[0]
            .session
            .is_none());
    }

    #[test]
    fn mikrotik_identity_unknown_competitor_prevents_unique_match() {
        for missing in ["local.address", "remote.as"] {
            let mut inv = documented_inventory();
            inv.connections[1]
                .props
                .insert("remote.address".into(), json!("192.0.2.2"));
            inv.connections[1].props.remove(missing);
            let rows = join_native_peers(&inv, "blue", Uuid::nil()).unwrap();
            assert!(rows
                .iter()
                .filter(|r| r.connection.is_some())
                .all(|r| r.session.is_none()));
        }
        let mut inv = documented_inventory();
        inv.connections[0].props.remove("local.address");
        assert!(join_native_peers(&inv, "blue", Uuid::nil()).unwrap()[0]
            .session
            .is_none());
        inv.connections[0]
            .props
            .insert("local.default-address".into(), json!("192.0.2.1"));
        assert!(join_native_peers(&inv, "blue", Uuid::nil()).unwrap()[0]
            .session
            .is_some());
    }

    #[test]
    fn mikrotik_identity_unknown_competing_session_blocks_both_directions() {
        let mut inv = documented_inventory();
        let mut unknown = inv.sessions[0].clone();
        unknown.id = "*CA".into();
        unknown
            .props
            .insert("name".into(), json!("unresolved-cache"));
        unknown.props.remove("local.address");
        inv.sessions.push(unknown);
        let rows = join_native_peers(&inv, "blue", Uuid::nil()).unwrap();
        assert!(rows[0].session.is_none());
        assert_eq!(
            rows.iter().filter(|row| row.connection.is_none()).count(),
            2
        );
    }

    #[test]
    fn mikrotik_identity_observed_local_as_or_scope_conflict_is_not_actionable() {
        for (key, value) in [
            ("local.as", json!(65099)),
            ("local.role", json!("ibgp")),
            ("vrf", json!("customer")),
            ("routing-table", json!("customer")),
            ("routing-table", json!(null)),
        ] {
            let mut inv = documented_inventory();
            inv.sessions[0].props.insert(key.into(), value);
            let rows = join_native_peers(&inv, "blue", Uuid::nil()).unwrap();
            assert!(rows[0].read_only_reason.is_some(), "{key}");
        }
    }

    #[test]
    fn mikrotik_identity_recursive_local_as_uses_observed_templates_not_instance_guess() {
        let mut inv = documented_inventory();
        inv.connections[0]
            .props
            .insert("templates".into(), json!(["child"]));
        inv.templates.extend([
            record(json!({".id":"*A1", "name":"child", "templates":["base"]})),
            record(json!({".id":"*A2", "name":"base", "as":65100})),
        ]);
        inv.sessions[0]
            .props
            .insert("local.as".into(), json!(65000));
        assert!(join_native_peers(&inv, "blue", Uuid::nil()).unwrap()[0]
            .session
            .is_none());
        inv.sessions[0]
            .props
            .insert("local.as".into(), json!(65100));
        assert!(join_native_peers(&inv, "blue", Uuid::nil()).unwrap()[0]
            .session
            .is_some());
    }

    #[test]
    fn mikrotik_identity_zone_qualified_ipv6_is_not_plain_ip() {
        let mut inv = documented_inventory();
        for record in [&mut inv.connections[0], &mut inv.sessions[0]] {
            record
                .props
                .insert("local.address".into(), json!("fe80::1%ether1"));
            record
                .props
                .insert("remote.address".into(), json!("fe80::2%ether1"));
        }
        let rows = join_native_peers(&inv, "blue", Uuid::nil()).unwrap();
        assert!(rows[0].session.is_some());
        assert_eq!(rows[0].record.props["remote.address"], "fe80::2%ether1");
        inv.sessions[0]
            .props
            .insert("remote.address".into(), json!("fe80::2%ether2"));
        assert!(join_native_peers(&inv, "blue", Uuid::nil()).unwrap()[0]
            .session
            .is_none());
    }

    #[test]
    fn mikrotik_identity_link_local_without_observed_zone_is_unresolved() {
        let mut inv = documented_inventory();
        for record in [&mut inv.connections[0], &mut inv.sessions[0]] {
            record
                .props
                .insert("local.address".into(), json!("fe80::1"));
            record
                .props
                .insert("remote.address".into(), json!("fe80::2"));
        }
        let rows = join_native_peers(&inv, "blue", Uuid::nil()).unwrap();
        assert!(rows[0].session.is_none());
        assert!(rows[0].read_only_reason.is_some());
    }

    #[test]
    fn mikrotik_identity_caches_runtime_only_and_unknown_flags_are_honest() {
        let mut inv = documented_inventory();
        inv.sessions[0]
            .props
            .insert("established".into(), json!(false));
        inv.sessions[0].props.insert("uptime".into(), json!("3d"));
        inv.sessions.push(record(
            json!({".id":"*9", "name":"orphan", "instance":"blue",
            "remote.address":"192.0.2.55", "local.address":"192.0.2.1", "remote.as":65001}),
        ));
        let rows = join_native_peers(&inv, "blue", Uuid::nil()).unwrap();
        assert_eq!(
            rows[0].session.as_ref().unwrap().props["established"],
            false
        );
        assert_eq!(rows[1].record.props["disabled"], true);
        assert!(rows[1].session.is_none());
        assert!(rows[2].connection.is_none());
        assert!(rows[2].read_only_reason.is_some());
        assert!(!rows[2].record.props.contains_key("established"));
        inv.sessions[0]
            .props
            .insert("established".into(), json!("unexpected"));
        let rows = join_native_peers(&inv, "blue", Uuid::nil()).unwrap();
        assert_eq!(
            rows[0].session.as_ref().unwrap().props["established"],
            "unexpected"
        );
    }

    #[test]
    fn mikrotik_identity_recreation_and_name_changes_are_snapshot_local() {
        let mut inv = documented_inventory();
        let old = join_native_peers(&inv, "blue", Uuid::from_u128(1)).unwrap()[0]
            .connection
            .clone();
        inv.connections[0]
            .props
            .insert("name".into(), json!("renamed"));
        let new = join_native_peers(&inv, "blue", Uuid::from_u128(2)).unwrap()[0]
            .connection
            .clone();
        assert_ne!(old, new);
        assert_eq!(new.unwrap().observed_id, "*2");
        inv.connections[0].id = "*20".into();
        assert_ne!(
            old,
            join_native_peers(&inv, "blue", Uuid::from_u128(1)).unwrap()[0].connection
        );
    }

    #[test]
    fn mikrotik_identity_dynamic_subnet_unnumbered_role_and_scope_are_read_only() {
        for (key, value) in [
            ("dynamic", json!(true)),
            ("remote.address", json!("192.0.2.0/24")),
            ("local.address", json!("ether1")),
            ("local.role", json!("ebgp-rs")),
            ("vrf", json!("customer")),
            ("disabled", json!("unknown")),
        ] {
            let mut inv = documented_inventory();
            inv.connections[0].props.insert(key.into(), value);
            let rows = join_native_peers(&inv, "blue", Uuid::nil()).unwrap();
            assert!(rows[0].read_only_reason.is_some(), "{key}");
        }
        // S5 unnumbered means no configured remote.address + local interface,
        // not a fixed host whose runtime address can be promoted into config.
        let mut inv = documented_inventory();
        inv.connections[0].props.remove("remote.address");
        inv.connections[0]
            .props
            .insert("local.address".into(), json!("ether1"));
        inv.connections[0]
            .props
            .insert("local.default-address".into(), json!("fe80::1%ether1"));
        inv.sessions[0]
            .props
            .insert("local.address".into(), json!("fe80::1%ether1"));
        inv.sessions[0]
            .props
            .insert("remote.address".into(), json!("fe80::2%ether1"));
        let rows = join_native_peers(&inv, "blue", Uuid::nil()).unwrap();
        assert!(rows[0].read_only_reason.is_some());
        assert!(rows[0].session.is_none());
        assert!(!rows[0].record.props.contains_key("remote.address"));
        assert!(rows.iter().any(|row| row.connection.is_none()));
    }

    #[test]
    fn mikrotik_identity_duplicate_ids_and_missing_identity_fail_closed() {
        let inv = documented_inventory();
        for menu in ["instances", "connections", "templates", "sessions", "rules"] {
            let mut inv = inv.clone();
            let records = match menu {
                "instances" => &mut inv.instances,
                "connections" => &mut inv.connections,
                "templates" => {
                    inv.templates
                        .push(record(json!({".id":"*A0", "name":"base"})));
                    &mut inv.templates
                }
                "sessions" => &mut inv.sessions,
                _ => &mut inv.rules,
            };
            records.push(records[0].clone());
            assert!(
                join_native_peers(&inv, "blue", Uuid::nil()).is_err(),
                "{menu}"
            );
        }
        for key in ["name", "instance", "local.role"] {
            let mut inv = inv.clone();
            inv.connections[0].props.remove(key);
            assert!(join_native_peers(&inv, "blue", Uuid::nil()).is_err());
        }
    }

    #[tokio::test]
    async fn mikrotik_read_order_registration_unknown_source_and_optional_failure() {
        let mut inv = documented_inventory();
        inv.connections[0].props.insert(
            "future.safe".into(),
            json!({"raw":"α\u{1b}[2J\n$", "number":"0007"}),
        );
        let io = TranscriptExecutor::new(replies(
            &inv,
            Some(Reply::Failure {
                code: "native-read-budget",
                started: true,
            }),
        ));
        let snap = snapshot(&io, WITH_ROUTES).await;
        assert_eq!(snap.registration, documented_registration());
        assert_eq!(snap.router_id, Uuid::nil());
        assert_eq!(snap.request, Uuid::from_u128(2));
        assert_ne!(snap.generation, Uuid::nil());
        assert_eq!(snap.instance, "blue");
        assert_eq!(snap.inventory.connections, inv.connections);
        assert_eq!(snap.peers[0].record.props["future.safe"]["number"], "0007");
        assert!(matches!(snap.routes, NativeRead::Unavailable(_)));
        assert!(matches!(snap.advertisements, NativeRead::Unavailable(_)));
        assert_eq!(
            io.seen_labels(),
            vec![
                "version",
                "instances",
                "connections",
                "templates",
                "sessions",
                "rules",
                "routes",
            ]
        );
        assert_eq!(io.mutation_attempts(), 0);
        assert_eq!(snap.guard, config_guard(&snap.inventory, "blue").unwrap());
    }

    #[tokio::test]
    async fn mikrotik_read_incomplete_references_preserve_views_not_action_guards() {
        for failed_index in [3, 5] {
            let inv = documented_inventory();
            let mut transcript = replies(&inv, None);
            transcript[failed_index] = Reply::Failure {
                code: "native-exit",
                started: true,
            };
            let io = TranscriptExecutor::new(transcript);
            let snap = snapshot(&io, INVENTORY_READS).await;
            assert!(!snap.inventory.bgp_reference_inventory_complete);
            assert_eq!(
                snap.peers.iter().filter(|r| r.connection.is_some()).count(),
                2
            );
            assert!(snap
                .peers
                .iter()
                .all(|r| matches!(r.scope, ScopeEligibility::ReadOnly(_))
                    && r.read_only_reason.is_some()));
            assert!(config_guard(&snap.inventory, "blue").is_err());
            assert_eq!(
                snap.guard.0.get("bgp_reference_inventory_complete"),
                Some(&json!(false))
            );
            assert!(!snap.guard.0.contains_key("connections"));
            assert!(snap.guard.0["read_only_reason"]
                .as_str()
                .unwrap()
                .contains("incomplete"));
            assert!(snap.guard.0["reference_audit_warning"]
                .as_str()
                .unwrap()
                .contains("other-protocol"));
            assert_eq!(io.mutation_attempts(), 0);
        }
    }

    fn route(session: &str, table: &str) -> Value {
        json!({".id":"*B1", "bgp.session":session, "routing-table":table,
            "dst-address":"203.0.113.0/24", "afi":"ip4", "contribution":"filtered",
            "bgp.as-path":"65001 {65002,65003} (65004 65005)", "filtered":true,
            "gateway":"192.0.2.99", "future.safe":"0001"})
    }

    #[tokio::test]
    async fn mikrotik_read_routes_require_session_and_main_not_gateway() {
        let inv = documented_inventory();
        let io = TranscriptExecutor::new(replies(
            &inv,
            Some(Reply::Data(json!([route("peer-a-1", "main")]))),
        ));
        let snap = snapshot(&io, WITH_ROUTES).await;
        let NativeRead::Available(routes) = snap.routes else {
            panic!("proven session association");
        };
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].props["afi"], "ip4");
        assert_eq!(
            routes[0].props["bgp.as-path"],
            "65001 {65002,65003} (65004 65005)"
        );
        assert_eq!(routes[0].props["contribution"], "filtered");
        assert_eq!(routes[0].props["future.safe"], "0001");
        for bad in [
            json!([route("missing", "main")]),
            json!([{".id":"*B1","routing-table":"main","gateway":"192.0.2.2"}]),
            json!({}),
            json!(null),
        ] {
            let io = TranscriptExecutor::new(replies(&inv, Some(Reply::Data(bad))));
            assert!(matches!(
                snapshot(&io, WITH_ROUTES).await.routes,
                NativeRead::Unavailable(_)
            ));
        }
    }

    #[tokio::test]
    async fn mikrotik_read_edit_readonly_does_not_hide_proven_main_routes() {
        for unsupported_role in [false, true] {
            let mut inv = documented_inventory();
            if unsupported_role {
                inv.connections[0]
                    .props
                    .insert("local.role".into(), json!("ebgp-rs"));
                inv.sessions[0]
                    .props
                    .insert("local.role".into(), json!("ebgp-rs"));
            } else {
                inv.connections[0].props.remove("disabled");
            }
            inv.sessions[0]
                .props
                .insert("routing-table".into(), json!("main"));
            inv.sessions[0].props.insert("vrf".into(), json!("main"));
            let raw = route("peer-a-1", "main");
            let io =
                TranscriptExecutor::new(replies(&inv, Some(Reply::Data(json!([raw.clone()])))));
            let snap = snapshot(&io, WITH_ROUTES).await;
            assert_eq!(snap.peers[0].scope, ScopeEligibility::Main);
            assert!(snap.peers[0].connection.is_some());
            assert_eq!(snap.peers[0].session_id.as_deref(), Some("*4"));
            assert_eq!(snap.peers[0].session, Some(inv.sessions[0].clone()));
            assert!(snap.peers[0].read_only_reason.is_some());
            let NativeRead::Available(routes) = snap.routes else {
                panic!("proven main monitoring must not depend on editing eligibility");
            };
            assert_eq!(routes, vec![record(raw)]);
            assert_eq!(
                routes[0].props["bgp.as-path"],
                "65001 {65002,65003} (65004 65005)"
            );
            assert_eq!(routes[0].props["afi"], "ip4");
            assert_eq!(routes[0].props["contribution"], "filtered");
            assert_eq!(io.mutation_attempts(), 0);
        }
    }

    #[tokio::test]
    async fn mikrotik_read_kind_unknown_keeps_proven_main_routes_visible() {
        for observed in [
            None,
            Some(json!(null)),
            Some(json!("unknown")),
            Some(json!(true)),
        ] {
            let mut inv = documented_inventory();
            match observed {
                Some(value) => {
                    inv.connections[0].props.insert("dynamic".into(), value);
                }
                None => {
                    inv.connections[0].props.remove("dynamic");
                }
            }
            let raw = route("peer-a-1", "main");
            let io =
                TranscriptExecutor::new(replies(&inv, Some(Reply::Data(json!([raw.clone()])))));
            let snap = snapshot(&io, WITH_ROUTES).await;
            assert_eq!(snap.peers[0].scope, ScopeEligibility::Main);
            assert_eq!(snap.peers[0].session_id.as_deref(), Some("*4"));
            assert!(snap.peers[0].read_only_reason.is_some());
            assert_eq!(snap.peers[0].record, inv.connections[0]);
            assert_eq!(snap.routes, NativeRead::Available(vec![record(raw)]));
            assert_eq!(io.mutation_attempts(), 0);
        }
    }

    #[tokio::test]
    async fn mikrotik_read_edit_readonly_routes_remain_available_alongside_editable_peer() {
        let mut inv = documented_inventory();
        inv.connections[0].props.remove("disabled");
        inv.sessions[0]
            .props
            .insert("routing-table".into(), json!("main"));
        inv.sessions[0].props.insert("vrf".into(), json!("main"));
        inv.sessions.push(record(
            json!({".id":"*7", "name":"peer-b-1", "instance":"blue",
            "local.address":"192.0.2.1", "remote.address":"192.0.2.3", "remote.as":65001,
            "routing-table":"main", "vrf":"main", "established":false}),
        ));
        let raw = route("peer-a-1", "main");
        let io = TranscriptExecutor::new(replies(&inv, Some(Reply::Data(json!([raw.clone()])))));
        let snap = snapshot(&io, WITH_ROUTES).await;
        assert!(snap.peers[0].read_only_reason.is_some());
        assert_eq!(snap.peers[0].scope, ScopeEligibility::Main);
        assert_eq!(snap.peers[0].session, Some(inv.sessions[0].clone()));
        assert!(snap.peers[1].read_only_reason.is_none());
        assert_eq!(snap.peers[1].scope, ScopeEligibility::Main);
        assert_eq!(snap.peers[1].session_id.as_deref(), Some("*7"));
        let NativeRead::Available(routes) = snap.routes else {
            panic!("per-route linkage must not depend on editing eligibility");
        };
        assert_eq!(routes, vec![record(raw)]);
        assert_eq!(io.mutation_attempts(), 0);
    }

    #[tokio::test]
    async fn mikrotik_read_unresolved_runtime_route_never_becomes_successful_empty_or_partial() {
        let mut inv = documented_inventory();
        inv.sessions.push(record(
            json!({".id":"*F1", "name":"orphan", "instance":"blue",
            "remote.address":"192.0.2.9", "local.address":"192.0.2.1", "remote.as":65001}),
        ));
        for data in [
            json!([route("orphan", "main")]),
            json!([
            route("peer-a-1","main"), {".id":"*F2", "bgp.session":"orphan", "routing-table":"main"}]),
        ] {
            let io = TranscriptExecutor::new(replies(&inv, Some(Reply::Data(data))));
            assert!(matches!(
                snapshot(&io, WITH_ROUTES).await.routes,
                NativeRead::Unavailable(_)
            ));
        }
    }

    #[tokio::test]
    async fn mikrotik_read_known_other_protocol_routes_do_not_invalidate_proven_bgp() {
        let inv = documented_inventory();
        let io = TranscriptExecutor::new(replies(
            &inv,
            Some(Reply::Data(json!([
                route("peer-a-1","main"), {".id":"*C", "routing-table":"main", "connect":true,
                    "dst-address":"192.0.2.0/24", "afi":"ip", "gateway":"ether1"}
            ]))),
        ));
        let NativeRead::Available(routes) = snapshot(&io, WITH_ROUTES).await.routes else {
            panic!("BGP link is proven");
        };
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].id, "*B1");
    }

    #[test]
    fn mikrotik_read_route_projection_preserves_documented_flags() {
        // S6 7.24 Flags table plus its detailed example's copy flag. This is
        // compiler evidence, not observed target serialization or wire keys.
        let script = read_script(Uuid::nil(), NativeMenu::Routes);
        for field in [
            "disabled",
            "filtered",
            "unreachable",
            "active",
            "connect",
            "static",
            "rip",
            "bgp",
            "bgp-net",
            "ospf",
            "isis",
            "dhcp",
            "vpn",
            "modem",
            "ldp-address",
            "ldp-mapping",
            "slaac",
            "bgp-mpls-vpn",
            "evpn",
            "hw-offloaded",
            "ecmp",
            "blackhole",
            "copy",
        ] {
            assert!(
                script.contains(&format!("\"{field}\"")),
                "projection drops {field}"
            );
        }
        let command = native_read_command(Uuid::nil(), NativeMenu::Routes).unwrap();
        assert_eq!(command.kind, crate::ssh::NativeCommandKind::Read);
    }

    #[tokio::test]
    async fn mikrotik_read_positive_ldp_does_not_poison_proven_bgp_rib() {
        let inv = documented_inventory();
        for field in ["ldp-address", "ldp-mapping"] {
            // Synthetic documentation-derived flag values, NOT device output.
            let mut bgp = route("peer-a-1", "main");
            bgp["disabled"] = json!(true);
            bgp["copy"] = json!(true);
            let ldp = json!({".id":"*F0", "routing-table":"main", "afi":"ip", (field):true,
                "dst-address":"192.0.2.0/24"});
            let io = TranscriptExecutor::new(replies(
                &inv,
                Some(Reply::Data(json!([bgp.clone(), ldp]))),
            ));
            let snap = snapshot(&io, WITH_ROUTES).await;
            assert_eq!(snap.routes, NativeRead::Available(vec![record(bgp)]));
            assert_eq!(io.mutation_attempts(), 0);
        }
    }

    #[tokio::test]
    async fn mikrotik_read_ldp_unknown_copy_or_bgp_conflict_stays_unavailable() {
        let inv = documented_inventory();
        for evidence in [
            json!({"ldp-address":false}),
            json!({"ldp-mapping":"unknown"}),
            json!({"copy":true}),
            json!({"ldp-address":true,"bgp":true}),
            json!({"ldp-address":true,"bgp":null}),
            json!({"ldp-mapping":true,"bgp.session":"unresolved"}),
            json!({"ldp-address":true,"bgp.session":"peer-a-1"}),
            json!({"ldp-address":true,"bgp.as-path":"65099"}),
            json!({"ldp-address":true,"bgp":false,"bgp.as-path":"65099"}),
            json!({"ldp-mapping":true,"bgp-net":true}),
            json!({"ldp-mapping":true,"bgp-net":"unknown"}),
            json!({"ldp-address":true,"bgp-mpls-vpn":true}),
            json!({"ldp-address":true,"evpn":true}),
        ] {
            let mut unresolved = evidence.clone();
            unresolved[".id"] = json!("*F0");
            unresolved["routing-table"] = json!("main");
            unresolved["dst-address"] = json!("198.51.100.0/24");
            unresolved["afi"] = json!("ip");
            let io = TranscriptExecutor::new(replies(
                &inv,
                Some(Reply::Data(json!([route("peer-a-1", "main"), unresolved]))),
            ));
            let snap = snapshot(&io, WITH_ROUTES).await;
            assert!(
                matches!(snap.routes, NativeRead::Unavailable(_)),
                "evidence={evidence}"
            );
            assert_eq!(io.mutation_attempts(), 0);
        }
    }

    #[tokio::test]
    async fn mikrotik_read_sensitive_or_malformed_required_inventory_is_rejected_without_source_errors(
    ) {
        for bad in [
            json!([{".id":"*2","name":"peer-a","tcp-md5-key":"never-log-secret"}]),
            json!([{".id":true,"name":"never-log-secret"}]),
            json!({}),
        ] {
            let inv = documented_inventory();
            let io = TranscriptExecutor::new(vec![
                Reply::Data(json!(inv.version)),
                Reply::Data(json!(inv.instances)),
                Reply::Data(bad),
            ]);
            let error = fetch_native(&io, &documented_registration(), Uuid::nil(), Some("blue"))
                .await
                .unwrap_err();
            assert!(!format!("{error:#}").contains("never-log-secret"));
            assert_eq!(
                io.seen_labels(),
                vec!["version", "instances", "connections"]
            );
        }
    }

    #[tokio::test]
    async fn mikrotik_discovery_backend_fails_before_io_when_registration_is_absent() {
        let config = crate::router::RouterConfig {
            id: Uuid::nil(),
            ..Default::default()
        };
        let backend = MikroTikBackend::new(&config, crate::ssh::SshSessionManager::new(&[]));
        let error = backend.discover(Uuid::nil(), None).await.unwrap_err();
        assert!(format!("{error:#}").contains("stale-native-registration"));
    }

    #[tokio::test]
    async fn mikrotik_read_rf2_inherited_nonmain_never_enters_selected_rib() {
        let mut inv = documented_inventory();
        inv.templates.push(record(
            json!({".id":"*A0", "name":"customer", "routing-table":"customer"}),
        ));
        inv.connections[0]
            .props
            .insert("templates".into(), json!(["customer"]));
        let io = TranscriptExecutor::new(replies(&inv, None));
        let snap = snapshot(&io, INVENTORY_READS).await;
        assert!(matches!(snap.peers[0].scope, ScopeEligibility::ReadOnly(_)));
        assert!(snap.peers[0].read_only_reason.is_some());
        assert!(!matches!(snap.routes, NativeRead::Available(ref r) if !r.is_empty()));
    }

    #[tokio::test]
    async fn mikrotik_read_rf2_mixed_inherited_scope_excludes_only_proven_other_table() {
        let mut inv = documented_inventory();
        inv.templates.push(record(
            json!({".id":"*A0", "name":"customer", "routing-table":"customer"}),
        ));
        inv.connections[1]
            .props
            .insert("templates".into(), json!("customer"));
        inv.sessions.push(record(
            json!({".id":"*7", "name":"peer-b-1", "instance":"blue",
            "local.address":"192.0.2.1", "remote.address":"192.0.2.3", "remote.as":65001,
            "established":false}),
        ));
        let mut out_of_scope = route("peer-b-1", "main");
        out_of_scope[".id"] = json!("*B2");
        let io = TranscriptExecutor::new(replies(
            &inv,
            Some(Reply::Data(json!([
                route("peer-a-1", "main"),
                out_of_scope
            ]))),
        ));
        let snap = snapshot(&io, WITH_ROUTES).await;
        assert!(matches!(snap.peers[1].scope, ScopeEligibility::ReadOnly(_)));
        let NativeRead::Available(routes) = snap.routes else {
            panic!("remaining main linkage is proven");
        };
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].props["bgp.session"], "peer-a-1");
    }

    #[tokio::test]
    async fn mikrotik_read_cached_session_and_supported_flags_keep_raw_observations() {
        let mut inv = documented_inventory();
        inv.connections[0]
            .props
            .insert("disabled".into(), json!("no"));
        inv.connections[0]
            .props
            .insert("use-bfd".into(), json!("yes"));
        inv.sessions[0]
            .props
            .insert("established".into(), json!("false"));
        inv.sessions[0].props.insert("uptime".into(), json!("3d"));
        let io = TranscriptExecutor::new(replies(
            &inv,
            Some(Reply::Data(json!([route("peer-a-1", "main")]))),
        ));
        let snap = snapshot(&io, WITH_ROUTES).await;
        assert_eq!(snap.peers[0].record.props["disabled"], "no");
        assert!(!snap.peers[0].record.props.contains_key("bfd-state"));
        assert_eq!(
            snap.peers[0].session.as_ref().unwrap().props["established"],
            "false"
        );
        assert!(matches!(snap.routes, NativeRead::Available(ref routes) if routes.len() == 1));
        assert!(matches!(snap.advertisements, NativeRead::Unavailable(_)));
        assert_eq!(io.mutation_attempts(), 0);
    }

    #[tokio::test]
    async fn mikrotik_read_registration_and_generation_are_not_reconstructed_from_inventory() {
        let inv = documented_inventory();
        let mut registration = documented_registration();
        registration.router_id = Uuid::from_u128(100);
        registration.revision = Uuid::from_u128(101);
        registration.endpoint.hostname = "other.invalid".into();
        let mut generations = BTreeSet::new();
        for _ in 0..2 {
            let io = TranscriptExecutor::new(replies(&inv, Some(Reply::Data(json!([])))));
            let NativeDiscovery::Snapshot(snap) =
                fetch_native(&io, &registration, Uuid::from_u128(102), Some("blue"))
                    .await
                    .unwrap()
            else {
                panic!("explicit selection");
            };
            assert_eq!(io.seen_labels(), WITH_ROUTES);
            assert_eq!(snap.router_id, Uuid::from_u128(100));
            assert_eq!(snap.registration, registration);
            assert_eq!(snap.request, Uuid::from_u128(102));
            assert!(generations.insert(snap.generation));
            assert!(snap
                .peers
                .iter()
                .filter_map(|row| row.connection.as_ref())
                .all(|reference| reference.generation == snap.generation));
        }
    }

    #[tokio::test]
    async fn mikrotik_read_no_unsupported_advertisement_probe() {
        let inv = documented_inventory();
        // Exactly seven replies: unsupported advertisements have no consumer,
        // so even an empty probe is forbidden rather than supplied and ignored.
        let io = TranscriptExecutor::new(replies(&inv, Some(Reply::Data(json!([])))));
        let snap = snapshot(&io, WITH_ROUTES).await;
        assert!(matches!(snap.routes, NativeRead::Available(ref routes) if routes.is_empty()));
        assert!(
            matches!(snap.advertisements, NativeRead::Unavailable(ref reason) if reason.contains("unproven"))
        );
        assert_eq!(io.mutation_attempts(), 0);
    }

    #[tokio::test]
    async fn mikrotik_read_no_unusable_rib_probe_incomplete_references() {
        for unavailable_menu in [3, 5] {
            let inv = documented_inventory();
            let mut transcript = replies(&inv, None);
            transcript[unavailable_menu] = Reply::Failure {
                code: "native-exit",
                started: true,
            };
            let io = TranscriptExecutor::new(transcript);
            let snap = snapshot(&io, INVENTORY_READS).await;
            assert!(!snap.inventory.bgp_reference_inventory_complete);
            assert!(
                matches!(snap.routes, NativeRead::Unavailable(ref reason) if reason.contains("incomplete"))
            );
            assert!(matches!(snap.advertisements, NativeRead::Unavailable(_)));
            assert_eq!(snap.inventory.connections, inv.connections);
            assert_eq!(io.mutation_attempts(), 0);
        }
    }

    #[tokio::test]
    async fn mikrotik_read_no_unusable_rib_probe_without_linked_main() {
        for case in [
            "sessionless",
            "unresolved-scope",
            "non-main",
            "runtime-only",
            "ambiguous",
        ] {
            let mut inv = documented_inventory();
            match case {
                "sessionless" => inv.sessions.clear(),
                "unresolved-scope" => {
                    inv.connections[0]
                        .props
                        .insert("templates".into(), json!(["missing"]));
                }
                "non-main" => {
                    inv.connections[0]
                        .props
                        .insert("routing-table".into(), json!("customer"));
                }
                "runtime-only" => inv.connections.clear(),
                "ambiguous" => {
                    inv.connections[1]
                        .props
                        .insert("remote.address".into(), json!("192.0.2.2"));
                }
                _ => unreachable!(),
            }
            // Six explicit inventory replies only, no unusable optional table.
            let io = TranscriptExecutor::new(replies(&inv, None));
            let snap = snapshot(&io, INVENTORY_READS).await;
            assert!(snap.inventory.bgp_reference_inventory_complete, "{case}");
            assert!(
                matches!(snap.routes, NativeRead::Unavailable(ref reason) if reason.contains("no eligible linked session")),
                "{case}"
            );
            assert!(matches!(snap.advertisements, NativeRead::Unavailable(_)));
            assert_eq!(io.mutation_attempts(), 0);
        }
    }

    #[tokio::test]
    async fn mikrotik_read_usable_rib_probe_for_linked_main_even_edit_readonly() {
        for edit_policy in ["editable", "unknown-admin", "unsupported-role"] {
            let mut inv = documented_inventory();
            match edit_policy {
                "unknown-admin" => {
                    inv.connections[0].props.remove("disabled");
                }
                "unsupported-role" => {
                    inv.connections[0]
                        .props
                        .insert("local.role".into(), json!("ebgp-rs"));
                    inv.sessions[0]
                        .props
                        .insert("local.role".into(), json!("ebgp-rs"));
                }
                _ => (),
            }
            inv.sessions[0]
                .props
                .insert("routing-table".into(), json!("main"));
            inv.sessions[0].props.insert("vrf".into(), json!("main"));
            let raw = route("peer-a-1", "main");
            let io =
                TranscriptExecutor::new(replies(&inv, Some(Reply::Data(json!([raw.clone()])))));
            let snap = snapshot(&io, WITH_ROUTES).await;
            assert_eq!(snap.peers[0].scope, ScopeEligibility::Main);
            assert_eq!(snap.peers[0].session_id.as_deref(), Some("*4"));
            assert_eq!(
                snap.peers[0].read_only_reason.is_some(),
                edit_policy != "editable"
            );
            assert_eq!(snap.routes, NativeRead::Available(vec![record(raw)]));
            assert!(matches!(snap.advertisements, NativeRead::Unavailable(_)));
            assert_eq!(io.mutation_attempts(), 0);
        }
    }

    #[tokio::test]
    async fn mikrotik_discovery_version_first_rejects_before_routing_queries() {
        for version in [
            json!("7.24.6"),
            json!("7.25"),
            json!("7.24.70"),
            json!(null),
        ] {
            let io = TranscriptExecutor::new(vec![Reply::Data(version)]);
            assert!(
                fetch_native(&io, &documented_registration(), Uuid::nil(), None)
                    .await
                    .is_err()
            );
            assert_eq!(io.seen_labels(), vec!["version"]);
        }
    }

    #[tokio::test]
    async fn mikrotik_discovery_blank_is_only_actual_eligible_candidates() {
        let mut inv = documented_inventory();
        inv.instances.extend([
            record(json!({".id":"*12", "name":"red", "routing-table":"customer"})),
            record(json!({".id":"*13", "name":"off", "disabled":true})),
            record(json!({".id":"*14", "name":"unknown", "inactive":"?"})),
        ]);
        for selected in [None, Some(""), Some("  ")] {
            let io = TranscriptExecutor::new(vec![
                Reply::Data(json!(inv.version)),
                Reply::Data(json!(inv.instances)),
            ]);
            let result = fetch_native(
                &io,
                &documented_registration(),
                Uuid::from_u128(7),
                selected,
            )
            .await
            .unwrap();
            let NativeDiscovery::Instances {
                router_id,
                registration,
                request,
                names,
            } = result
            else {
                panic!("discovery only");
            };
            assert_eq!(names, vec!["blue"]);
            assert_eq!(router_id, Uuid::nil());
            assert_eq!(registration, documented_registration());
            assert_eq!(request, Uuid::from_u128(7));
            assert_eq!(io.seen_labels(), vec!["version", "instances"]);
        }
    }

    #[tokio::test]
    async fn mikrotik_discovery_selected_missing_nonmain_unusable_or_renamed_errors() {
        for (selected, field) in [
            ("missing", None),
            ("blue", Some(("routing-table", json!("red")))),
            ("blue", Some(("vrf", json!("red")))),
            ("blue", Some(("name", json!("renamed")))),
            ("blue", Some(("disabled", json!(true)))),
            ("blue", Some(("inactive", json!("unknown")))),
        ] {
            let mut inv = documented_inventory();
            if let Some((key, value)) = field {
                inv.instances[0].props.insert(key.into(), value);
            }
            let io = TranscriptExecutor::new(vec![
                Reply::Data(json!(inv.version)),
                Reply::Data(json!(inv.instances)),
            ]);
            assert!(
                fetch_native(&io, &documented_registration(), Uuid::nil(), Some(selected))
                    .await
                    .is_err()
            );
            assert_eq!(io.seen_labels(), vec!["version", "instances"]);
        }
    }

    #[test]
    fn mikrotik_read_compiler_fixed_menus_project_before_serializing() {
        for menu in [
            NativeMenu::Version,
            NativeMenu::Instances,
            NativeMenu::Connections,
            NativeMenu::Templates,
            NativeMenu::Sessions,
            NativeMenu::Rules,
            NativeMenu::Routes,
            NativeMenu::Advertisements,
        ] {
            let script = read_script(Uuid::from_u128(99), menu);
            assert!(!script.chars().any(char::is_control));
            assert!(!script.contains(".proplist"));
            assert!(!script.contains("tcp-md5-key"));
            for forbidden in [
                "/set",
                "/add",
                "/remove",
                "/file",
                "dump-saved",
                "save-to=",
                "file-name=",
                "keep-sent-attributes=",
                " | ",
                "mtu=",
            ] {
                assert!(!script.contains(forbidden), "{forbidden}");
            }
            assert_eq!(script.matches(":serialize").count(), 1);
            assert!(script.ends_with("to=json options=json.no-string-conversion]"));
            assert!(script.contains(
                "\"request\"=\"00000000-0000-0000-0000-000000000063\";\"ok\"=true;\"data\"="
            ));
            let command = native_read_command(Uuid::from_u128(99), menu).unwrap();
            assert_eq!(command.kind, crate::ssh::NativeCommandKind::Read);
            assert_eq!(command.request, Uuid::from_u128(99));
            if menu != NativeMenu::Version {
                assert!(script.contains("/print as-value detail"));
                assert!(script.contains(":foreach"));
                assert!(script.find("$mtitem").unwrap() < script.find(":serialize").unwrap());
            }
        }
    }
}
