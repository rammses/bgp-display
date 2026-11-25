//! Fixed-menu, single-line RouterOS 7.24 commands. All operator values are data.
//! Modeled from S4/S5/S8/S9, pending authorized 7.24.7 device validation.
use crate::router::mikrotik::*;
use crate::ssh::{NativeCommand, NativeCommandKind};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use uuid::Uuid;

pub(crate) struct CompiledStep {
    pub(crate) command: NativeCommand,
    pub(crate) approved: ApprovedChange,
    pub(crate) safe_label: String,
}

pub(crate) enum ApprovedChange {
    Insert {
        collection: String,
        identity: Properties,
        required: Properties,
    },
    Patch {
        collection: String,
        id: String,
        set: Properties,
    },
    Remove {
        collection: String,
        id: String,
    },
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "approved shared delta variant; native filter compiler is Task6, not neighbor scope"
        )
    )]
    RuleOrder {
        chain: String,
        before: Vec<String>,
        after: Vec<String>,
    },
}

impl std::fmt::Debug for CompiledStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CompiledStep { [redacted] }")
    }
}

pub(crate) fn bool_value(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(v) => Some(*v),
        Value::String(v) if v == "yes" || v == "true" => Some(true),
        Value::String(v) if v == "no" || v == "false" => Some(false),
        _ => None,
    }
}

pub(crate) fn as_value(value: &Value) -> Option<u32> {
    let result = match value {
        Value::Number(n) => u32::try_from(n.as_u64()?).ok(),
        Value::String(s) => {
            if let Some((a, b)) = s.split_once('.') {
                Some((u32::from(a.parse::<u16>().ok()?) << 16) | u32::from(b.parse::<u16>().ok()?))
            } else {
                s.parse().ok()
            }
        }
        _ => None,
    };
    result.filter(|v| *v > 0)
}

// Exact integer nanoseconds; no lossy floats or arbitrary string equality.
fn decimal_ns(value: &str, unit: u128) -> Option<u128> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 9
    {
        return None;
    }
    let whole = whole.parse::<u128>().ok()?.checked_mul(unit)?;
    let part = if fraction.is_empty() {
        0
    } else {
        let numerator = fraction.parse::<u128>().ok()?.checked_mul(unit)?;
        let denominator = 10u128.pow(fraction.len() as u32);
        if numerator % denominator != 0 {
            return None;
        }
        numerator / denominator
    };
    whole.checked_add(part)
}

pub(crate) fn duration_ns(value: &str) -> Option<u128> {
    if value == "infinity" {
        return Some(0);
    }
    if value.contains(':') {
        let parts: Vec<_> = value.split(':').collect();
        if parts.len() != 3 {
            return None;
        }
        let h = decimal_ns(parts[0], 3_600_000_000_000)?;
        let m = decimal_ns(parts[1], 60_000_000_000)?;
        let s = decimal_ns(parts[2], 1_000_000_000)?;
        if m >= 3_600_000_000_000 || s >= 60_000_000_000 {
            return None;
        }
        return h.checked_add(m)?.checked_add(s);
    }
    let mut remaining = value;
    let mut total = 0u128;
    let mut previous = u128::MAX;
    while !remaining.is_empty() {
        let end = remaining
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(remaining.len());
        if end == 0 {
            return None;
        }
        let (number, suffix) = remaining.split_at(end);
        let (unit, length) = if suffix.starts_with("ms") {
            (1_000_000, 2)
        } else if suffix.starts_with("us") {
            (1_000, 2)
        } else if suffix.starts_with("ns") {
            (1, 2)
        } else {
            match suffix.chars().next() {
                Some('w') => (604_800_000_000_000, 1),
                Some('d') => (86_400_000_000_000, 1),
                Some('h') => (3_600_000_000_000, 1),
                Some('m') => (60_000_000_000, 1),
                Some('s') => (1_000_000_000, 1),
                None => (1_000_000_000, 0),
                _ => return None,
            }
        };
        if unit >= previous {
            return None;
        }
        previous = unit;
        total = total.checked_add(decimal_ns(number, unit)?)?;
        remaining = &suffix[length..];
    }
    if value.is_empty() {
        None
    } else {
        Some(total)
    }
}

fn afi_set(value: &Value) -> Option<BTreeSet<String>> {
    let values: Vec<&str> = match value {
        Value::String(s) => s.split(',').collect(),
        Value::Array(v) => v.iter().map(Value::as_str).collect::<Option<_>>()?,
        _ => return None,
    };
    if values.is_empty() || values.iter().any(|s| !matches!(*s, "ip" | "ipv6")) {
        return None;
    }
    let set = values
        .iter()
        .map(|s| (*s).to_owned())
        .collect::<BTreeSet<_>>();
    if set.len() != values.len() {
        None
    } else {
        Some(set)
    }
}

pub(crate) fn native_equal(key: &str, left: &Value, right: &Value) -> bool {
    match key {
        "disabled" | "dynamic" | "use-bfd" => bool_value(left)
            .zip(bool_value(right))
            .is_some_and(|(a, b)| a == b),
        "remote.as" | "as" => as_value(left)
            .zip(as_value(right))
            .is_some_and(|(a, b)| a == b),
        "afi" => afi_set(left)
            .zip(afi_set(right))
            .is_some_and(|(a, b)| a == b),
        "hold-time" | "keepalive-time" => left
            .as_str()
            .and_then(duration_ns)
            .zip(right.as_str().and_then(duration_ns))
            .is_some_and(|(a, b)| a == b),
        "local.address" | "remote.address" => left
            .as_str()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .zip(right.as_str().and_then(|s| s.parse::<IpAddr>().ok()))
            .is_some_and(|(a, b)| a == b),
        _ => left == right,
    }
}

fn host(address: IpAddr) -> Result<()> {
    ensure!(
        !address.is_unspecified() && !address.is_multicast(),
        "fixed unicast host address required"
    );
    ensure!(
        !matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local()),
        "zone-qualified link-local host is not supported by this form"
    );
    Ok(())
}

fn templates(record: &NativeRecord) -> Result<Vec<&str>> {
    match record.props.get("templates") {
        None => Ok(vec![]),
        Some(Value::String(v)) => Ok(v.split(',').collect()),
        Some(Value::Array(v)) => v
            .iter()
            .map(|v| v.as_str().context("unreadable template reference"))
            .collect(),
        _ => bail!("unreadable template reference"),
    }
}

// Conservative property inheritance: conflicts/cycles/unreadable parents fail
// closed rather than guessing precedence. No default is written to existing rows.
pub(crate) fn inherited_value(
    inv: &NativeInventory,
    row: &NativeRecord,
    key: &str,
) -> Result<Option<Value>> {
    let mut pending = templates(row)?
        .into_iter()
        .map(|n| (n, false))
        .collect::<Vec<_>>();
    let mut visiting = BTreeSet::new();
    let mut resolved: BTreeMap<&str, Option<Value>> = BTreeMap::new();
    while let Some((name, exiting)) = pending.pop() {
        let parents = inv
            .templates
            .iter()
            .filter(|r| r.props.get("name").and_then(Value::as_str) == Some(name))
            .collect::<Vec<_>>();
        ensure!(
            parents.len() == 1,
            "template property is unavailable or ambiguous"
        );
        let parent = parents[0];
        if exiting {
            let mut inherited: Option<Value> = None;
            for name in templates(parent)? {
                if let Some(value) = resolved
                    .get(name)
                    .context("template property unavailable")?
                {
                    ensure!(
                        inherited
                            .as_ref()
                            .is_none_or(|v| native_equal(key, v, value)),
                        "conflicting inherited property"
                    );
                    inherited = Some(value.clone());
                }
            }
            resolved.insert(name, parent.props.get(key).cloned().or(inherited));
            visiting.remove(name);
        } else if !resolved.contains_key(name) {
            ensure!(visiting.insert(name), "cyclic template properties");
            pending.push((name, true));
            for name in templates(parent)? {
                pending.push((name, false));
            }
        }
    }
    let mut result: Option<Value> = None;
    for name in templates(row)? {
        if let Some(value) = resolved
            .get(name)
            .context("template property unavailable")?
        {
            ensure!(
                result.as_ref().is_none_or(|v| native_equal(key, v, value)),
                "conflicting inherited property"
            );
            result = Some(value.clone());
        }
    }
    Ok(result)
}

pub(crate) fn target_record<'a>(
    snapshot: &'a MikroTikSnapshot,
    target: &NativeConnectionRef,
    original_generation: Uuid,
) -> Result<&'a NativeRecord> {
    ensure!(
        target.generation == original_generation && target.instance == snapshot.instance,
        "native target generation or instance changed"
    );
    let rows = join_native_peers(&snapshot.inventory, &snapshot.instance, snapshot.generation)?;
    let row = rows
        .iter()
        .find(|r| {
            r.record.id == target.observed_id
                && r.connection
                    .as_ref()
                    .is_some_and(|c| c.instance == target.instance && c.name == target.name)
        })
        .context("native target identity changed")?;
    ensure!(
        row.read_only_reason.is_none() && row.scope == ScopeEligibility::Main,
        "native target is read-only; refresh and inspect eligibility"
    );
    let record = snapshot
        .inventory
        .connections
        .iter()
        .find(|r| r.id == target.observed_id)
        .context("native target disappeared")?;
    let address = record
        .props
        .get("remote.address")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<IpAddr>().ok())
        .context("fixed host endpoint required")?;
    host(address)?;
    // Monitoring's direct-only source check is not mutation authorization.
    // Resolve the observable template source here, preserving a proven direct
    // override but rejecting unresolved/conflicting inheritance and non-hosts.
    let source = record
        .props
        .get("local.address")
        .cloned()
        .or(inherited_value(
            &snapshot.inventory,
            record,
            "local.address",
        )?);
    if let Some(source) = source {
        // Observed Null is unknown data, not an operator's optional unset intent.
        ensure!(source.is_string(), "effective native source is unreadable");
        validate_property("local.address", &source, &snapshot.inventory, record)?;
    }
    Ok(record)
}

enum BindingEffect {
    Bound(String),
    Unbound,
    Unknown,
}

fn binding_effect(inv: &NativeInventory, row: &NativeRecord, key: &str) -> BindingEffect {
    let inherited = match inherited_value(inv, row, key) {
        Ok(value) => value,
        Err(_) => return BindingEffect::Unknown,
    };
    match row.props.get(key).cloned().or(inherited) {
        // Only observable absence after resolved inheritance is the supported
        // unbound case. Null/empty/other wire representations prove nothing.
        None => BindingEffect::Unbound,
        Some(Value::String(name))
            if !name.is_empty()
                && inv.rules.iter().any(|rule| {
                    rule.props.get("chain").and_then(Value::as_str) == Some(name.as_str())
                }) =>
        {
            BindingEffect::Bound(name)
        }
        _ => BindingEffect::Unknown,
    }
}

fn role_as(inv: &NativeInventory, record: &NativeRecord) -> Result<()> {
    let local = effective_local_as(inv, record)?.context("effective local AS is unavailable")?;
    let remote = record
        .props
        .get("remote.as")
        .and_then(as_value)
        .context("explicit remote AS greater than zero required")?;
    ensure!(local > 0, "local AS must be greater than zero");
    match record.props.get("local.role").and_then(Value::as_str) {
        Some("ebgp") => ensure!(local != remote, "eBGP requires a different remote AS"),
        Some("ibgp" | "ibgp-rr") => {
            ensure!(local == remote, "iBGP requires the effective local AS")
        }
        _ => bail!("unsupported native role"),
    }
    Ok(())
}

fn validate_property(
    key: &str,
    value: &Value,
    inv: &NativeInventory,
    record: &NativeRecord,
) -> Result<()> {
    let optional = matches!(
        key,
        "local.address"
            | "hold-time"
            | "keepalive-time"
            | "nexthop-choice"
            | "use-bfd"
            | "input.filter"
            | "output.filter-chain"
    );
    ensure!(
        optional || matches!(key, "comment" | "remote.as" | "local.role" | "afi"),
        "unsupported native patch property"
    );
    if value.is_null() {
        ensure!(optional, "required native property cannot be unset");
        if let Some(inherited) = inherited_value(inv, record, key)? {
            ensure!(
                !inherited.is_null(),
                "inherited unset result is not observable"
            );
            validate_property(key, &inherited, inv, record)?;
        }
        return Ok(());
    }
    let valid = match key {
        "comment" => value.is_string(),
        "remote.as" => as_value(value).is_some(),
        "local.role" => matches!(value.as_str(), Some("ebgp" | "ibgp" | "ibgp-rr")),
        "afi" => afi_set(value).is_some(),
        "local.address" => value
            .as_str()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .is_some_and(|source| {
                host(source).is_ok()
                    && record
                        .props
                        .get("remote.address")
                        .and_then(Value::as_str)
                        .and_then(|s| s.parse::<IpAddr>().ok())
                        .is_some_and(|remote| remote.is_ipv4() == source.is_ipv4())
            }),
        "hold-time" => value
            .as_str()
            .and_then(duration_ns)
            .is_some_and(|v| v == 0 || (3_000_000_000..=65_535_000_000_000).contains(&v)),
        "keepalive-time" => value
            .as_str()
            .and_then(duration_ns)
            .is_some_and(|v| v > 0 && v <= 65_535_000_000_000),
        "nexthop-choice" => matches!(value.as_str(), Some("default" | "force-self" | "propagate")),
        "use-bfd" => bool_value(value).is_some(),
        "input.filter" | "output.filter-chain" => value.as_str().is_some_and(|s| {
            !s.is_empty()
                && inv
                    .rules
                    .iter()
                    .any(|r| r.props.get("chain").and_then(Value::as_str) == Some(s))
        }),
        _ => false,
    };
    ensure!(valid, "invalid or unsupported native property value");
    Ok(())
}

fn validate_secret(secret: &SecretChange) -> Result<()> {
    if let SecretChange::Replace(value) = secret {
        ensure!(
            !value.is_empty(),
            "Replace requires a nonempty value; use explicit Clear"
        );
    }
    Ok(())
}

pub(crate) fn chain_names(operation: Uuid) -> (String, String) {
    (
        format!("bgp-lm-in-{}", operation.simple()),
        format!("bgp-lm-out-{}", operation.simple()),
    )
}

fn new_properties(
    snapshot: &MikroTikSnapshot,
    d: &NativeConnectionDraft,
    operation: Uuid,
) -> Result<Properties> {
    ensure!(!d.name.trim().is_empty(), "connection name required");
    host(d.remote_address)?;
    let (input, output) = chain_names(operation);
    ensure!(
        !snapshot
            .inventory
            .known_other_protocol_chains
            .contains(&input)
            && !snapshot
                .inventory
                .known_other_protocol_chains
                .contains(&output),
        "generated chain name is already referenced by another protocol"
    );
    ensure!(
        !snapshot
            .inventory
            .connections
            .iter()
            .any(|r| r.props.get("name").and_then(Value::as_str) == Some(&d.name)),
        "connection name collision"
    );
    ensure!(
        !snapshot.inventory.rules.iter().any(|r| r
            .props
            .get("chain")
            .and_then(Value::as_str)
            .is_some_and(|s| s == input || s == output)),
        "generated filter chain collision"
    );
    // References to a currently empty chain still reserve its name.
    for row in snapshot
        .inventory
        .connections
        .iter()
        .chain(&snapshot.inventory.templates)
    {
        ensure!(
            ![
                "input.filter",
                "output.filter-chain",
                "output.filter-select",
                "input.filter-nlri"
            ]
            .iter()
            .any(|k| row
                .props
                .get(*k)
                .and_then(Value::as_str)
                .is_some_and(|s| s == input || s == output)),
            "generated filter chain reference collision"
        );
    }
    let mut props = Properties::from([
        ("name".into(), json!(d.name)),
        ("instance".into(), json!(snapshot.instance)),
        ("remote.address".into(), json!(d.remote_address.to_string())),
        ("remote.as".into(), json!(d.remote_as)),
        ("local.role".into(), json!(d.role)),
        ("afi".into(), json!(d.afi)),
        ("comment".into(), json!(d.comment)),
        ("routing-table".into(), json!("main")),
        ("vrf".into(), json!("main")),
        ("disabled".into(), json!(true)),
        ("input.filter".into(), json!(input)),
        ("output.filter-chain".into(), json!(output)),
    ]);
    if let Some(v) = d.source {
        props.insert("local.address".into(), json!(v.to_string()));
    }
    for (k, v) in [
        ("hold-time", &d.hold_time),
        ("keepalive-time", &d.keepalive_time),
        ("nexthop-choice", &d.nexthop_choice),
    ] {
        if let Some(v) = v {
            props.insert(k.into(), json!(v));
        }
    }
    if let Some(v) = d.use_bfd {
        props.insert("use-bfd".into(), json!(v));
    }
    let row = NativeRecord {
        id: "new".into(),
        props: props.clone(),
    };
    for key in [
        "remote.as",
        "local.role",
        "afi",
        "comment",
        "local.address",
        "hold-time",
        "keepalive-time",
        "nexthop-choice",
        "use-bfd",
    ] {
        if let Some(v) = props.get(key) {
            validate_property(key, v, &snapshot.inventory, &row)?;
        }
    }
    role_as(&snapshot.inventory, &row)?;
    validate_secret(&d.secret)?;
    Ok(props)
}

fn render_value(key: &str, value: &Value) -> Result<String> {
    let raw = match value {
        Value::String(s) => s.clone(),
        Value::Bool(b) => if *b { "yes" } else { "no" }.into(),
        Value::Number(n) => n.to_string(),
        Value::Array(_) if key == "afi" => afi_set(value)
            .context("invalid AFI")?
            .into_iter()
            .collect::<Vec<_>>()
            .join(","),
        _ => bail!("unrenderable native property"),
    };
    Ok(ros_string(&raw))
}

fn assignments(props: &Properties) -> Result<String> {
    props
        .iter()
        .map(|(key, value)| {
            if value.is_null() {
                Ok(format!("!{key}"))
            } else {
                Ok(format!("{key}={}", render_value(key, value)?))
            }
        })
        .collect::<Result<Vec<_>>>()
        .map(|p| p.join(" "))
}

fn secret_assignment(secret: &SecretChange) -> String {
    match secret {
        SecretChange::Keep => String::new(),
        SecretChange::Clear => " !tcp-md5-key".into(),
        SecretChange::Replace(v) => format!(" tcp-md5-key={}", ros_string(v)),
    }
}

fn creation_secret_assignment(secret: &SecretChange) -> String {
    match secret {
        // S5 explicitly documents empty tcp-md5-key as authentication disabled.
        // S4's !property unset modifier belongs to set, not add.
        SecretChange::Clear => format!(" tcp-md5-key={}", ros_string("")),
        _ => secret_assignment(secret),
    }
}

fn selector(target: &NativeConnectionRef) -> String {
    format!(":local mtids [/routing/bgp/connection/find where name={} instance={}]; :if ([:len $mtids]!=1) do={{ :error \"target-count\" }}; :local mttarget [:pick $mtids 0]; :if ([:tostr $mttarget]!={}) do={{ :error \"target-id\" }}; ",ros_string(&target.name),ros_string(&target.instance),ros_string(&target.observed_id))
}

fn envelope(request: Uuid, data: &str) -> String {
    format!(":local mtresult {{\"request\"={};\"ok\"=true;\"data\"={data}}}; :put [:serialize value=$mtresult to=json options=json.no-string-conversion]",ros_string(&request.to_string()))
}

pub(crate) fn secret_verification(preview: &NativePreview) -> Result<Option<NativeCommand>> {
    secret_verification_script(preview)?
        .map(|body| {
            NativeCommand::checked(
                preview.operation,
                "neighbor.secret-check",
                NativeCommandKind::Read,
                body,
            )
        })
        .transpose()
}

fn secret_verification_script(preview: &NativePreview) -> Result<Option<String>> {
    let (secret, name, target) = match &preview.intent {
        NativeIntent::Create(d) => (&d.secret, d.name.as_str(), None),
        NativeIntent::Patch { target, changes } => {
            (&changes.secret, target.name.as_str(), Some(target))
        }
        _ => return Ok(None),
    };
    if matches!(secret, SecretChange::Keep) {
        return Ok(None);
    }
    let select=target.map(selector).unwrap_or_else(||format!(":local mtids [/routing/bgp/connection/find where name={} instance={}]; :if ([:len $mtids]!=1) do={{ :error \"target-count\" }}; :local mttarget [:pick $mtids 0]; ",ros_string(name),ros_string(&preview.instance)));
    let expected = match secret {
        SecretChange::Replace(v) => ros_string(v),
        SecretChange::Clear => ros_string(""),
        SecretChange::Keep => return Ok(None),
    };
    // S9 + /user, /user/group and /user/active references: establish the local
    // SSH principal's effective group, require readable matching non-RADIUS SSH
    // sessions and exact read/sensitive policy tokens (not substring matches).
    // Never export the dictionary, policy, or property. Missing keys, masks,
    // ambiguous principals/groups and unsupported syntax cannot prove success.
    let user = ros_string(&preview.registration.endpoint.username);
    let permission=format!(concat!(
        ":local mtcan false; :local mtusers [/user/find where name={user}]; ",
        ":if ([:len $mtusers]=1) do={{ :local mtgroup [/user/get [:pick $mtusers 0] group]; ",
        ":local mtgroups [/user/group/find where name=$mtgroup]; :if ([:len $mtgroups]=1) do={{ ",
        ":local mtread false; :local mtsensitive false; :local mtdenied false; ",
        ":foreach mtpolicy in=[:toarray [/user/group/get [:pick $mtgroups 0] policy]] do={{ ",
        ":if ($mtpolicy=\"read\") do={{ :set mtread true }}; ",
        ":if ($mtpolicy=\"sensitive\") do={{ :set mtsensitive true }}; ",
        ":if (($mtpolicy=\"!sensitive\") || ($mtpolicy=\"!read\")) do={{ :set mtdenied true }} }}; ",
        ":local mtactive [/user/active/print as-value where name={user} via=ssh]; ",
        ":local mtidentity ([:len $mtactive]>0); :foreach mtlogin in=$mtactive do={{ ",
        ":if ((($mtlogin->\"group\")!=$mtgroup) || ([:typeof ($mtlogin->\"radius\")]!=\"bool\") || (($mtlogin->\"radius\")!=false)) do={{ :set mtidentity false }} }}; ",
        ":set mtcan ($mtread && $mtsensitive && $mtidentity && (!$mtdenied)) }} }}; "
    ),user=user);
    let body=format!("{select}{permission}:local mtverified false; :if ($mtcan) do={{ :local mtactual [/routing/bgp/connection/get $mttarget tcp-md5-key]; :local mtpresent false; :local mtrows [/routing/bgp/connection/print as-value detail where name={} instance={}]; :if ([:len $mtrows]=1) do={{ :foreach mtkey,mtvalue in=[:pick $mtrows 0] do={{ :if (($mtkey=\"tcp-md5-key\") && ([:typeof $mtvalue]=\"str\") && ($mtvalue=$mtactual)) do={{ :set mtpresent true }} }} }}; :if ($mtpresent && ([:typeof $mtactual]=\"str\") && ($mtactual!=\"***\") && ($mtactual!=\"*****\") && ($mtactual!=\"<hidden>\")) do={{ :set mtverified ($mtactual={expected}) }} }}; {}",ros_string(name),ros_string(&preview.instance),envelope(preview.operation,"{\"id\"=[:tostr $mttarget];\"verified\"=$mtverified}"));
    Ok(Some(body))
}

fn mutation(
    request: Uuid,
    label: &'static str,
    body: String,
    approved: ApprovedChange,
    safe_label: &str,
) -> Result<CompiledStep> {
    let script = format!(
        "{body}; {}",
        envelope(request, "{\"id\"=[:tostr $mttarget];\"applied\"=true}")
    );
    Ok(CompiledStep {
        command: NativeCommand::checked(request, label, NativeCommandKind::Mutation, script)?,
        approved,
        safe_label: safe_label.into(),
    })
}

pub(crate) fn compile_native(
    snapshot: &MikroTikSnapshot,
    intent: &NativeIntent,
    operation: Uuid,
    original_generation: Uuid,
) -> Result<Vec<CompiledStep>> {
    config_guard(&snapshot.inventory, &snapshot.instance)?;
    ensure!(
        !operation.is_nil() && snapshot.router_id == snapshot.registration.router_id,
        "invalid native operation identity"
    );
    match intent {
        NativeIntent::Create(d) => {
            let props = new_properties(snapshot, d, operation)?;
            let (input, output) = chain_names(operation);
            let mut result = Vec::new();
            for (chain, label, safe) in [
                (
                    input,
                    "neighbor.reject-in",
                    "Create enabled reject input chain",
                ),
                (
                    output,
                    "neighbor.reject-out",
                    "Create enabled reject output chain",
                ),
            ] {
                let rule = Properties::from([
                    ("chain".into(), json!(chain)),
                    ("rule".into(), json!("reject;")),
                    ("disabled".into(), json!(false)),
                ]);
                let body = format!(":if ([:len [/routing/filter/rule/find where chain={}]]!=0) do={{ :error \"chain-collision\" }}; :local mttarget [/routing/filter/rule/add {}]",ros_string(&chain),assignments(&rule)?);
                result.push(mutation(
                    operation,
                    label,
                    body,
                    ApprovedChange::Insert {
                        collection: "rules".into(),
                        identity: Properties::from([("chain".into(), json!(chain))]),
                        required: rule,
                    },
                    safe,
                )?);
            }
            let body = format!(":if ([:len [/routing/bgp/connection/find where name={}]]!=0) do={{ :error \"name-collision\" }}; :local mttarget [/routing/bgp/connection/add {}{}]",ros_string(&d.name),assignments(&props)?,creation_secret_assignment(&d.secret));
            let mut required = props;
            // Dynamic is a read-only flag, not an add parameter. Require positive
            // static-kind proof in the independent post-read before success.
            required.insert("dynamic".into(), json!(false));
            result.push(mutation(
                operation,
                "neighbor.create",
                body,
                ApprovedChange::Insert {
                    collection: "connections".into(),
                    identity: Properties::from([
                        ("name".into(), json!(d.name)),
                        ("instance".into(), json!(snapshot.instance)),
                    ]),
                    required,
                },
                "Create disabled connection with both deny-all bindings",
            )?);
            Ok(result)
        }
        NativeIntent::Patch { target, changes } => {
            let record = target_record(snapshot, target, original_generation)?;
            validate_secret(&changes.secret)?;
            ensure!(
                !changes.properties.is_empty() || !matches!(changes.secret, SecretChange::Keep),
                "no native changes requested"
            );
            let mut effective = record.clone();
            for (key, value) in &changes.properties {
                validate_property(key, value, &snapshot.inventory, record)?;
                if value.is_null() {
                    effective.props.remove(key);
                } else {
                    effective.props.insert(key.clone(), value.clone());
                }
            }
            role_as(&snapshot.inventory, &effective)?;
            let body = format!(
                "{}/routing/bgp/connection/set $mttarget {}{}",
                selector(target),
                assignments(&changes.properties)?,
                secret_assignment(&changes.secret)
            );
            Ok(vec![mutation(
                operation,
                "neighbor.patch",
                body,
                ApprovedChange::Patch {
                    collection: "connections".into(),
                    id: target.observed_id.clone(),
                    set: changes.properties.clone(),
                },
                "Patch connection properties",
            )?])
        }
        NativeIntent::SetDisabled { target, disabled } => {
            let row = target_record(snapshot, target, original_generation)?;
            if !disabled {
                for key in ["input.filter", "output.filter-chain"] {
                    ensure!(
                        !matches!(
                            binding_effect(&snapshot.inventory, row, key),
                            BindingEffect::Unknown
                        ),
                        "cannot enable with an unknown native filter binding effect"
                    );
                }
            }
            let set = Properties::from([("disabled".into(), json!(disabled))]);
            Ok(vec![mutation(
                operation,
                "neighbor.admin",
                format!(
                    "{}/routing/bgp/connection/set $mttarget {}",
                    selector(target),
                    assignments(&set)?
                ),
                ApprovedChange::Patch {
                    collection: "connections".into(),
                    id: target.observed_id.clone(),
                    set,
                },
                "Set administrative disabled state",
            )?])
        }
        NativeIntent::Delete(target) => {
            target_record(snapshot, target, original_generation)?;
            Ok(vec![mutation(
                operation,
                "neighbor.delete",
                format!(
                    "{}/routing/bgp/connection/remove $mttarget",
                    selector(target)
                ),
                ApprovedChange::Remove {
                    collection: "connections".into(),
                    id: target.observed_id.clone(),
                },
                "Delete exact connection only",
            )?])
        }
    }
}

pub fn preview_native(
    snapshot: &MikroTikSnapshot,
    intent: NativeIntent,
    operation: Uuid,
) -> Result<NativePreview> {
    ensure!(
        snapshot.guard == config_guard(&snapshot.inventory, &snapshot.instance)?,
        "snapshot guard is not actionable"
    );
    let _all_steps = compile_native(snapshot, &intent, operation, snapshot.generation)?;
    let mut visible_diff = vec![format!(
        "Endpoint {}:{} user {} / revision {} / router {} / instance {} / main",
        snapshot.registration.endpoint.hostname,
        snapshot.registration.endpoint.ssh_port,
        snapshot.registration.endpoint.username,
        snapshot.registration.revision,
        snapshot.router_id,
        snapshot.instance
    )];
    let mut warnings = vec!["Live changes; not atomic. Observable guard is best-effort, not a device lock; another administrator can race between reads and writes. No automatic rollback or replay.".into()];
    match &intent {
        NativeIntent::Create(d) => {
            let (input, output) = chain_names(operation);
            visible_diff.push(format!("Create {} remote {} AS {} role {} AFI {} disabled=yes; input.filter={input}, output.filter-chain={output}; enabled reject; rules",d.name,d.remote_address,d.remote_as,d.role,d.afi.join(",")));
            // Review the compiler's actual nonsecret property map, not a second
            // hand-picked subset. SecretChange is deliberately outside this map.
            let properties = new_properties(snapshot, d, operation)?;
            for (key, value) in &properties {
                visible_diff.push(format!("Create {key} = {value} (explicit)"));
            }
            for key in [
                "local.address",
                "hold-time",
                "keepalive-time",
                "nexthop-choice",
                "use-bfd",
            ] {
                if !properties.contains_key(key) {
                    visible_diff.push(format!(
                        "Create {key}: omitted; native default/inheritance, not explicitly set"
                    ));
                }
            }
            for chain in [&input, &output] {
                visible_diff.push(format!(
                    "Create chain {}: rule=\"reject;\", disabled=false (explicit)",
                    json!(chain)
                ));
            }
            warnings.push(format!("Creation is disabled / deny-all. Enable requires a separate reviewed operation. Failure can leave orphan chains {input} and {output}; inspect manually, never automatic cleanup."));
        }
        NativeIntent::Patch { target, changes } => {
            let row = target_record(snapshot, target, snapshot.generation)?;
            visible_diff.push(format!("Patch {} [{}]", target.name, target.observed_id));
            for (key, value) in &changes.properties {
                let before =
                    row.props
                        .get(key)
                        .cloned()
                        .or(inherited_value(&snapshot.inventory, row, key)?);
                if value.is_null() {
                    let inherited = inherited_value(&snapshot.inventory, row, key)?;
                    visible_diff.push(format!(
                        "{key}: {before:?} → unset override; inherited result {}",
                        inherited
                            .as_ref()
                            .map(Value::to_string)
                            .unwrap_or_else(|| "native default (no override)".into())
                    ));
                    if matches!(key.as_str(), "input.filter" | "output.filter-chain")
                        && inherited.is_none()
                    {
                        warnings.push(format!("{key}: no binding after unset; ACCEPT everything at that filter stage. Explicit confirmation required."));
                    }
                } else {
                    visible_diff.push(format!("{key}: {before:?} → {value}"));
                }
            }
        }
        NativeIntent::SetDisabled { target, disabled } => {
            let row = target_record(snapshot, target, snapshot.generation)?;
            visible_diff.push(format!(
                "{} [{}]: disabled {:?} → {disabled}; remote AS {:?}, AFI {:?}",
                target.name,
                target.observed_id,
                row.props.get("disabled"),
                row.props.get("remote.as"),
                row.props.get("afi")
            ));
            for key in ["input.filter", "output.filter-chain"] {
                match binding_effect(&snapshot.inventory, row, key) {
                    BindingEffect::Bound(name) => {
                        visible_diff
                            .push(format!("{key}: bound to observed chain {}", json!(name)));
                        warnings.push(format!("{key}: configured filter applies immediately, including any reject/deny-all rules; this is not proof of traffic protection"));
                    }
                    BindingEffect::Unbound => {
                        visible_diff.push(format!(
                            "{key}: unbound (observable absence after inheritance)"
                        ));
                        warnings.push(format!("{key}: unbound — ACCEPT at this stage"));
                    }
                    BindingEffect::Unknown => {
                        visible_diff.push(format!("{key}: unknown binding effect"));
                        warnings.push(format!("{key}: unknown representation or inheritance; no configured filtering assurance. Enable is unavailable."));
                    }
                }
            }
        }
        NativeIntent::Delete(target) => {
            visible_diff.push(format!(
                "Delete connection {} [{}] ONLY",
                target.name, target.observed_id
            ));
            warnings.push("Immediate session/traffic impact. All filters, lists and templates are preserved; orphan policies are not cleaned up.".into());
        }
    }
    let secret = match &intent {
        NativeIntent::Create(d) => Some(&d.secret),
        NativeIntent::Patch { changes, .. } => Some(&changes.secret),
        _ => None,
    };
    if let Some(secret) = secret {
        visible_diff.push(
            match secret {
                SecretChange::Keep => "Authentication: Keep (no sensitive read/write)",
                SecretChange::Replace(_) => "Authentication: Replace (value hidden)",
                SecretChange::Clear => "Authentication: Clear (explicit removal)",
            }
            .into(),
        );
        if !matches!(secret, SecretChange::Keep) {
            warnings.push("Private on-device verification may be unavailable. A verified value is configuration proof only, never proof that authentication works.".into());
        }
    }
    visible_diff = visible_diff.iter().map(|s| presentation_text(s)).collect();
    warnings = warnings.iter().map(|s| presentation_text(s)).collect();
    let preview = NativePreview {
        router_id: snapshot.router_id,
        operation,
        registration: snapshot.registration.clone(),
        generation: snapshot.generation,
        instance: snapshot.instance.clone(),
        guard: snapshot.guard.clone(),
        intent,
        visible_diff,
        warnings,
    };
    let _private_check = secret_verification(&preview)?;
    Ok(preview)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::mikrotik::test_support::*;

    fn sec003_draft() -> NativeConnectionDraft {
        NativeConnectionDraft {
            name: "review-peer".into(),
            remote_address: "192.0.2.9".parse().unwrap(),
            remote_as: 65099,
            role: "ebgp".into(),
            afi: vec!["ipv6".into(), "ip".into()],
            source: Some("192.0.2.55".parse().unwrap()),
            comment: "distinct comment\nsecond line".into(),
            hold_time: Some("3m".into()),
            keepalive_time: Some("30s".into()),
            nexthop_choice: Some("propagate".into()),
            use_bfd: Some(true),
            secret: SecretChange::Keep,
        }
    }

    #[test]
    fn mikrotik_neighbor_sec003_create_review_discloses_every_written_nonsecret_property() {
        let snapshot = documented_snapshot();
        let preview = preview_native(
            &snapshot,
            NativeIntent::Create(sec003_draft()),
            Uuid::from_u128(42),
        )
        .unwrap();
        for expected in [
            "Create name = \"review-peer\" (explicit)", "Create instance = \"blue\" (explicit)",
            "Create remote.address = \"192.0.2.9\" (explicit)", "Create remote.as = 65099 (explicit)",
            "Create local.role = \"ebgp\" (explicit)", "Create afi = [\"ipv6\",\"ip\"] (explicit)",
            "Create local.address = \"192.0.2.55\" (explicit)",
            "Create comment = \"distinct comment\\nsecond line\" (explicit)",
            "Create hold-time = \"3m\" (explicit)", "Create keepalive-time = \"30s\" (explicit)",
            "Create nexthop-choice = \"propagate\" (explicit)", "Create use-bfd = true (explicit)",
            "Create routing-table = \"main\" (explicit)", "Create vrf = \"main\" (explicit)",
            "Create disabled = true (explicit)",
            "Create input.filter = \"bgp-lm-in-0000000000000000000000000000002a\" (explicit)",
            "Create output.filter-chain = \"bgp-lm-out-0000000000000000000000000000002a\" (explicit)",
        ] {
            assert!(preview.visible_diff.iter().any(|s|s==expected),"missing visible intention: {expected}");
        }
        for chain in [
            "bgp-lm-in-0000000000000000000000000000002a",
            "bgp-lm-out-0000000000000000000000000000002a",
        ] {
            assert!(preview.visible_diff.iter().any(|s| s.contains(chain)
                && s.contains("rule=\"reject;\"")
                && s.contains("disabled=false")));
        }
        assert!(!preview
            .visible_diff
            .iter()
            .any(|s| s.contains("Create dynamic =")));
    }

    #[test]
    fn mikrotik_neighbor_sec003_create_review_distinguishes_omitted_defaults_from_explicit_empty_or_false(
    ) {
        let snapshot = documented_snapshot();
        let mut draft = sec003_draft();
        draft.source = None;
        draft.hold_time = None;
        draft.keepalive_time = None;
        draft.nexthop_choice = None;
        draft.use_bfd = None;
        draft.comment.clear();
        let preview =
            preview_native(&snapshot, NativeIntent::Create(draft), Uuid::new_v4()).unwrap();
        for key in [
            "local.address",
            "hold-time",
            "keepalive-time",
            "nexthop-choice",
            "use-bfd",
        ] {
            assert!(
                preview
                    .visible_diff
                    .iter()
                    .any(|s| s.starts_with(&format!("Create {key}: omitted"))
                        && s.contains("not explicitly set")),
                "{key}"
            );
            assert!(!preview
                .visible_diff
                .iter()
                .any(|s| s.starts_with(&format!("Create {key} ="))));
        }
        assert!(preview
            .visible_diff
            .iter()
            .any(|s| s == "Create comment = \"\" (explicit)"));
        let mut draft = sec003_draft();
        draft.use_bfd = Some(false);
        let preview =
            preview_native(&snapshot, NativeIntent::Create(draft), Uuid::new_v4()).unwrap();
        assert!(preview
            .visible_diff
            .iter()
            .any(|s| s == "Create use-bfd = false (explicit)"));
    }

    #[test]
    fn mikrotik_secret_sec003_complete_create_review_keeps_md5_intention_only() {
        let snapshot = documented_snapshot();
        let mut draft = sec003_draft();
        draft.secret = SecretChange::Replace("SEC003_MD5_SENTINEL".into());
        let preview =
            preview_native(&snapshot, NativeIntent::Create(draft), Uuid::new_v4()).unwrap();
        assert!(preview
            .visible_diff
            .iter()
            .any(|s| s.contains("Authentication: Replace")));
        let visible = format!(
            "{preview:?} {:?} {:?}",
            preview.visible_diff, preview.warnings
        );
        assert!(!visible.contains("SEC003_MD5_SENTINEL"));
        assert!(!visible.contains("tcp-md5-key="));
        assert!(preview
            .visible_diff
            .iter()
            .any(|s| s.starts_with("Create comment =")));
    }

    #[test]
    fn mikrotik_secret_create_clear_uses_documented_empty_string_not_add_unset_syntax() {
        assert_eq!(
            creation_secret_assignment(&SecretChange::Clear),
            " tcp-md5-key=\"\""
        );
        assert_eq!(creation_secret_assignment(&SecretChange::Keep), "");
        assert_eq!(secret_assignment(&SecretChange::Clear), " !tcp-md5-key");
    }

    #[test]
    fn mikrotik_neighbor_create_rejects_generated_name_in_known_other_protocol_references() {
        let mut snapshot = documented_snapshot();
        let operation = Uuid::new_v4();
        snapshot
            .inventory
            .known_other_protocol_chains
            .insert(chain_names(operation).0);
        snapshot.guard = config_guard(&snapshot.inventory, "blue").unwrap();
        let draft = NativeConnectionDraft {
            name: "new".into(),
            remote_address: "192.0.2.9".parse().unwrap(),
            remote_as: 65001,
            role: "ebgp".into(),
            afi: vec!["ip".into()],
            source: None,
            comment: String::new(),
            hold_time: None,
            keepalive_time: None,
            nexthop_choice: None,
            use_bfd: None,
            secret: SecretChange::Keep,
        };
        assert!(preview_native(&snapshot, NativeIntent::Create(draft), operation).is_err());
    }

    #[test]
    fn mikrotik_neighbor_hostile_properties_are_one_quoted_assignment_not_executable_code() {
        let value = "a\"; /routing/bgp/connection/remove [find]; # \\ $x\nβ";
        let props = Properties::from([("comment".into(), json!(value))]);
        assert_eq!(
            assignments(&props).unwrap(),
            "comment=\"a\\\"; /routing/bgp/connection/remove [find]; # \\\\ \\$x\\nβ\""
        );
        let snapshot = documented_snapshot();
        let preview = preview_native(
            &snapshot,
            NativeIntent::Patch {
                target: snapshot.peers[0].connection.clone().unwrap(),
                changes: NativePatch {
                    properties: props,
                    secret: SecretChange::Keep,
                },
            },
            Uuid::new_v4(),
        )
        .unwrap();
        let steps = compile_native(
            &snapshot,
            &preview.intent,
            preview.operation,
            snapshot.generation,
        )
        .unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].command.label, "neighbor.patch");
        assert!(!format!("{:?}", steps[0]).contains(value));
        assert!(secret_verification_script(&preview).unwrap().is_none());
    }

    #[test]
    fn mikrotik_secret_private_verification_checks_actual_policy_tokens_property_and_presence() {
        let snapshot = documented_snapshot();
        for clear in [false, true] {
            let preview = preview_native(
                &snapshot,
                NativeIntent::Patch {
                    target: snapshot.peers[0].connection.clone().unwrap(),
                    changes: NativePatch {
                        properties: Properties::new(),
                        secret: if clear {
                            SecretChange::Clear
                        } else {
                            SecretChange::Replace("SENTINEL_MD5\";$x".into())
                        },
                    },
                },
                Uuid::new_v4(),
            )
            .unwrap();
            let script = secret_verification_script(&preview).unwrap().unwrap();
            assert!(
                script.contains("/user/get")
                    && script.contains("/user/group/get")
                    && script.contains("/user/active/print")
            );
            assert!(script.contains("($mtpolicy=\"sensitive\")"));
            assert!(script.contains("($mtpolicy=\"!sensitive\")"));
            assert!(!script.contains(":find")); // no substring permission authorization
            assert!(script.contains("/routing/bgp/connection/get $mttarget tcp-md5-key"));
            assert!(
                script.contains("$mtpresent") && script.contains("[:typeof $mtactual]=\"str\"")
            );
            assert!(script.ends_with("to=json options=json.no-string-conversion]"));
            assert!(
                script.contains("\"data\"={\"id\"=[:tostr $mttarget];\"verified\"=$mtverified}")
            );
            assert!(!script.contains("\"data\"=$mtactual"));
            assert!(!script.chars().any(char::is_control));
        }
    }

    #[test]
    fn mikrotik_neighbor_native_semantics_do_not_coerce_unknown_or_unrelated_values() {
        for (key, a, b) in [
            ("hold-time", json!("3m"), json!("00:03:00")),
            ("hold-time", json!("infinity"), json!("0")),
            ("keepalive-time", json!("500ms"), json!("0.5s")),
            ("remote.as", json!("1.10"), json!(65546)),
            ("afi", json!("ipv6,ip"), json!(["ip", "ipv6"])),
            ("use-bfd", json!("no"), json!(false)),
        ] {
            assert!(native_equal(key, &a, &b), "{key}");
        }
        for (key, a, b) in [
            ("hold-time", json!("bogus"), json!("bogus")),
            ("use-bfd", json!("!yes"), json!(true)),
            ("afi", json!("ip,ip"), json!(["ip"])),
            ("vendor.future", json!("0"), json!(0)),
            ("comment", json!("3m"), json!("00:03:00")),
        ] {
            assert!(!native_equal(key, &a, &b), "{key}");
        }
    }
}
