use super::{
    require_target_version, ConfigGuard, NativeInventory, NativeRecord, Properties,
    ScopeEligibility,
};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn required_text<'a>(record: &'a NativeRecord, key: &str) -> Result<&'a str> {
    record
        .props
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .context("invalid or missing required native configuration field")
}

fn optional_text<'a>(record: &'a NativeRecord, key: &str) -> Result<Option<&'a str>> {
    if record.props.contains_key(key) {
        required_text(record, key).map(Some)
    } else {
        Ok(None)
    }
}

fn validate_records(records: &[NativeRecord], fields: &[&str], identity: &[&str]) -> Result<()> {
    let mut ids = BTreeSet::new();
    let mut identities = BTreeSet::new();
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
            let values = identity
                .iter()
                .map(|key| required_text(record, key))
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                identities.insert(values),
                "duplicate native configuration identity"
            );
        }
    }
    Ok(())
}

fn validate_inventory(inv: &NativeInventory) -> Result<()> {
    require_target_version(&inv.version).context("native inventory is unsupported")?;
    ensure!(
        inv.bgp_reference_inventory_complete,
        "native configuration inventory is incomplete"
    );
    validate_records(&inv.instances, &["name"], &["name"])?;
    validate_records(
        &inv.connections,
        &["name", "instance", "local.role"],
        &["instance", "name"],
    )?;
    validate_records(&inv.templates, &["name"], &["name"])?;
    validate_records(&inv.rules, &["chain", "rule"], &[])?;
    Ok(())
}

fn flag_is_set(record: &NativeRecord, key: &str) -> Result<bool> {
    match record.props.get(key) {
        None | Some(Value::Bool(false)) => Ok(false),
        Some(Value::Bool(true)) => Ok(true),
        Some(Value::String(value)) if value == "false" || value == "no" => Ok(false),
        Some(Value::String(value)) if value == "true" || value == "yes" => Ok(true),
        _ => bail!("native instance state is unreadable"),
    }
}

fn selected_instance<'a>(inv: &'a NativeInventory, selected: &str) -> Result<&'a NativeRecord> {
    ensure!(
        !selected.trim().is_empty(),
        "an existing BGP instance must be explicitly selected"
    );
    let instance = inv
        .instances
        .iter()
        .find(|record| record.props.get("name").and_then(Value::as_str) == Some(selected))
        .context("selected native instance is unavailable")?;
    ensure!(
        !flag_is_set(instance, "disabled")? && !flag_is_set(instance, "inactive")?,
        "selected native instance is unusable"
    );
    // RouterOS 7.24 instance/connection/template references: VRF defaults main;
    // absent connection/template routing-table inherits the instance table.
    ensure!(
        optional_text(instance, "vrf")?.unwrap_or("main") == "main",
        "selected instance VRF is not main"
    );
    ensure!(
        optional_text(instance, "routing-table")?.unwrap_or("main") == "main",
        "selected instance routing table is not main"
    );
    Ok(instance)
}

fn template_names(record: &NativeRecord) -> Result<Vec<&str>> {
    let names = match record.props.get("templates") {
        None => return Ok(Vec::new()),
        Some(Value::String(value)) => value.split(',').collect::<Vec<_>>(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .context("native template reference is unreadable")
            })
            .collect::<Result<Vec<_>>>()?,
        _ => bail!("native template references are unreadable"),
    };
    ensure!(
        names.iter().all(|name| !name.trim().is_empty()),
        "native template reference is empty"
    );
    Ok(names)
}

#[derive(Clone, Default)]
struct ScopeValues {
    table: Option<String>,
    vrf: Option<String>,
}

fn inherit(target: &mut Option<String>, source: &Option<String>) -> Result<()> {
    if let Some(source) = source {
        ensure!(
            target.as_ref().is_none_or(|value| value == source),
            "conflicting inherited native scope values"
        );
        *target = Some(source.clone());
    }
    Ok(())
}

fn resolve_values(
    record: &NativeRecord,
    resolved: &BTreeMap<&str, ScopeValues>,
) -> Result<ScopeValues> {
    let mut values = ScopeValues::default();
    for name in template_names(record)? {
        let parent = resolved
            .get(name)
            .context("native template scope is unavailable")?;
        inherit(&mut values.table, &parent.table)?;
        inherit(&mut values.vrf, &parent.vrf)?;
    }
    // Explicit values override known, unambiguous inherited values. Conflicting
    // multi-template sources have already failed closed, never chosen by order.
    if let Some(table) = optional_text(record, "routing-table")? {
        values.table = Some(table.into());
    }
    if let Some(vrf) = optional_text(record, "vrf")? {
        values.vrf = Some(vrf.into());
    }
    Ok(values)
}

fn effective_scope(inv: &NativeInventory, connection: &NativeRecord) -> Result<ScopeValues> {
    let templates = inv
        .templates
        .iter()
        .map(|record| Ok((required_text(record, "name")?, record)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut visiting = BTreeSet::new();
    let mut resolved = BTreeMap::new();
    let mut pending = template_names(connection)?
        .into_iter()
        .map(|name| (name, false))
        .collect::<Vec<_>>();
    // Iterative postorder traversal avoids recursion on untrusted template depth.
    // `visiting` tracks the current path; `resolved` permits shared DAG ancestors.
    while let Some((name, exiting)) = pending.pop() {
        let record = templates
            .get(name)
            .context("referenced native template is unavailable")?;
        if exiting {
            resolved.insert(name, resolve_values(record, &resolved)?);
            visiting.remove(name);
        } else if !resolved.contains_key(name) {
            ensure!(visiting.insert(name), "cyclic native template inheritance");
            pending.push((name, true));
            for parent in template_names(record)? {
                pending.push((parent, false));
            }
        }
    }
    resolve_values(connection, &resolved)
}

fn check_connection_scope(
    inv: &NativeInventory,
    selected: &str,
    connection: &NativeRecord,
) -> Result<()> {
    validate_inventory(inv)?;
    selected_instance(inv, selected)?;
    validate_records(
        std::slice::from_ref(connection),
        &["name", "instance", "local.role"],
        &[],
    )?;
    ensure!(
        required_text(connection, "instance")? == selected,
        "connection belongs to another native instance"
    );
    let effective = effective_scope(inv, connection)?;
    ensure!(
        effective.table.as_deref().unwrap_or("main") == "main",
        "effective connection routing table is not main"
    );
    ensure!(
        effective.vrf.as_deref().unwrap_or("main") == "main",
        "effective connection VRF is not main"
    );
    Ok(())
}

pub fn connection_scope(
    inv: &NativeInventory,
    selected: &str,
    connection: &NativeRecord,
) -> ScopeEligibility {
    match check_connection_scope(inv, selected, connection) {
        Ok(()) => ScopeEligibility::Main,
        Err(error) => ScopeEligibility::ReadOnly(error.to_string()),
    }
}

fn sensitive(key: &str) -> bool {
    // Explicit sensitive-property classification, including grouped forms. Do
    // not broadly discard unknown fields merely because they contain "key".
    matches!(
        key.rsplit('.').next().unwrap_or(key),
        "tcp-md5-key" | "password" | "passphrase" | "private-key" | "secret" | "authentication-key"
    )
}

fn redact(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .filter(|(key, _)| !sensitive(key))
                .map(|(key, value)| (key.clone(), redact(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(redact).collect()),
        value => value.clone(),
    }
}

fn volatile(key: &str) -> bool {
    // Only known telemetry is excluded. All session rows are excluded separately;
    // unknown observed configuration (including comments/state/bindings) stays.
    matches!(
        key,
        "uptime"
            | "last-started"
            | "established"
            | "prefix-count"
            | "messages"
            | "bytes"
            | "local.messages"
            | "remote.messages"
            | "local.bytes"
            | "remote.bytes"
            | "input.procid"
            | "output.procid"
            | "last-notification"
            | "local.default-address"
    )
}

fn guard_records(records: &[NativeRecord], ordered: bool) -> Value {
    let mut records = records.iter().collect::<Vec<_>>();
    if !ordered {
        records.sort_by(|left, right| left.id.cmp(&right.id));
    }
    Value::Array(
        records
            .into_iter()
            .map(|record| {
                let mut props = record
                    .props
                    .iter()
                    .filter(|(key, _)| !sensitive(key) && !volatile(key))
                    .map(|(key, value)| (key.clone(), redact(value)))
                    .collect::<serde_json::Map<_, _>>();
                props.insert(".id".into(), json!(record.id));
                Value::Object(props)
            })
            .collect(),
    )
}

/// Canonical source configuration, not a presentation string or a telemetry hash.
/// Include all observed consumers/templates, including other instances, so shared
/// filter/reference edits invalidate a reviewed guard. Rule order is significant.
pub fn config_guard(inv: &NativeInventory, selected: &str) -> Result<ConfigGuard> {
    validate_inventory(inv).context("cannot guard native configuration")?;
    selected_instance(inv, selected).context("cannot guard selected native instance")?;
    let mut props = Properties::new();
    props.insert("version".into(), json!(inv.version));
    props.insert("selected".into(), json!(selected));
    props.insert("instances".into(), guard_records(&inv.instances, false));
    props.insert("connections".into(), guard_records(&inv.connections, false));
    props.insert("templates".into(), guard_records(&inv.templates, false));
    props.insert("rules".into(), guard_records(&inv.rules, true));
    props.insert(
        "bgp_reference_inventory_complete".into(),
        json!(inv.bgp_reference_inventory_complete),
    );
    props.insert(
        "known_other_protocol_chains".into(),
        json!(inv.known_other_protocol_chains),
    );
    Ok(ConfigGuard(props))
}

#[cfg(test)]
mod tests {
    use crate::router::mikrotik::{
        config_guard, connection_scope, NativeInventory, NativeRecord, ScopeEligibility,
    };
    use serde_json::{json, Value};
    use std::collections::BTreeSet;

    // Synthetic, documentation-derived configuration; no SSH/devices involved.
    fn record(value: Value) -> NativeRecord {
        serde_json::from_value(value).unwrap()
    }

    fn inventory() -> NativeInventory {
        NativeInventory {
            version: "7.24.7 (stable)".into(),
            instances: vec![record(json!({
                ".id": "*I", "name": "blue", "vrf": "main", "routing-table": "main",
                "disabled": false, "as": "001234"
            }))],
            connections: vec![record(json!({
                ".id": "*A", "name": "peer", "instance": "blue", "local.role": "ebgp",
                "remote.address": "192.0.2.1", "input.filter": "in", "output.filter-chain": "out",
                "disabled": true, "comment": "raw α\u{1b}[2J\n$"
            }))],
            templates: vec![],
            sessions: vec![],
            rules: vec![
                record(
                    json!({".id": "*R1", "chain": "in", "rule": "reject;", "disabled": false, "comment": "first"}),
                ),
                record(json!({".id": "*R2", "chain": "out", "rule": "reject;", "disabled": false})),
            ],
            bgp_reference_inventory_complete: true,
            known_other_protocol_chains: BTreeSet::new(),
        }
    }

    fn assert_read_only(inv: &NativeInventory) {
        assert!(matches!(
            connection_scope(inv, "blue", &inv.connections[0]),
            ScopeEligibility::ReadOnly(_)
        ));
    }

    #[test]
    fn mikrotik_scope_effective_main_and_documented_defaults() {
        let mut inv = inventory();
        assert_eq!(
            connection_scope(&inv, "blue", &inv.connections[0]),
            ScopeEligibility::Main
        );
        inv.instances[0].props.remove("vrf");
        inv.instances[0].props.remove("routing-table");
        assert_eq!(
            connection_scope(&inv, "blue", &inv.connections[0]),
            ScopeEligibility::Main
        );
        inv.templates = vec![
            record(json!({".id": "*T1", "name": "parent", "vrf": "main", "templates": ["base"]})),
            record(json!({".id": "*T2", "name": "base", "routing-table": "main"})),
            record(
                json!({".id": "*T3", "name": "equivalent", "vrf": "main", "routing-table": "main"}),
            ),
        ];
        inv.connections[0]
            .props
            .insert("templates".into(), json!(["parent", "equivalent"]));
        assert_eq!(
            connection_scope(&inv, "blue", &inv.connections[0]),
            ScopeEligibility::Main
        );
        inv.connections[0]
            .props
            .insert("templates".into(), json!("parent,equivalent"));
        assert_eq!(
            connection_scope(&inv, "blue", &inv.connections[0]),
            ScopeEligibility::Main
        );
    }

    #[test]
    fn mikrotik_scope_rf2_direct_and_inherited_overrides_are_independent() {
        for property in ["vrf", "routing-table"] {
            let mut inv = inventory();
            inv.connections[0]
                .props
                .insert(property.into(), json!("customer"));
            assert_read_only(&inv);
            inv.connections[0].props.remove(property);
            inv.templates.push(record(
                json!({".id": "*T", "name": "parent", (property): "customer"}),
            ));
            inv.connections[0]
                .props
                .insert("templates".into(), json!(["parent"]));
            assert_read_only(&inv);
            // A known inherited value can be overridden explicitly, not by list order.
            inv.connections[0]
                .props
                .insert(property.into(), json!("main"));
            assert_eq!(
                connection_scope(&inv, "blue", &inv.connections[0]),
                ScopeEligibility::Main
            );
            inv.connections[0].props.remove(property);
            inv.templates[0]
                .props
                .insert("templates".into(), json!(["base"]));
            inv.templates[0]
                .props
                .insert(property.into(), json!("main"));
            inv.templates.push(record(
                json!({".id": "*B", "name": "base", (property): "customer"}),
            ));
            assert_eq!(
                connection_scope(&inv, "blue", &inv.connections[0]),
                ScopeEligibility::Main
            );
        }
        let mut inv = inventory();
        inv.connections[0]
            .props
            .insert("routing-table".into(), json!("main"));
        inv.connections[0]
            .props
            .insert("vrf".into(), json!("customer"));
        assert_read_only(&inv);
    }

    #[test]
    fn mikrotik_scope_unknown_cyclic_and_conflicting_inheritance_fails_closed() {
        let mut inv = inventory();
        inv.connections[0]
            .props
            .insert("templates".into(), json!(["parent"]));
        assert_read_only(&inv); // Missing/inaccessible reference is not a default.
        inv.templates = vec![
            record(json!({".id": "*T", "name": "parent", "templates": ["base"]})),
            record(json!({".id": "*B", "name": "base", "templates": ["parent"]})),
        ];
        assert_read_only(&inv);
        inv.connections[0].props.insert("vrf".into(), json!("main"));
        inv.connections[0]
            .props
            .insert("routing-table".into(), json!("main"));
        assert_read_only(&inv); // Explicit values do not make a cyclic graph trustworthy.
        for property in ["vrf", "routing-table"] {
            let mut conflict = inventory();
            conflict.templates = vec![
                record(json!({".id": "*T1", "name": "parent", (property): "main"})),
                record(json!({".id": "*T2", "name": "other", (property): "customer"})),
            ];
            for refs in [json!(["parent", "other"]), json!(["other", "parent"])] {
                conflict.connections[0]
                    .props
                    .insert("templates".into(), refs);
                assert_read_only(&conflict);
            }
        }
        for value in [json!(null), json!(42), json!(""), json!(["main"])] {
            for property in ["vrf", "routing-table"] {
                let mut unknown = inventory();
                unknown.connections[0]
                    .props
                    .insert(property.into(), value.clone());
                assert_read_only(&unknown);
                unknown.connections[0].props.remove(property);
                unknown.templates.push(record(
                    json!({".id": "*T", "name": "parent", (property): value}),
                ));
                unknown.connections[0]
                    .props
                    .insert("templates".into(), json!(["parent"]));
                assert_read_only(&unknown);
            }
        }
        for refs in [
            json!(null),
            json!(42),
            json!(["parent", null]),
            json!("parent,"),
            json!([""]),
        ] {
            let mut unknown = inventory();
            unknown.connections[0]
                .props
                .insert("templates".into(), refs);
            assert_read_only(&unknown);
        }
    }

    #[test]
    fn mikrotik_scope_shared_template_is_not_mistaken_for_a_cycle() {
        let mut inv = inventory();
        inv.templates = vec![
            record(json!({".id": "*T1", "name": "a", "templates": ["base"]})),
            record(json!({".id": "*T2", "name": "b", "templates": ["base"]})),
            record(json!({".id": "*T3", "name": "base", "vrf": "main"})),
        ];
        inv.connections[0]
            .props
            .insert("templates".into(), json!(["a", "b"]));
        assert_eq!(
            connection_scope(&inv, "blue", &inv.connections[0]),
            ScopeEligibility::Main
        );
    }

    #[test]
    fn mikrotik_scope_selection_instance_state_and_inventory_must_be_observable() {
        let inv = inventory();
        for selected in ["", " ", "missing"] {
            assert!(config_guard(&inv, selected).is_err());
            assert!(matches!(
                connection_scope(&inv, selected, &inv.connections[0]),
                ScopeEligibility::ReadOnly(_)
            ));
        }
        for (property, value) in [
            ("vrf", json!("customer")),
            ("routing-table", json!("customer")),
            ("vrf", json!(null)),
            ("routing-table", json!(42)),
            ("disabled", json!(true)),
            ("inactive", json!(true)),
            ("disabled", json!("unknown")),
        ] {
            let mut invalid = inv.clone();
            invalid.instances[0].props.insert(property.into(), value);
            assert_read_only(&invalid);
            assert!(config_guard(&invalid, "blue").is_err());
        }
        let mut inaccessible = inv.clone();
        inaccessible.bgp_reference_inventory_complete = false;
        assert_read_only(&inaccessible);
        assert!(config_guard(&inaccessible, "blue").is_err());
        inaccessible.connections.clear();
        assert!(config_guard(&inaccessible, "blue").is_err());
        let mut wrong_version = inv.clone();
        wrong_version.version = "7.24.70".into();
        assert_read_only(&wrong_version);
        assert!(config_guard(&wrong_version, "blue").is_err());
    }

    #[test]
    fn mikrotik_scope_other_instance_peers_do_not_change_selected_membership() {
        let mut inv = inventory();
        inv.instances.push(record(
            json!({".id": "*J", "name": "red", "vrf": "customer"}),
        ));
        inv.connections.push(record(
            json!({".id": "*B", "name": "peer", "instance": "red", "local.role": "ebgp"}),
        ));
        assert_eq!(
            connection_scope(&inv, "blue", &inv.connections[0]),
            ScopeEligibility::Main
        );
        assert!(matches!(
            connection_scope(&inv, "blue", &inv.connections[1]),
            ScopeEligibility::ReadOnly(_)
        ));
        assert!(config_guard(&inv, "blue").is_ok());
    }

    #[test]
    fn mikrotik_scope_rf4_guard_excludes_telemetry_and_secrets_not_raw_unknown_config() {
        let mut inv = inventory();
        inv.templates.push(record(
            json!({".id": "*T", "name": "parent", "vrf": "main"}),
        ));
        inv.connections[0]
            .props
            .insert("templates".into(), json!(["parent"]));
        inv.connections[0].props.insert(
            "vendor.future".into(),
            json!({"values": ["001", null, false]}),
        );
        let baseline = config_guard(&inv, "blue").unwrap();
        let mut changed = inv.clone();
        changed.sessions.push(record(
            json!({".id": "*S", "uptime": "1d", "remote.messages": 100}),
        ));
        changed.connections[0]
            .props
            .insert("uptime".into(), json!("2d"));
        changed.connections[0]
            .props
            .insert("remote.messages".into(), json!(200));
        for records in [
            &mut changed.instances,
            &mut changed.connections,
            &mut changed.templates,
            &mut changed.rules,
        ] {
            records[0]
                .props
                .insert("tcp-md5-key".into(), json!("SECRET_MARKER"));
            records[0]
                .props
                .insert("password".into(), json!("SECRET_MARKER"));
        }
        assert_eq!(baseline, config_guard(&changed, "blue").unwrap());
        let text = serde_json::to_string(&baseline.0).unwrap();
        assert!(!text.contains("SECRET_MARKER"));
        assert!(text.contains("vendor.future") && text.contains("001"));
        assert_eq!(baseline.0["connections"][0]["comment"], "raw α\u{1b}[2J\n$");
        assert_eq!(changed.connections[0].props["tcp-md5-key"], "SECRET_MARKER");
        changed.connections[0].props.insert(
            "vendor.future".into(),
            json!({"values": ["002", null, false]}),
        );
        assert_ne!(baseline, config_guard(&changed, "blue").unwrap());
    }

    #[test]
    fn mikrotik_scope_guard_includes_configuration_order_ids_bindings_and_references() {
        let mut inv = inventory();
        inv.templates.push(record(
            json!({".id": "*T", "name": "parent", "vrf": "main"}),
        ));
        let baseline = config_guard(&inv, "blue").unwrap();
        let mut variants = Vec::new();
        for (key, value) in [
            ("vrf", json!("customer")),
            ("routing-table", json!("customer")),
            ("comment", json!("new")),
            ("disabled", json!(false)),
            ("input.filter", json!("changed")),
            ("output.filter-chain", json!("changed")),
            ("templates", json!(["parent"])),
            ("remote.address", json!("192.0.2.2")),
        ] {
            let mut changed = inv.clone();
            changed.connections[0].props.insert(key.into(), value);
            variants.push(changed);
        }
        for (key, value) in [
            ("vrf", json!("customer")),
            ("routing-table", json!("customer")),
            ("templates", json!(["new-reference"])),
        ] {
            let mut changed = inv.clone();
            changed.templates[0].props.insert(key.into(), value);
            variants.push(changed);
        }
        for records in 0..4 {
            let mut changed = inv.clone();
            match records {
                0 => changed.instances[0].id = "*NEW".into(),
                1 => changed.connections[0].id = "*NEW".into(),
                2 => changed.templates[0].id = "*NEW".into(),
                _ => changed.rules[0].id = "*NEW".into(),
            }
            variants.push(changed);
        }
        for (key, value) in [
            ("rule", json!("accept;")),
            ("comment", json!("new")),
            ("disabled", json!(true)),
            ("chain", json!("changed")),
        ] {
            let mut changed = inv.clone();
            changed.rules[0].props.insert(key.into(), value);
            variants.push(changed);
        }
        let mut reordered = inv.clone();
        reordered.rules.reverse();
        variants.push(reordered);
        let mut references = inv.clone();
        references
            .known_other_protocol_chains
            .insert("ospf-used".into());
        variants.push(references);
        for changed in variants {
            assert_ne!(baseline, config_guard(&changed, "blue").unwrap());
        }
        let mut canonical = inv.clone();
        canonical.connections.push(record(
            json!({".id": "*B", "name": "other", "instance": "blue", "local.role": "ibgp"}),
        ));
        let expected = config_guard(&canonical, "blue").unwrap();
        canonical.connections.reverse();
        assert_eq!(expected, config_guard(&canonical, "blue").unwrap());
    }

    #[test]
    fn mikrotik_scope_invalid_and_duplicate_configuration_has_fixed_safe_errors() {
        let inv = inventory();
        let mut variants = Vec::new();
        for field in ["name", "instance", "local.role"] {
            for value in [None, Some(json!("")), Some(json!(null)), Some(json!(42))] {
                let mut changed = inv.clone();
                if let Some(value) = value {
                    changed.connections[0].props.insert(field.into(), value);
                } else {
                    changed.connections[0].props.remove(field);
                }
                variants.push(changed);
            }
        }
        let mut duplicate = inv.clone();
        duplicate.connections.push(duplicate.connections[0].clone());
        duplicate.connections[1].id = "*OTHER".into();
        variants.push(duplicate);
        let mut duplicate_id = inv.clone();
        duplicate_id.connections.push(record(
            json!({".id": "*A", "name": "other", "instance": "blue", "local.role": "ibgp"}),
        ));
        variants.push(duplicate_id);
        let mut duplicate_instance = inv.clone();
        duplicate_instance
            .instances
            .push(duplicate_instance.instances[0].clone());
        variants.push(duplicate_instance);
        let mut duplicate_template = inv.clone();
        duplicate_template.templates = vec![
            record(json!({".id": "*T", "name": "parent"})),
            record(json!({".id": "*U", "name": "parent"})),
        ];
        variants.push(duplicate_template);
        let mut duplicate_rule = inv.clone();
        duplicate_rule.rules[1].id = duplicate_rule.rules[0].id.clone();
        variants.push(duplicate_rule);
        for field in ["chain", "rule"] {
            let mut changed = inv.clone();
            changed.rules[0].props.remove(field);
            variants.push(changed);
        }
        let mut empty_id = inv.clone();
        empty_id.connections[0].id.clear();
        variants.push(empty_id);
        for mut invalid in variants {
            invalid.connections[0]
                .props
                .insert("comment".into(), json!("DEVICE_SECRET"));
            let error = config_guard(&invalid, "blue").unwrap_err();
            assert!(!format!("{error:#}").contains("DEVICE_SECRET"));
            assert_read_only(&invalid);
        }
    }
}
