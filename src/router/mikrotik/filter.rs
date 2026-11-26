//! Ordered native rules. Fixtures are synthetic/documentation-derived, not captures.
use super::*;
use crate::router::commands::mikrotik::{bool_value, inherited_value, native_equal};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub(crate) const LIVE_WARNING: &str = "live changes; not atomic; shared consumers may be affected.";
pub(crate) const AUDIT_WARNING: &str = "Nested rule references and other protocol consumers may exist; this is not a complete dependency audit.";

pub(crate) struct FilterEligibility {
    pub(crate) consumers: Vec<String>,
}

pub(crate) fn observed_rule_id(id: &str) -> Result<()> {
    ensure!(
        id.starts_with('*') && id.len() > 1 && id[1..].bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid observed native rule ID"
    );
    Ok(())
}

fn template_names(row: &NativeRecord) -> Result<Vec<&str>> {
    let names = match row.props.get("templates") {
        None => vec![],
        Some(Value::String(s)) => s.split(',').collect(),
        Some(Value::Array(v)) => v
            .iter()
            .map(|v| v.as_str().context("unreadable template reference"))
            .collect::<Result<_>>()?,
        _ => anyhow::bail!("unreadable template references"),
    };
    ensure!(
        names.iter().all(|n| !n.is_empty()),
        "empty template reference"
    );
    Ok(names)
}

fn template_ancestors<'a>(
    inv: &'a NativeInventory,
    row: &'a NativeRecord,
) -> Result<BTreeSet<&'a str>> {
    let mut found = BTreeSet::new();
    let mut path = BTreeSet::new();
    let mut pending = template_names(row)?
        .into_iter()
        .map(|n| (n, false))
        .collect::<Vec<_>>();
    while let Some((name, exiting)) = pending.pop() {
        if exiting {
            path.remove(name);
            found.insert(name);
            continue;
        }
        if found.contains(name) {
            continue;
        }
        ensure!(path.insert(name), "cyclic filter consumer inheritance");
        let rows = inv
            .templates
            .iter()
            .filter(|r| r.props.get("name").and_then(Value::as_str) == Some(name))
            .collect::<Vec<_>>();
        ensure!(rows.len() == 1, "unresolved filter template consumer");
        pending.push((name, true));
        for parent in template_names(rows[0])? {
            pending.push((parent, false));
        }
    }
    Ok(found)
}

fn binding(inv: &NativeInventory, row: &NativeRecord, key: &str) -> Result<Option<String>> {
    // Resolve even when overridden, so unreadable/cyclic reference inventories
    // cannot silently be declared safe. Explicit values still take precedence.
    let inherited = inherited_value(inv, row, key)?;
    match row.props.get(key).cloned().or(inherited) {
        None => Ok(None),
        Some(Value::String(s)) if !s.is_empty() => Ok(Some(s)),
        _ => anyhow::bail!("filter binding representation is unresolved"),
    }
}

pub(crate) fn filter_eligibility(
    snapshot: &MikroTikSnapshot,
    chain: &str,
) -> Result<FilterEligibility> {
    config_guard(&snapshot.inventory, &snapshot.instance)?;
    let inv = &snapshot.inventory;
    ensure!(
        !inv.known_other_protocol_chains.contains(chain),
        "known other-protocol consumer makes this chain read-only"
    );
    let rules = inv
        .rules
        .iter()
        .filter(|r| r.props.get("chain").and_then(Value::as_str) == Some(chain))
        .collect::<Vec<_>>();
    ensure!(!rules.is_empty(), "native chain is unavailable");
    for row in rules {
        observed_rule_id(&row.id)?;
        let _draft = rule_draft(row)?;
        crate::router::commands::mikrotik::check_existing_rule_budget(row)
            .context("existing rule exceeds client edit/command budget or supported controls; view-only, full source retained")?;
        ensure!(
            !row.props
                .get("dynamic")
                .is_some_and(|v| bool_value(v) != Some(false)),
            "dynamic/unknown rule kind is read-only"
        );
    }
    let mut consumers = Vec::new();
    let keys = [
        "input.filter",
        "output.filter-chain",
        "output.filter-select",
        "input.filter-nlri",
    ];
    let ancestors = inv
        .connections
        .iter()
        .map(|r| template_ancestors(inv, r))
        .collect::<Result<Vec<_>>>()?;
    for row in &inv.connections {
        for key in keys {
            if binding(inv, row, key)?.as_deref() == Some(chain) {
                ensure!(
                    connection_scope(inv, &snapshot.instance, row) == ScopeEligibility::Main,
                    "direct/inherited filter consumer is outside selected effective-main scope"
                );
                consumers.push(format!(
                    "connection {} [{}] instance={} {key} (direct/effective inherited)",
                    row.props["name"], row.id, row.props["instance"]
                ));
            }
        }
    }
    for template in &inv.templates {
        let name = template
            .props
            .get("name")
            .and_then(Value::as_str)
            .context("template identity unavailable")?;
        for key in keys {
            if binding(inv, template, key)?.as_deref() == Some(chain) {
                let users = inv
                    .connections
                    .iter()
                    .zip(&ancestors)
                    .filter(|(_, parents)| parents.contains(name))
                    .map(|(r, _)| r)
                    .collect::<Vec<_>>();
                ensure!(
                    !users.is_empty(),
                    "template consumer set is unresolved; chain is read-only"
                );
                ensure!(
                    users
                        .iter()
                        .all(|r| connection_scope(inv, &snapshot.instance, r)
                            == ScopeEligibility::Main),
                    "template has a non-main/outside/unresolved consumer"
                );
                consumers.push(format!(
                    "template {} [{}] {key}; all {} known connection consumers selected-main",
                    json!(name),
                    template.id,
                    users.len()
                ));
            }
        }
    }
    Ok(FilterEligibility { consumers })
}

pub(crate) fn known_filter_consumers(snapshot: &MikroTikSnapshot, chain: &str) -> Vec<String> {
    let mut known = BTreeSet::new();
    for (kind, rows) in [
        ("connection", &snapshot.inventory.connections),
        ("template", &snapshot.inventory.templates),
    ] {
        for row in rows {
            for key in [
                "input.filter",
                "output.filter-chain",
                "output.filter-select",
                "input.filter-nlri",
            ] {
                if row.props.get(key).and_then(Value::as_str) == Some(chain)
                    || binding(&snapshot.inventory, row, key)
                        .ok()
                        .flatten()
                        .as_deref()
                        == Some(chain)
                {
                    known.insert(format!(
                        "{kind} {} [{}] instance={} {key} (direct/effective inherited)",
                        row.props.get("name").unwrap_or(&Value::Null),
                        row.id,
                        row.props.get("instance").unwrap_or(&Value::Null)
                    ));
                }
            }
        }
    }
    known.into_iter().collect()
}

pub(crate) fn rule_draft(row: &NativeRecord) -> Result<NativeRuleDraft> {
    Ok(NativeRuleDraft {
        text: row
            .props
            .get("rule")
            .and_then(Value::as_str)
            .context("rule text is unreadable")?
            .into(),
        comment: match row.props.get("comment") {
            None => String::new(),
            Some(Value::String(s)) => s.clone(),
            _ => anyhow::bail!("rule comment is unreadable"),
        },
        disabled: row
            .props
            .get("disabled")
            .and_then(bool_value)
            .context("rule administrative state is unreadable")?,
    })
}

pub(crate) fn draft_properties(draft: &NativeRuleDraft) -> Properties {
    Properties::from([
        ("rule".into(), json!(draft.text)),
        ("comment".into(), json!(draft.comment)),
        ("disabled".into(), json!(draft.disabled)),
    ])
}

pub(crate) fn changed_properties(row: &NativeRecord, draft: &NativeRuleDraft) -> Properties {
    draft_properties(draft)
        .into_iter()
        .filter(|(k, v)| {
            if k == "comment" && !row.props.contains_key(k) && draft.comment.is_empty() {
                return false;
            }
            !row.props.get(k).is_some_and(|old| native_equal(k, old, v))
        })
        .collect()
}

pub(crate) fn ensure_enabled_rule_survives(rules: &[NativeRecord]) -> Result<()> {
    ensure!(
        rules
            .iter()
            .any(|r| r.props.get("disabled").and_then(bool_value) == Some(false)),
        "at least one enabled rule must survive every intermediate state"
    );
    Ok(())
}

pub(crate) fn ensure_same_chain_targets(
    rules: &[NativeRecord],
    edit: &NativeRuleEdit,
    chain: &str,
) -> Result<()> {
    ensure!(
        rules.iter().map(|r| &r.id).collect::<BTreeSet<_>>().len() == rules.len(),
        "duplicate rule identity"
    );
    let (target, anchor) = match edit {
        NativeRuleEdit::Insert { before, .. } => (None, before.as_ref()),
        NativeRuleEdit::Update { id, .. } | NativeRuleEdit::Delete { id } => (Some(id), None),
        NativeRuleEdit::Move { id, before } => (Some(id), before.as_ref()),
    };
    ensure!(
        target.is_none() || target != anchor,
        "a rule cannot anchor to itself"
    );
    for id in target.into_iter().chain(anchor) {
        ensure!(rules.iter().any(|r|r.id==*id && r.props.get("chain").and_then(Value::as_str)==Some(chain)),
            "rule target or anchor is missing/foreign");
    }
    Ok(())
}

pub(crate) fn simulate_rule_edit(
    rules: &[NativeRecord],
    edit: &NativeRuleEdit,
) -> Result<Vec<NativeRecord>> {
    let chain = match edit {
        NativeRuleEdit::Insert { .. } => rules.first(),
        NativeRuleEdit::Update { id, .. }
        | NativeRuleEdit::Delete { id }
        | NativeRuleEdit::Move { id, .. } => rules.iter().find(|r| r.id == *id),
    }
    .and_then(|r| r.props.get("chain"))
    .and_then(Value::as_str)
    .context("native chain is unavailable")?;
    ensure_same_chain_targets(rules, edit, chain)?;
    let mut after = rules.to_vec();
    match edit {
        NativeRuleEdit::Insert { before, rule } => {
            ensure!(!rule.text.trim().is_empty(), "empty native rule text");
            let mut slot = 0;
            while after.iter().any(|r| r.id == format!("@insert/{slot}")) {
                slot += 1;
            }
            let mut props = draft_properties(rule);
            props.insert("chain".into(), json!(chain));
            let pos = before
                .as_ref()
                .and_then(|id| after.iter().position(|r| r.id == *id))
                .unwrap_or(after.len());
            // A purely local symbol: never sent to RouterOS or presented as an observed ID.
            after.insert(
                pos,
                NativeRecord {
                    id: format!("@insert/{slot}"),
                    props,
                },
            );
        }
        NativeRuleEdit::Update { id, rule } => {
            ensure!(!rule.text.trim().is_empty(), "empty native rule text");
            let row = after
                .iter_mut()
                .find(|r| r.id == *id)
                .context("rule missing")?;
            row.props.extend(changed_properties(row, rule));
        }
        NativeRuleEdit::Delete { id } => after.retain(|r| r.id != *id),
        NativeRuleEdit::Move { id, before } => {
            let pos = after
                .iter()
                .position(|r| r.id == *id)
                .context("rule missing")?;
            let row = after.remove(pos);
            let pos = before
                .as_ref()
                .and_then(|id| after.iter().position(|r| r.id == *id))
                .unwrap_or(after.len());
            after.insert(pos, row);
        }
    }
    Ok(after)
}

pub fn validate_filter_change(
    snapshot: &MikroTikSnapshot,
    change: &NativeFilterChange,
) -> Result<()> {
    let eligibility = filter_eligibility(snapshot, &change.chain)?;
    ensure!(
        eligibility.consumers.is_empty() || change.shared_acknowledged,
        "explicit shared-chain acknowledgment required"
    );
    ensure!(!change.edits.is_empty(), "no native filter edits requested");
    let mut expected = snapshot
        .inventory
        .rules
        .iter()
        .filter(|r| r.props.get("chain").and_then(Value::as_str) == Some(change.chain.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    for edit in &change.edits {
        if matches!(edit, NativeRuleEdit::Insert { .. }) {
            ensure_enabled_rule_survives(&expected)?;
        }
        ensure_same_chain_targets(&expected, edit, &change.chain)?;
        // Public references select observed source records only, never a fabricated
        // inserted ID. Symbolic references exist solely in the private step plan.
        match edit {
            NativeRuleEdit::Insert { before, .. } => {
                if let Some(id) = before {
                    observed_rule_id(id)?;
                }
            }
            NativeRuleEdit::Move { id, before } => {
                observed_rule_id(id)?;
                if let Some(id) = before {
                    observed_rule_id(id)?;
                }
            }
            NativeRuleEdit::Update { id, .. } | NativeRuleEdit::Delete { id } => {
                observed_rule_id(id)?
            }
        }
        expected = simulate_rule_edit(&expected, edit)?;
        ensure_enabled_rule_survives(&expected)?;
    }
    Ok(())
}

pub(crate) fn compile_rule_edit(
    before: &[NativeRecord],
    after: &[NativeRecord],
    edit: &NativeRuleEdit,
    operation: uuid::Uuid,
) -> Result<Vec<crate::router::commands::mikrotik::CompiledStep>> {
    crate::router::commands::mikrotik::compile_concrete_rule_edit(before, after, edit, operation)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use serde_json::json;

    fn draft(text: &str, disabled: bool) -> NativeRuleDraft {
        NativeRuleDraft {
            text: text.into(),
            comment: "raw α\n\"\\$".into(),
            disabled,
        }
    }
    fn update() -> NativeFilterChange {
        NativeFilterChange {
            chain: "blue-in".into(),
            edits: vec![NativeRuleEdit::Update {
                id: "*5".into(),
                rule: draft("accept;", false),
            }],
            shared_acknowledged: true,
        }
    }

    #[test]
    fn mikrotik_filter_cannot_drop_last_enabled_rule() {
        let snapshot = documented_snapshot();
        let chain = snapshot.inventory.rules[0].props["chain"]
            .as_str()
            .unwrap()
            .to_owned();
        let change = NativeFilterChange {
            chain,
            edits: vec![NativeRuleEdit::Delete {
                id: snapshot.inventory.rules[0].id.clone(),
            }],
            shared_acknowledged: true,
        };
        assert!(validate_filter_change(&snapshot, &change).is_err());
    }

    #[test]
    fn mikrotik_filter_every_intermediate_state_keeps_an_enabled_rule() {
        for first in [
            NativeRuleEdit::Delete { id: "*5".into() },
            NativeRuleEdit::Update {
                id: "*5".into(),
                rule: draft("reject;", true),
            },
        ] {
            let change = NativeFilterChange {
                chain: "blue-in".into(),
                shared_acknowledged: true,
                edits: vec![
                    first,
                    NativeRuleEdit::Insert {
                        before: None,
                        rule: draft("reject;", false),
                    },
                ],
            };
            assert!(validate_filter_change(&documented_snapshot(), &change).is_err());
        }
    }

    #[test]
    fn mikrotik_filter_targets_and_anchors_fail_closed() {
        for edit in [
            NativeRuleEdit::Move {
                id: "*5".into(),
                before: Some("*6".into()),
            },
            NativeRuleEdit::Move {
                id: "*5".into(),
                before: Some("*5".into()),
            },
            NativeRuleEdit::Move {
                id: "*7".into(),
                before: None,
            },
            NativeRuleEdit::Insert {
                before: Some("*7".into()),
                rule: draft("accept;", false),
            },
            NativeRuleEdit::Delete { id: "*6".into() },
        ] {
            let change = NativeFilterChange {
                chain: "blue-in".into(),
                edits: vec![edit],
                shared_acknowledged: true,
            };
            assert!(validate_filter_change(&documented_snapshot(), &change).is_err());
        }
        let mut snapshot = documented_snapshot();
        snapshot
            .inventory
            .rules
            .push(snapshot.inventory.rules[0].clone());
        assert!(validate_filter_change(&snapshot, &update()).is_err());
    }

    #[test]
    fn mikrotik_filter_dependency_table_rejects_nonmain_outside_and_unresolved_consumers() {
        for case in [
            "missing-inventory",
            "direct-table",
            "direct-vrf",
            "inherited-table",
            "outside-instance",
            "other-protocol",
            "unresolved-template",
            "unused-template",
            "malformed-binding",
        ] {
            let mut s = documented_snapshot();
            match case {
                "missing-inventory" => s.inventory.bgp_reference_inventory_complete = false,
                "direct-table" => {
                    s.inventory.connections[0]
                        .props
                        .insert("routing-table".into(), json!("red"));
                }
                "direct-vrf" => {
                    s.inventory.connections[0]
                        .props
                        .insert("vrf".into(), json!("red"));
                }
                "inherited-table" => {
                    s.inventory.templates.push(record(
                        json!({".id":"*20","name":"base","routing-table":"red"}),
                    ));
                    s.inventory.connections[0]
                        .props
                        .insert("templates".into(), json!("base"));
                }
                "outside-instance" => {
                    s.inventory.connections[0]
                        .props
                        .insert("instance".into(), json!("red"));
                }
                "other-protocol" => {
                    s.inventory
                        .known_other_protocol_chains
                        .insert("blue-in".into());
                }
                "unresolved-template" => {
                    s.inventory.connections[0]
                        .props
                        .insert("templates".into(), json!("missing"));
                }
                "unused-template" => {
                    s.inventory.templates.push(record(
                        json!({".id":"*20","name":"unused","input.filter":"blue-in"}),
                    ));
                }
                _ => {
                    s.inventory.connections[0]
                        .props
                        .insert("input.filter".into(), json!(null));
                }
            }
            assert!(validate_filter_change(&s, &update()).is_err(), "{case}");
        }
    }

    #[test]
    fn mikrotik_filter_selected_main_shared_consumers_require_distinct_ack() {
        let s = documented_snapshot();
        let mut c = update();
        c.shared_acknowledged = false;
        assert!(validate_filter_change(&s, &c).is_err());
        c.shared_acknowledged = true;
        assert!(validate_filter_change(&s, &c).is_ok());
        let mut s = s;
        s.inventory.templates.push(record(
            json!({".id":"*20","name":"base","input.filter":"blue-in","vrf":"main"}),
        ));
        s.inventory.connections[0].props.remove("input.filter");
        s.inventory.connections[0]
            .props
            .insert("templates".into(), json!("base"));
        assert!(validate_filter_change(&s, &c).is_ok());
        s.inventory.templates[0]
            .props
            .insert("vrf".into(), json!("red"));
        assert!(validate_filter_change(&s, &c).is_err());
    }

    #[test]
    fn mikrotik_filter_simulation_preserves_untouched_source_and_unknown_metadata() {
        let first = record(
            json!({".id":"*A","chain":"c","rule":"old;","comment":"old","disabled":false,"future":{"raw":"α\n\"\\$"}}),
        );
        let second = record(
            json!({".id":"*2","chain":"c","rule":"untouched\n$","comment":"α\n","disabled":false,"future":[null,"0007"]}),
        );
        let rules = vec![first.clone(), second.clone()];
        let after = simulate_rule_edit(
            &rules,
            &NativeRuleEdit::Update {
                id: "*A".into(),
                rule: draft("α\n\"; /system/reboot; $x", false),
            },
        )
        .unwrap();
        assert_eq!(after[0].props["rule"], "α\n\"; /system/reboot; $x");
        assert_eq!(after[0].props["comment"], "raw α\n\"\\$");
        assert_eq!(after[0].props["future"], first.props["future"]);
        assert_eq!(after[1], second);
        assert_eq!(rules[0], first);
        let moved = simulate_rule_edit(
            &rules,
            &NativeRuleEdit::Move {
                id: "*2".into(),
                before: Some("*A".into()),
            },
        )
        .unwrap();
        assert_eq!(
            moved.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["*2", "*A"]
        );
        assert_eq!(moved[0], second);
    }

    fn insert_preview(s: &MikroTikSnapshot) -> NativePreview {
        NativePreview {
            router_id: s.router_id,
            operation: uuid::Uuid::from_u128(42),
            registration: s.registration.clone(),
            generation: s.generation,
            instance: s.instance.clone(),
            guard: s.guard.clone(),
            visible_diff: vec![],
            warnings: vec![],
            intent: NativeIntent::Filter(NativeFilterChange {
                chain: "blue-in".into(),
                shared_acknowledged: true,
                edits: vec![NativeRuleEdit::Insert {
                    before: Some("*5".into()),
                    rule: draft("accept;", false),
                }],
            }),
        }
    }
    fn insert_states(s: &MikroTikSnapshot, new_id: &str) -> Vec<NativeInventory> {
        let mut added = s.inventory.clone();
        added.rules.push(record(json!({".id":new_id,"chain":"blue-in","rule":"accept;","comment":"raw α\n\"\\$","disabled":true,"future":{"default":"raw"}})));
        let mut moved = added.clone();
        let row = moved.rules.remove(2);
        moved.rules.insert(0, row);
        let mut enabled = moved.clone();
        enabled.rules[0]
            .props
            .insert("disabled".into(), json!(false));
        vec![added, moved, enabled]
    }
    fn insert_replies(
        s: &MikroTikSnapshot,
        states: &[NativeInventory],
        marker: &str,
    ) -> Vec<Reply> {
        let mut replies = configuration_replies(&s.inventory);
        for (i, inv) in states.iter().enumerate() {
            if i > 0 {
                replies.extend(configuration_replies(&states[i - 1]));
            }
            replies.push(Reply::Data(json!({"id":marker,"applied":true})));
            replies.extend(configuration_replies(inv));
        }
        replies
    }

    #[tokio::test]
    async fn mikrotik_filter_rf3_insert_disabled_bind_position_enable_three_verified_steps() {
        let s = documented_snapshot();
        let io = TranscriptExecutor::new(insert_replies(&s, &insert_states(&s, "*AB"), "*AB"));
        let receipt = apply_native(&io, insert_preview(&s)).await;
        assert_eq!(
            receipt.outcome,
            NativeOutcome::VerifiedApplied,
            "{}",
            receipt.summary
        );
        assert_eq!(io.mutation_attempts(), 3);
        assert_eq!(receipt.verified_steps.len(), 3);
        assert!(receipt.verified_steps[0].contains("id=\"*AB\""));
        assert!(
            receipt.summary.contains("chain=\"blue-in\"") && receipt.summary.contains("Insert")
        );
        let stored = serde_json::to_string(&receipt).unwrap();
        assert!(!stored.contains("accept;") && !stored.contains("raw α"));
    }

    #[test]
    fn mikrotik_filter_preview_lists_order_raw_properties_consumers_and_exact_warning() {
        let s = documented_snapshot();
        let preview =
            preview_native(&s, insert_preview(&s).intent, uuid::Uuid::from_u128(42)).unwrap();
        let text = preview.visible_diff.join("\n");
        assert!(
            text.contains("BEFORE")
                && text.contains("AFTER")
                && text.contains("*5")
                && text.contains("accept;")
        );
        assert!(text.contains("peer-a") && text.contains("peer-b"));
        assert!(preview
            .warnings
            .iter()
            .any(|s| s == "live changes; not atomic; shared consumers may be affected."));
        assert!(preview
            .warnings
            .iter()
            .any(|s| s.contains("not a complete dependency audit")));
        assert!(!format!("{preview:?}").contains("accept;"));
    }

    #[tokio::test]
    async fn mikrotik_filter_binding_needs_marker_exact_new_object_chain_and_reserved_id() {
        for case in [
            "marker-only",
            "wrong-id",
            "wrong-chain",
            "oversize-id",
            "bad-marker",
            "old-record-change",
        ] {
            let s = documented_snapshot();
            let long_id = format!("*{}", "A".repeat(64)); // 65 bytes: exceeds PRIVATE application reservation.
            let actual = if case == "oversize-id" {
                long_id.as_str()
            } else {
                "*AB"
            };
            let mut added = insert_states(&s, actual).remove(0);
            match case {
                "marker-only" => added = s.inventory.clone(),
                "wrong-chain" => {
                    added.rules[2]
                        .props
                        .insert("chain".into(), json!("blue-out"));
                }
                "old-record-change" => {
                    added.rules[0]
                        .props
                        .insert("comment".into(), json!("external"));
                }
                _ => {}
            }
            let mut replies = configuration_replies(&s.inventory);
            replies.push(Reply::Data(if case == "bad-marker" {
                json!({"id":actual,"applied":true,"extra":true})
            } else {
                json!({"id":if case=="wrong-id" {"*AC"} else {actual},"applied":true})
            }));
            replies.extend(configuration_replies(&added));
            let io = TranscriptExecutor::new(replies);
            let r = apply_native(&io, insert_preview(&s)).await;
            assert_eq!(r.outcome, NativeOutcome::Indeterminate, "{case}");
            assert_eq!(io.mutation_attempts(), 1, "{case}");
            assert!(
                r.verified_steps.is_empty()
                    && r.uncertain_steps.len() == 1
                    && r.unapplied_steps.len() == 2,
                "{case}"
            );
        }
    }

    fn existing_marker_replies(s: &MikroTikSnapshot, added: &NativeInventory) -> Vec<Reply> {
        let mut replies = configuration_replies(&s.inventory);
        replies.push(Reply::Data(json!({"id":"*5","applied":true})));
        replies.extend(configuration_replies(added));
        // Valid next-step pre/post reads and matching mutation envelopes remain
        // available. An unsafe following write must fail the assertions, never
        // accidentally look safe because the transcript runs out of replies.
        for _ in 0..2 {
            replies.extend(configuration_replies(added));
            replies.push(Reply::Data(json!({"id":"*5","applied":true})));
            replies.extend(configuration_replies(added));
        }
        replies
    }

    #[tokio::test]
    async fn mikrotik_filter_fix1_existing_same_chain_marker_cannot_bind_before_move() {
        let s = documented_snapshot();
        let added = insert_states(&s, "*AB").remove(0);
        assert_eq!(added.rules[0].id, "*5");
        assert_eq!(added.rules[2].id, "*AB");
        assert_eq!(added.rules[0], s.inventory.rules[0]);
        let io = TranscriptExecutor::new(existing_marker_replies(&s, &added));
        let r = apply_native(&io, insert_preview(&s)).await;
        assert_eq!(
            io.mutation_attempts(),
            1,
            "an old-ID marker must not authorize a following move"
        );
        assert_eq!(r.outcome, NativeOutcome::Indeterminate);
        assert!(r.verified_steps.is_empty());
        assert_eq!(r.uncertain_steps, vec!["Insert disabled native rule"]);
        assert_eq!(
            r.unapplied_steps,
            vec![
                "Position exact native rule",
                "Set native rule properties/state"
            ]
        );
    }

    #[tokio::test]
    async fn mikrotik_filter_fix1_existing_same_chain_marker_cannot_bind_on_append() {
        let s = documented_snapshot();
        let added = insert_states(&s, "*AB").remove(0);
        let mut p = insert_preview(&s);
        if let NativeIntent::Filter(c) = &mut p.intent {
            c.edits = vec![NativeRuleEdit::Insert {
                before: None,
                rule: draft("accept;", false),
            }];
        }
        let io = TranscriptExecutor::new(existing_marker_replies(&s, &added));
        let r = apply_native(&io, p).await;
        assert_eq!(
            io.mutation_attempts(),
            1,
            "verified append must not bind an existing rule for state changes"
        );
        assert_eq!(r.outcome, NativeOutcome::Indeterminate);
        assert!(r.verified_steps.is_empty());
        assert_eq!(r.uncertain_steps, vec!["Insert disabled native rule"]);
        assert_eq!(r.unapplied_steps, vec!["Set native rule properties/state"]);
    }

    #[tokio::test]
    async fn mikrotik_filter_fix1_existing_identical_rule_marker_cannot_verify_noop_append() {
        let mut s = documented_snapshot();
        s.inventory.rules[0] = record(json!({".id":"*5","chain":"blue-in","rule":"accept;",
            "comment":"raw α\n\"\\$","disabled":true,"future":{"default":"raw"}}));
        s.inventory.rules.push(record(
            json!({".id":"*7","chain":"blue-in","rule":"reject;","disabled":false}),
        ));
        s.guard = config_guard(&s.inventory, "blue").unwrap();
        let mut added = s.inventory.clone();
        added.rules.push(record(
            json!({".id":"*AB","chain":"blue-in","rule":"accept;",
            "comment":"raw α\n\"\\$","disabled":true,"future":{"default":"raw"}}),
        ));
        assert_eq!(added.rules[0].props, added.rules[3].props);
        assert_eq!(added.rules[0].id, "*5");
        assert_eq!(added.rules[3].id, "*AB");
        let mut p = insert_preview(&s);
        if let NativeIntent::Filter(c) = &mut p.intent {
            c.edits = vec![NativeRuleEdit::Insert {
                before: None,
                rule: draft("accept;", true),
            }];
        }
        let io = TranscriptExecutor::new(existing_marker_replies(&s, &added));
        let r = apply_native(&io, p).await;
        assert_eq!(
            r.outcome,
            NativeOutcome::Indeterminate,
            "identical properties do not establish the newly created ID"
        );
        assert_eq!(io.mutation_attempts(), 1);
        assert!(r.verified_steps.is_empty());
        assert_eq!(r.uncertain_steps, vec!["Insert disabled native rule"]);
        assert!(r.unapplied_steps.is_empty());
    }

    #[tokio::test]
    async fn mikrotik_filter_binding_accepts_exact_64_byte_application_reservation() {
        let s = documented_snapshot();
        let id = format!("*{}", "A".repeat(63));
        let io = TranscriptExecutor::new(insert_replies(&s, &insert_states(&s, &id), &id));
        let r = apply_native(&io, insert_preview(&s)).await;
        assert_eq!(r.outcome, NativeOutcome::VerifiedApplied);
        assert_eq!(io.mutation_attempts(), 3);
    }

    #[tokio::test]
    async fn mikrotik_filter_rf4_external_change_before_next_step_is_not_absorbed() {
        for case in ["comment", "order", "binding", "template"] {
            let s = documented_snapshot();
            let added = insert_states(&s, "*AB").remove(0);
            let mut changed = added.clone();
            match case {
                "comment" => {
                    changed.rules[0]
                        .props
                        .insert("comment".into(), json!("external"));
                }
                "order" => changed.rules.swap(0, 1),
                "binding" => {
                    changed.connections[0]
                        .props
                        .insert("input.filter".into(), json!("external"));
                }
                _ => changed
                    .templates
                    .push(record(json!({".id":"*20","name":"external","vrf":"red"}))),
            }
            let mut replies = configuration_replies(&s.inventory);
            replies.push(Reply::Data(json!({"id":"*AB","applied":true})));
            replies.extend(configuration_replies(&added));
            replies.extend(configuration_replies(&changed));
            let io = TranscriptExecutor::new(replies);
            let r = apply_native(&io, insert_preview(&s)).await;
            assert_eq!(r.outcome, NativeOutcome::PartialApplication, "{case}");
            assert_eq!(io.mutation_attempts(), 1, "{case}");
            assert_eq!(r.verified_steps.len(), 1);
            assert_eq!(r.unapplied_steps.len(), 2);
        }
    }

    #[tokio::test]
    async fn mikrotik_filter_complete_utf8_payloads_and_stale_guard_reject_before_first_write() {
        let s = documented_snapshot();
        for case in ["utf8-budget", "stale", "ack", "late-anchor"] {
            let mut p = insert_preview(&s);
            let mut inv = s.inventory.clone();
            if let NativeIntent::Filter(change) = &mut p.intent {
                match case {
                    "utf8-budget" => change.edits.push(NativeRuleEdit::Update {
                        id: "*5".into(),
                        rule: draft(&"α".repeat(17000), false),
                    }),
                    "ack" => change.shared_acknowledged = false,
                    "late-anchor" => change.edits.push(NativeRuleEdit::Move {
                        id: "*5".into(),
                        before: Some("*BAD".into()),
                    }),
                    _ => {
                        inv.connections[0]
                            .props
                            .insert("comment".into(), json!("external"));
                    }
                }
            }
            let io = TranscriptExecutor::new(configuration_replies(&inv));
            let r = apply_native(&io, p).await;
            assert_eq!(r.outcome, NativeOutcome::RejectedBeforeWrite, "{case}");
            assert_eq!(io.mutation_attempts(), 0, "{case}");
        }
    }

    #[tokio::test]
    async fn mikrotik_filter_update_state_delete_are_minimal_and_keep_raw_untouched_rows() {
        let mut s = documented_snapshot();
        s.inventory.rules.push(record(json!({".id":"*7","chain":"blue-in","rule":"accept;","disabled":false,"comment":"α\n$","future":{"raw":"0007"}})));
        s.guard = config_guard(&s.inventory, "blue").unwrap();
        let change = NativeFilterChange {
            chain: "blue-in".into(),
            shared_acknowledged: true,
            edits: vec![
                NativeRuleEdit::Update {
                    id: "*5".into(),
                    rule: NativeRuleDraft {
                        text: "reject;".into(),
                        comment: "α\n\"\\$".into(),
                        disabled: true,
                    },
                },
                NativeRuleEdit::Delete { id: "*5".into() },
            ],
        };
        let p =
            preview_native(&s, NativeIntent::Filter(change), uuid::Uuid::from_u128(42)).unwrap();
        let mut patched = s.inventory.clone();
        patched.rules[0]
            .props
            .insert("comment".into(), json!("α\n\"\\$"));
        patched.rules[0]
            .props
            .insert("disabled".into(), json!(true));
        let mut deleted = patched.clone();
        deleted.rules.remove(0);
        let mut replies = configuration_replies(&s.inventory);
        replies.push(Reply::Data(json!({"id":"*5","applied":true})));
        replies.extend(configuration_replies(&patched));
        replies.extend(configuration_replies(&patched));
        replies.push(Reply::Data(json!({"id":"*5","applied":true})));
        replies.extend(configuration_replies(&deleted));
        let io = TranscriptExecutor::new(replies);
        let r = apply_native(&io, p).await;
        assert_eq!(r.outcome, NativeOutcome::VerifiedApplied);
        assert_eq!(io.mutation_attempts(), 2);
        assert_eq!(r.verified_steps.len(), 2);
        assert!(
            r.summary.contains("Update rule id=\"*5\"")
                && r.summary.contains("Delete rule id=\"*5\"")
        );
        let serialized = serde_json::to_string(&r).unwrap();
        assert!(!serialized.contains("α") && !serialized.contains("reject;"));
    }

    #[tokio::test]
    async fn mikrotik_filter_launched_timeout_or_bad_position_retains_earlier_proof_without_retry()
    {
        for case in ["read-budget", "wrong-order", "wrong-marker"] {
            let s = documented_snapshot();
            let states = insert_states(&s, "*AB");
            let mut replies = configuration_replies(&s.inventory);
            replies.push(Reply::Data(json!({"id":"*AB","applied":true})));
            replies.extend(configuration_replies(&states[0]));
            replies.extend(configuration_replies(&states[0]));
            replies.push(Reply::Data(
                json!({"id":if case=="wrong-marker" {"*5"}else{"*AB"},"applied":true}),
            ));
            if case == "read-budget" {
                replies.push(Reply::Failure {
                    code: "native-time-budget",
                    started: true,
                });
            } else {
                replies.extend(configuration_replies(
                    &states[if case == "wrong-order" { 0 } else { 1 }],
                ));
            }
            let io = TranscriptExecutor::new(replies);
            let r = apply_native(&io, insert_preview(&s)).await;
            assert_eq!(r.outcome, NativeOutcome::Indeterminate, "{case}");
            assert_eq!(io.mutation_attempts(), 2);
            assert_eq!(r.verified_steps.len(), 1);
            assert_eq!(r.uncertain_steps.len(), 1);
            assert_eq!(r.unapplied_steps.len(), 1);
        }
    }

    #[tokio::test]
    async fn mikrotik_filter_later_observed_move_uses_previously_bound_global_rule_id() {
        let s = documented_snapshot();
        let mut p = insert_preview(&s);
        if let NativeIntent::Filter(c) = &mut p.intent {
            c.edits.push(NativeRuleEdit::Move {
                id: "*5".into(),
                before: None,
            });
        }
        let mut states = insert_states(&s, "*AB");
        let mut last = states[2].clone();
        let row = last.rules.remove(1);
        last.rules.push(row); // [*AB,*5,*6] -> [*AB,*6,*5]
        assert_eq!(
            last.rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["*AB", "*6", "*5"]
        );
        states.push(last);
        let mut replies = configuration_replies(&s.inventory);
        for (i, inv) in states.iter().enumerate() {
            if i > 0 {
                replies.extend(configuration_replies(&states[i - 1]));
            }
            replies.push(Reply::Data(
                json!({"id":if i==3 {"*5"}else{"*AB"},"applied":true}),
            ));
            replies.extend(configuration_replies(inv));
        }
        let io = TranscriptExecutor::new(replies);
        let r = apply_native(&io, p).await;
        assert_eq!(r.outcome, NativeOutcome::VerifiedApplied);
        assert_eq!(r.verified_steps.len(), 4);
        assert_eq!(io.mutation_attempts(), 4);
    }

    #[tokio::test]
    async fn mikrotik_filter_end_insert_verifies_append_before_state_and_omits_noop_move() {
        for disabled in [true, false] {
            let s = documented_snapshot();
            let mut p = insert_preview(&s);
            if let NativeIntent::Filter(c) = &mut p.intent {
                c.edits = vec![NativeRuleEdit::Insert {
                    before: None,
                    rule: draft("accept;", disabled),
                }];
            }
            let added = insert_states(&s, "*AB").remove(0);
            let mut enabled = added.clone();
            enabled.rules[2]
                .props
                .insert("disabled".into(), json!(false));
            let states = if disabled {
                vec![added]
            } else {
                vec![added, enabled]
            };
            let io = TranscriptExecutor::new(insert_replies(&s, &states, "*AB"));
            let r = apply_native(&io, p).await;
            assert_eq!(r.outcome, NativeOutcome::VerifiedApplied);
            assert_eq!(io.mutation_attempts(), if disabled { 1 } else { 2 });
            assert!(!io.seen_labels().contains(&"filter.move"));
        }
    }

    #[tokio::test]
    async fn mikrotik_filter_disabled_inserts_bind_distinct_slots_not_identical_rule_text() {
        let s = documented_snapshot();
        let mut p = insert_preview(&s);
        if let NativeIntent::Filter(c) = &mut p.intent {
            let edit = NativeRuleEdit::Insert {
                before: Some("*5".into()),
                rule: draft("accept;", true),
            };
            c.edits = vec![edit.clone(), edit];
        }
        let mut states = insert_states(&s, "*AB");
        states.truncate(2); // no enable requested
        let mut second = states[1].clone();
        let mut row = second.rules[0].clone();
        row.id = "*AC".into();
        second.rules.push(row);
        states.push(second.clone());
        let row = second.rules.remove(3);
        second.rules.insert(1, row);
        states.push(second);
        assert_eq!(
            states[3]
                .rules
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            vec!["*AB", "*AC", "*5", "*6"]
        );
        let mut replies = configuration_replies(&s.inventory);
        for (i, state) in states.iter().enumerate() {
            if i > 0 {
                replies.extend(configuration_replies(&states[i - 1]));
            }
            replies.push(Reply::Data(
                json!({"id":if i<2 {"*AB"}else{"*AC"},"applied":true}),
            ));
            replies.extend(configuration_replies(state));
        }
        let io = TranscriptExecutor::new(replies);
        let r = apply_native(&io, p).await;
        assert_eq!(r.outcome, NativeOutcome::VerifiedApplied);
        assert_eq!(io.mutation_attempts(), 4);
        assert!(
            r.verified_steps[0].contains("id=\"*AB\"")
                && r.verified_steps[2].contains("id=\"*AC\"")
        );
        assert!(!io.seen_labels().contains(&"filter.patch"));
    }
}
