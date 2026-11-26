//! A receipt is evidence, never an executable replay plan.
use super::*;
use crate::router::commands::mikrotik::{
    bind_inserted_rule, compile_native, native_equal, secret_verification, ApprovedChange,
    RuleBindings,
};
use crate::ssh::NativeExecutor;
use anyhow::{ensure, Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;

fn collection<'a>(guard: &'a ConfigGuard, name: &str) -> Result<&'a Vec<Value>> {
    ensure!(
        matches!(name, "connections" | "rules"),
        "invalid compiler-owned collection"
    );
    guard
        .0
        .get(name)
        .and_then(Value::as_array)
        .context("incomplete native guard")
}

fn id(row: &Value) -> Result<&str> {
    row.get(".id")
        .and_then(Value::as_str)
        .filter(|s| {
            s.starts_with('*') && s.len() > 1 && s[1..].bytes().all(|c| c.is_ascii_hexdigit())
        })
        .context("invalid observed native ID")
}

fn matches_properties(row: &Value, props: &Properties) -> bool {
    props.iter().all(|(key, value)| {
        if value.is_null() {
            row.get(key).is_none()
        } else {
            row.get(key).is_some_and(|v| native_equal(key, v, value))
        }
    })
}

/// Advance ONLY the approved delta. Raw untouched fields/objects remain exact;
/// semantics are used exclusively for explicitly changed/required properties.
pub(crate) fn advance_expected(
    before: &ConfigGuard,
    verified_after: &ConfigGuard,
    change: &ApprovedChange,
) -> Result<ConfigGuard> {
    let mut expected = before.clone();
    match change {
        ApprovedChange::Insert {
            collection: name,
            identity,
            required,
        } => {
            let old = collection(before, name)?;
            let after = collection(verified_after, name)?;
            ensure!(
                after.len() == old.len() + 1,
                "insert must create exactly one object"
            );
            let old_ids = old.iter().map(id).collect::<Result<BTreeSet<_>>>()?;
            let new = after
                .iter()
                .filter(|r| id(r).is_ok_and(|v| !old_ids.contains(v)))
                .collect::<Vec<_>>();
            ensure!(
                new.len() == 1
                    && matches_properties(new[0], identity)
                    && matches_properties(new[0], required),
                "insert postcondition unavailable"
            );
            let new_id = id(new[0])?;
            ensure!(
                after.iter().map(id).collect::<Result<BTreeSet<_>>>()?.len() == after.len(),
                "duplicate postcondition ID"
            );
            for row in old {
                ensure!(
                    after.iter().find(|r| id(r).ok() == id(row).ok()) == Some(row),
                    "pre-existing object changed during insert"
                );
            }
            let mut added = old.clone();
            // Only device defaults inside this one verified new object survive.
            added.push(new[0].clone());
            if name == "connections" {
                added.sort_by(|a, b| a[".id"].as_str().cmp(&b[".id"].as_str()));
            } else {
                ensure!(
                    after.last().and_then(|r| id(r).ok()) == Some(new_id),
                    "new rule was not appended"
                );
            }
            expected.0.insert(name.clone(), Value::Array(added));
        }
        ApprovedChange::Patch {
            collection: name,
            id: target,
            set,
        } => {
            let mut rows = collection(before, name)?.clone();
            let before_row = rows
                .iter_mut()
                .find(|row| id(row).ok() == Some(target.as_str()))
                .context("patch target missing")?;
            let after_row = collection(verified_after, name)?
                .iter()
                .find(|row| id(row).ok() == Some(target.as_str()))
                .context("patch target missing after write")?;
            ensure!(
                matches_properties(after_row, set),
                "patch properties not verified"
            );
            let object = before_row.as_object_mut().context("invalid guard object")?;
            for (key, value) in set {
                if value.is_null() {
                    object.remove(key);
                } else {
                    object.insert(key.clone(), after_row[key].clone());
                }
            }
            expected.0.insert(name.clone(), Value::Array(rows));
        }
        ApprovedChange::Remove {
            collection: name,
            id: target,
        } => {
            let old = collection(before, name)?;
            ensure!(
                old.iter()
                    .filter(|row| id(row).ok() == Some(target.as_str()))
                    .count()
                    == 1,
                "remove target missing or ambiguous"
            );
            let rows = old
                .iter()
                .filter(|row| id(row).ok() != Some(target.as_str()))
                .cloned()
                .collect();
            expected.0.insert(name.clone(), Value::Array(rows));
        }
        ApprovedChange::RuleOrder {
            chain,
            id: target,
            before: anchor,
            order_before: prior,
            order_after: order,
        } => {
            let rows = collection(before, "rules")?;
            let observed = rows.iter().map(id).collect::<Result<Vec<_>>>()?;
            ensure!(
                observed
                    .iter()
                    .copied()
                    .eq(prior.iter().map(String::as_str))
                    && observed.iter().collect::<BTreeSet<_>>().len() == observed.len(),
                "rule order before mismatch"
            );
            for wanted in std::iter::once(target).chain(anchor.iter()) {
                ensure!(
                    rows.iter().any(|r| id(r).ok() == Some(wanted.as_str())
                        && r["chain"].as_str() == Some(chain.as_str())),
                    "move target or anchor is missing or foreign"
                );
            }
            ensure!(anchor.as_ref() != Some(target), "self-anchored rule move");
            let mut reordered = rows.clone();
            let from = reordered
                .iter()
                .position(|r| id(r).ok() == Some(target.as_str()))
                .context("move target missing")?;
            let moved = reordered.remove(from);
            let to = match anchor {
                Some(anchor) => reordered
                    .iter()
                    .position(|r| id(r).ok() == Some(anchor.as_str()))
                    .context("move anchor missing")?,
                None => reordered.len(),
            };
            reordered.insert(to, moved);
            ensure!(
                reordered
                    .iter()
                    .map(id)
                    .collect::<Result<Vec<_>>>()?
                    .iter()
                    .copied()
                    .eq(order.iter().map(String::as_str)),
                "invalid approved global move"
            );
            expected.0.insert("rules".into(), Value::Array(reordered));
        }
    }
    ensure!(
        expected == *verified_after,
        "unapproved native configuration delta"
    );
    Ok(expected)
}

struct VerifiedChange {
    after: ConfigGuard,
    approved: ApprovedChange,
    safe_label: String,
}
enum StepResult {
    Verified(VerifiedChange),
    ConfirmedFailure(String),
    Unknown(String),
}

fn filter_action_evidence(change: &NativeFilterChange) -> String {
    let safe_id = |id: &str| {
        if super::filter::observed_rule_id(id).is_ok() {
            serde_json::json!(id).to_string()
        } else {
            "<invalid ID>".into()
        }
    };
    let anchor = |before: &Option<String>| {
        before
            .as_deref()
            .map(&safe_id)
            .unwrap_or_else(|| "end".into())
    };
    change
        .edits
        .iter()
        .map(|edit| match edit {
            NativeRuleEdit::Insert { before, rule } => format!(
                "Insert disabled first, then verified placement before={}, requested disabled={}",
                anchor(before),
                rule.disabled
            ),
            NativeRuleEdit::Update { id, rule } => format!(
                "Update rule id={} (text/comment properties; disabled={})",
                safe_id(id),
                rule.disabled
            ),
            NativeRuleEdit::Delete { id } => format!("Delete rule id={}", safe_id(id)),
            NativeRuleEdit::Move { id, before } => {
                format!("Move rule id={} before={}", safe_id(id), anchor(before))
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn safe_intent_evidence(preview: &NativePreview) -> String {
    let target = match &preview.intent {
        NativeIntent::Filter(change) => format!(
            "filter chain={}",
            serde_json::json!(presentation_text(&change.chain))
        ),
        NativeIntent::Create(draft) => format!(
            "new connection name={} (ID unavailable before creation)",
            serde_json::json!(presentation_text(&draft.name))
        ),
        NativeIntent::Patch { target, .. }
        | NativeIntent::SetDisabled { target, .. }
        | NativeIntent::Delete(target) => {
            format!(
                "connection name={} id={}",
                serde_json::json!(presentation_text(&target.name)),
                serde_json::json!(presentation_text(&target.observed_id))
            )
        }
    };
    let (action, authentication) = match &preview.intent {
        NativeIntent::Filter(change) => (
            filter_action_evidence(change),
            "not applicable (native filter)",
        ),
        NativeIntent::Create(draft) => (
            "Create (disabled=true, both deny-all bindings)".to_owned(),
            match &draft.secret {
                SecretChange::Keep => "Keep",
                SecretChange::Replace(_) => "Replace",
                SecretChange::Clear => "Clear",
            },
        ),
        NativeIntent::Patch { changes, .. } => {
            // Public rejected requests may contain arbitrary property keys.
            // Include only literal allowed names, never raw keys or values
            // (including pasted credentials/commands).
            let mut names = [
                "comment",
                "remote.as",
                "local.role",
                "afi",
                "local.address",
                "hold-time",
                "keepalive-time",
                "nexthop-choice",
                "use-bfd",
                "input.filter",
                "output.filter-chain",
            ]
            .into_iter()
            .filter(|name| changes.properties.contains_key(*name))
            .collect::<Vec<_>>();
            if names.len() != changes.properties.len() {
                names.push("<unsupported property names redacted>");
            }
            (
                format!("Patch properties [{}]", names.join(", ")),
                match &changes.secret {
                    SecretChange::Keep => "Keep",
                    SecretChange::Replace(_) => "Replace",
                    SecretChange::Clear => "Clear",
                },
            )
        }
        NativeIntent::SetDisabled { disabled, .. } => (
            if *disabled {
                "Disable (disabled=true)"
            } else {
                "Enable (disabled=false)"
            }
            .to_owned(),
            "Keep",
        ),
        NativeIntent::Delete(_) => (
            "Delete exact connection only".to_owned(),
            "not applicable (connection deletion)",
        ),
    };
    format!(
        "Target: instance={} {target}; Action: {action}; Authentication: {authentication}.",
        serde_json::json!(presentation_text(&preview.instance))
    )
}

pub(crate) fn rejected_receipt(preview: &NativePreview) -> NativeReceipt {
    let labels: &[&str] = match &preview.intent {
        NativeIntent::Create(_) => &[
            "Create enabled reject input chain",
            "Create enabled reject output chain",
            "Create disabled connection with both deny-all bindings",
        ],
        NativeIntent::Patch { .. } => &["Patch connection properties"],
        NativeIntent::SetDisabled { .. } => &["Set administrative disabled state"],
        NativeIntent::Delete(_) => &["Delete exact connection only"],
        NativeIntent::Filter(_) => &["Native filter edits (not launched)"],
    };
    NativeReceipt {
        router_id: preview.router_id,
        operation: preview.operation,
        instance: preview.instance.clone(),
        registration: preview.registration.clone(),
        outcome: NativeOutcome::RejectedBeforeWrite,
        verified_steps: vec![],
        uncertain_steps: vec![],
        unapplied_steps: labels.iter().map(|s| (*s).to_owned()).collect(),
        summary: format!(
            "{} Rejected before any mutation launch. Refresh and create a new preview.",
            safe_intent_evidence(preview)
        ),
    }
}

fn partial_or_rejected(receipt: &mut NativeReceipt, label: String, evidence: &str) {
    receipt.outcome = if receipt.verified_steps.is_empty() {
        NativeOutcome::RejectedBeforeWrite
    } else {
        NativeOutcome::PartialApplication
    };
    receipt.unapplied_steps.insert(0, label);
    receipt.summary=format!("{evidence} Stopped before launching the next mutation. Earlier verified steps remain applied. Refresh and review; never automatic replay.");
}

fn indeterminate(receipt: &mut NativeReceipt, label: String, evidence: &str) {
    receipt.outcome = NativeOutcome::Indeterminate;
    receipt.uncertain_steps.push(label);
    receipt.summary=format!("{evidence} A mutation launched but its complete effect is unverified. Local cancellation or registration change does not revoke a remote command. Refresh and inspect; no automatic retry or rollback.");
}

fn operation_target(preview: &NativePreview) -> Option<&NativeConnectionRef> {
    match &preview.intent {
        NativeIntent::Patch { target, .. }
        | NativeIntent::SetDisabled { target, .. }
        | NativeIntent::Delete(target) => Some(target),
        NativeIntent::Create(_) | NativeIntent::Filter(_) => None,
    }
}

fn verify_marker(
    data: &Value,
    approved: &ApprovedChange,
    before: &ConfigGuard,
    after: &ConfigGuard,
) -> Result<String> {
    ensure!(
        data.as_object().is_some_and(|o| o.len() == 2) && data["applied"] == Value::Bool(true),
        "invalid mutation postcondition marker"
    );
    let marker = data["id"].as_str().context("missing mutation identity")?;
    match approved {
        ApprovedChange::Insert {
            collection: name,
            identity,
            ..
        } => {
            let old_ids = collection(before, name)?
                .iter()
                .map(id)
                .collect::<Result<BTreeSet<_>>>()?;
            let inserted = collection(after, name)?
                .iter()
                .filter(|row| id(row).is_ok_and(|value| !old_ids.contains(value)))
                .collect::<Vec<_>>();
            // Matching chain/properties do not prove creation. The marker must
            // name the one new row relative to this step's expected-before guard.
            ensure!(
                inserted.len() == 1
                    && id(inserted[0])? == marker
                    && matches_properties(inserted[0], identity),
                "created marker identity mismatch"
            );
        }
        ApprovedChange::Patch { id, .. } | ApprovedChange::Remove { id, .. } => {
            ensure!(marker == id, "mutation marker identity mismatch")
        }
        ApprovedChange::RuleOrder { id, .. } => {
            ensure!(marker == id, "move marker identity mismatch")
        }
    }
    Ok(marker.to_owned())
}

pub async fn apply_native<E: NativeExecutor>(io: &E, preview: NativePreview) -> NativeReceipt {
    let mut receipt = rejected_receipt(&preview);
    // Only a Result-returning private runner uses ?. All public exits are safe,
    // correlated receipts; no dynamic device text/error chain reaches history.
    let _result = run(io, &preview, &mut receipt).await;
    if matches!(preview.intent, NativeIntent::Create(_))
        && receipt.outcome != NativeOutcome::VerifiedApplied
    {
        let (input, output) = crate::router::commands::mikrotik::chain_names(preview.operation);
        receipt.summary.push_str(&format!(" Possible named orphan chains: {input}, {output}; inspect manually. No cleanup performed."));
    }
    receipt
}

async fn run<E: NativeExecutor>(
    io: &E,
    preview: &NativePreview,
    receipt: &mut NativeReceipt,
) -> Result<()> {
    let evidence = safe_intent_evidence(preview);
    ensure!(
        preview.router_id == preview.registration.router_id
            && !preview.operation.is_nil()
            && !preview.generation.is_nil()
            && !preview.instance.trim().is_empty(),
        "invalid native request identity"
    );
    if let Some(target) = operation_target(preview) {
        ensure!(
            target.generation == preview.generation && target.instance == preview.instance,
            "invalid reviewed target generation"
        );
    }
    let mut fresh = super::read::fetch_configuration(
        io,
        &preview.registration,
        preview.operation,
        &preview.instance,
    )
    .await?;
    let mut expected = config_guard(&fresh.inventory, &preview.instance)?;
    ensure!(expected == preview.guard, "stale native configuration");
    let steps = compile_native(
        &fresh,
        &preview.intent,
        preview.operation,
        preview.generation,
    )?;
    let mut secret_check = secret_verification(preview)?; // budget ALL bytes before FIRST write
    receipt.unapplied_steps = steps.iter().map(|s| s.safe_label().to_owned()).collect();
    let mut bindings = RuleBindings::new();
    for (index, plan) in steps.into_iter().enumerate() {
        if index > 0 {
            let guard = super::read::fetch_configuration(
                io,
                &preview.registration,
                preview.operation,
                &preview.instance,
            )
            .await;
            match guard {
                Ok(snapshot)
                    if config_guard(&snapshot.inventory, &preview.instance)
                        .is_ok_and(|g| g == expected) =>
                {
                    fresh = snapshot
                }
                _ => {
                    let label = receipt.unapplied_steps.remove(0);
                    partial_or_rejected(receipt, label, &evidence);
                    return Ok(());
                }
            }
        }
        // Every independently-read connection postcondition also proves scope.
        if let Some(target) = operation_target(preview) {
            if crate::router::commands::mikrotik::target_record(&fresh, target, preview.generation)
                .is_err()
            {
                let label = receipt.unapplied_steps.remove(0);
                partial_or_rejected(receipt, label, &evidence);
                return Ok(());
            }
        }
        if let NativeIntent::Filter(change) = &preview.intent {
            if super::filter::filter_eligibility(&fresh, &change.chain).is_err() {
                let label = receipt.unapplied_steps.remove(0);
                partial_or_rejected(receipt, label, &evidence);
                return Ok(());
            }
        }
        let insertion_slot = plan.insertion_slot();
        let step = match plan.materialize(&bindings) {
            Ok(step) => step,
            Err(_) => {
                let label = receipt.unapplied_steps.remove(0);
                partial_or_rejected(receipt, label, &evidence);
                return Ok(());
            }
        };
        receipt.unapplied_steps.remove(0);
        let result = match io.exec(step.command).await {
            Err(error) if !error.started => StepResult::ConfirmedFailure(step.safe_label),
            Err(_) => {
                // Reconcile by configuration reads only, never replay a command.
                let _ = super::read::fetch_configuration(
                    io,
                    &preview.registration,
                    preview.operation,
                    &preview.instance,
                )
                .await;
                StepResult::Unknown(step.safe_label)
            }
            Ok(data) => {
                let after = super::read::fetch_configuration(
                    io,
                    &preview.registration,
                    preview.operation,
                    &preview.instance,
                )
                .await;
                match after {
                    Ok(snapshot) => {
                        let proof = (|| -> Result<(ConfigGuard, String)> {
                            let after = config_guard(&snapshot.inventory, &preview.instance)?;
                            let marker = verify_marker(&data, &step.approved, &expected, &after)?;
                            advance_expected(&expected, &after, &step.approved)?;
                            if let Some(slot) = insertion_slot {
                                ensure!(
                                    matches!(&step.approved,ApprovedChange::Insert{collection,..} if collection=="rules"),
                                    "invalid rule slot proof"
                                );
                                // This is the only binding point: marker AND unique
                                // exact independent Insert proof have both succeeded.
                                bind_inserted_rule(&mut bindings, slot, &marker)?;
                            }
                            // RouterOS IDs are menu-local. A new filter rule
                            // may share its ID with a foreign connection; only
                            // connection changes may select a connection here.
                            if matches!(&step.approved,ApprovedChange::Patch{collection,..}|ApprovedChange::Insert{collection,..} if collection=="connections")
                            {
                                let row = snapshot
                                    .inventory
                                    .connections
                                    .iter()
                                    .find(|row| row.id == marker)
                                    .context("connection postcondition identity unavailable")?;
                                ensure!(
                                    connection_scope(&snapshot.inventory, &preview.instance, row)
                                        == ScopeEligibility::Main,
                                    "postcondition scope unavailable"
                                );
                            }
                            Ok((after, marker))
                        })();
                        match proof {
                            Ok((after, marker)) => {
                                fresh = snapshot;
                                let safe_label = if matches!(&step.approved,ApprovedChange::Insert{collection,..} if collection=="connections")
                                {
                                    format!(
                                        "{}; observed connection id={}",
                                        step.safe_label,
                                        serde_json::json!(presentation_text(&marker))
                                    )
                                } else if insertion_slot.is_some() {
                                    format!(
                                        "{}; observed rule id={}",
                                        step.safe_label,
                                        serde_json::json!(presentation_text(&marker))
                                    )
                                } else {
                                    step.safe_label
                                };
                                let needs_secret = matches!(&step.approved,ApprovedChange::Patch{collection,..}|ApprovedChange::Insert{collection,..} if collection=="connections");
                                let private_verified = if needs_secret {
                                    match secret_check.take() {
                                        None => true,
                                        Some(command) => io.exec(command).await.is_ok_and(|v| {
                                            v.as_object().is_some_and(|o| o.len() == 2)
                                                && v["verified"] == Value::Bool(true)
                                                && v["id"].as_str() == Some(marker.as_str())
                                        }),
                                    }
                                } else {
                                    true
                                };
                                if private_verified {
                                    StepResult::Verified(VerifiedChange {
                                        after,
                                        approved: step.approved,
                                        safe_label,
                                    })
                                } else {
                                    StepResult::Unknown(safe_label)
                                }
                            }
                            Err(_) => StepResult::Unknown(step.safe_label),
                        }
                    }
                    Err(_) => StepResult::Unknown(step.safe_label),
                }
            }
        };
        match result {
            StepResult::Verified(change) => {
                match advance_expected(&expected, &change.after, &change.approved) {
                    Ok(guard) => expected = guard,
                    Err(_) => {
                        indeterminate(receipt, change.safe_label, &evidence);
                        return Ok(());
                    }
                }
                receipt.verified_steps.push(change.safe_label);
            }
            StepResult::ConfirmedFailure(label) => {
                partial_or_rejected(receipt, label, &evidence);
                return Ok(());
            }
            StepResult::Unknown(label) => {
                indeterminate(receipt, label, &evidence);
                return Ok(());
            }
        }
    }
    receipt.outcome = NativeOutcome::VerifiedApplied;
    receipt.summary=format!("{evidence} All reviewed configuration steps independently verified. Not proof of BGP establishment, BFD, or operational authentication.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::commands::mikrotik::ApprovedChange;
    use crate::router::mikrotik::test_support::*;
    use serde_json::json;

    #[test]
    fn mikrotik_apply_advance_allows_only_approved_property_and_preserves_unknowns() {
        let mut inv = documented_inventory();
        inv.connections[0]
            .props
            .insert("vendor.future".into(), json!({"opaque":"unchanged"}));
        let before = config_guard(&inv, "blue").unwrap();
        inv.connections[0]
            .props
            .insert("hold-time".into(), json!("00:03:00"));
        let change = ApprovedChange::Patch {
            collection: "connections".into(),
            id: "*2".into(),
            set: Properties::from([("hold-time".into(), json!("3m"))]),
        };
        let after = config_guard(&inv, "blue").unwrap();
        assert_eq!(advance_expected(&before, &after, &change).unwrap(), after);
        inv.connections[0]
            .props
            .insert("vendor.future".into(), json!({"opaque":"external"}));
        assert!(advance_expected(&before, &config_guard(&inv, "blue").unwrap(), &change).is_err());
    }

    #[test]
    fn mikrotik_apply_advance_new_id_must_be_unique_and_old_objects_untouched() {
        let mut inv = documented_inventory();
        let before = config_guard(&inv, "blue").unwrap();
        let required = Properties::from([
            ("chain".into(), json!("new")),
            ("rule".into(), json!("reject;")),
            ("disabled".into(), json!(false)),
        ]);
        let change = ApprovedChange::Insert {
            collection: "rules".into(),
            identity: Properties::from([("chain".into(), json!("new"))]),
            required: required.clone(),
        };
        inv.rules.push(NativeRecord {
            id: "*ABC".into(),
            props: required,
        });
        inv.rules
            .last_mut()
            .unwrap()
            .props
            .insert("future-default".into(), json!("device"));
        assert!(advance_expected(&before, &config_guard(&inv, "blue").unwrap(), &change).is_ok());
        inv.rules[0]
            .props
            .insert("comment".into(), json!("external"));
        assert!(advance_expected(&before, &config_guard(&inv, "blue").unwrap(), &change).is_err());
    }

    #[test]
    fn mikrotik_filter_fix1_shared_connection_insert_marker_must_name_new_row() {
        let mut inv = documented_inventory();
        let before = config_guard(&inv, "blue").unwrap();
        let mut created = inv.connections[0].clone();
        created.id = "*AB".into();
        created.props.insert("name".into(), json!("created-peer"));
        created.props.insert("disabled".into(), json!(true));
        let change = ApprovedChange::Insert {
            collection: "connections".into(),
            // Exercise the shared insert verifier independently of name uniqueness.
            // Both old and new rows match this identity; the delta still proves
            // one exact new connection and all old rows unchanged.
            identity: Properties::from([("instance".into(), json!("blue"))]),
            required: created.props.clone(),
        };
        inv.connections.push(created);
        let after = config_guard(&inv, "blue").unwrap();
        assert_eq!(advance_expected(&before, &after, &change).unwrap(), after);
        assert!(
            verify_marker(&json!({"id":"*2","applied":true}), &change, &before, &after).is_err(),
            "an existing matching connection must not masquerade as the created connection"
        );
        assert_eq!(
            verify_marker(
                &json!({"id":"*AB","applied":true}),
                &change,
                &before,
                &after
            )
            .unwrap(),
            "*AB"
        );
    }

    #[test]
    fn mikrotik_apply_advance_ruleorder_cannot_accept_other_chain_or_properties() {
        let mut inv = documented_inventory();
        inv.rules.push(record(
            json!({".id":"*7","chain":"blue-in","rule":"accept;","disabled":false}),
        ));
        let before = config_guard(&inv, "blue").unwrap();
        let change = ApprovedChange::RuleOrder {
            chain: "blue-in".into(),
            id: "*7".into(),
            before: Some("*5".into()),
            order_before: vec!["*5".into(), "*6".into(), "*7".into()],
            order_after: vec!["*7".into(), "*5".into(), "*6".into()],
        };
        let moved = inv.rules.remove(2);
        inv.rules.insert(0, moved);
        let after = config_guard(&inv, "blue").unwrap();
        assert!(advance_expected(&before, &after, &change).is_ok());
        inv.rules
            .iter_mut()
            .find(|r| r.id == "*6")
            .unwrap()
            .props
            .insert("disabled".into(), json!(true));
        assert!(advance_expected(&before, &config_guard(&inv, "blue").unwrap(), &change).is_err());
    }

    #[test]
    fn mikrotik_filter_rf3_native_move_preserves_other_chain_relative_order() {
        // Synthetic documentation-derived global rule list, not a device capture.
        // A real move-before removes *7 from its old position and inserts it
        // before *5: [*5, *6, *7] -> [*7, *5, *6], not [*7, *6, *5].
        let mut inv = documented_inventory();
        inv.rules.push(record(json!({
            ".id":"*7", "chain":"blue-in", "rule":"accept;", "disabled":false,
            "comment":"α\n\"\\$", "vendor.future":{"opaque":[false,"0007"]}
        })));
        let before = config_guard(&inv, "blue").unwrap();
        let approved = ApprovedChange::RuleOrder {
            chain: "blue-in".into(),
            id: "*7".into(),
            before: Some("*5".into()),
            order_before: vec!["*5".into(), "*6".into(), "*7".into()],
            order_after: vec!["*7".into(), "*5".into(), "*6".into()],
        };
        let moved = inv.rules.remove(2);
        inv.rules.insert(0, moved);
        assert_eq!(
            inv.rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["*7", "*5", "*6"]
        );
        let after = config_guard(&inv, "blue").unwrap();
        let advanced = advance_expected(&before, &after, &approved);
        assert!(
            advanced.is_ok(),
            "approved native move-before must accept its exact global-list effect: {advanced:?}"
        );
    }

    #[test]
    fn mikrotik_filter_global_moves_distinguish_anchor_end_and_untouched_interleavings() {
        let mut inv = documented_inventory();
        inv.rules.extend([
            record(json!({".id":"*7","chain":"blue-in","rule":"accept;","disabled":false,"comment":"α\n\"\\$","unknown":[null,"0007"]})),
            record(json!({".id":"*8","chain":"blue-out","rule":"reject;","disabled":false})),
            record(json!({".id":"*9","chain":"green","rule":"reject;","disabled":false})),
        ]);
        let before = config_guard(&inv, "blue").unwrap();
        for (target, anchor, expected) in [
            ("*7", Some("*5"), vec!["*7", "*5", "*6", "*8", "*9"]),
            ("*5", None, vec!["*6", "*7", "*8", "*9", "*5"]),
        ] {
            let approved = ApprovedChange::RuleOrder {
                chain: "blue-in".into(),
                id: target.into(),
                before: anchor.map(str::to_owned),
                order_before: vec![
                    "*5".into(),
                    "*6".into(),
                    "*7".into(),
                    "*8".into(),
                    "*9".into(),
                ],
                order_after: expected.iter().map(|s| (*s).into()).collect(),
            };
            let mut after = inv.clone();
            after.rules = expected
                .iter()
                .map(|id| inv.rules.iter().find(|r| r.id == *id).unwrap().clone())
                .collect();
            let guard = config_guard(&after, "blue").unwrap();
            assert_eq!(advance_expected(&before, &guard, &approved).unwrap(), guard);
            assert!(verify_marker(
                &json!({"id":target,"applied":true}),
                &approved,
                &before,
                &guard
            )
            .is_ok());
            assert!(verify_marker(
                &json!({"id":"*BAD","applied":true}),
                &approved,
                &before,
                &guard
            )
            .is_err());
            after.rules.swap(2, 3); // even unaffected chains cannot be rearranged
            assert!(
                advance_expected(&before, &config_guard(&after, "blue").unwrap(), &approved)
                    .is_err()
            );
            after.rules = expected
                .iter()
                .map(|id| inv.rules.iter().find(|r| r.id == *id).unwrap().clone())
                .collect();
            after.rules[0]
                .props
                .insert("comment".into(), json!("external"));
            assert!(
                advance_expected(&before, &config_guard(&after, "blue").unwrap(), &approved)
                    .is_err()
            );
        }
        let mut slot_swap = inv.clone();
        slot_swap.rules.swap(0, 2);
        let approved = ApprovedChange::RuleOrder {
            chain: "blue-in".into(),
            id: "*7".into(),
            before: Some("*5".into()),
            order_before: vec![
                "*5".into(),
                "*6".into(),
                "*7".into(),
                "*8".into(),
                "*9".into(),
            ],
            order_after: vec![
                "*7".into(),
                "*5".into(),
                "*6".into(),
                "*8".into(),
                "*9".into(),
            ],
        };
        assert!(advance_expected(
            &before,
            &config_guard(&slot_swap, "blue").unwrap(),
            &approved
        )
        .is_err());
    }
}
