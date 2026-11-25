//! A receipt is evidence, never an executable replay plan.
use super::*;
use crate::router::commands::mikrotik::{
    compile_native, native_equal, secret_verification, ApprovedChange,
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
            before: prior,
            after: order,
        } => {
            let rows = collection(before, "rules")?;
            let selected = rows
                .iter()
                .filter(|r| r["chain"].as_str() == Some(chain.as_str()))
                .map(id)
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                selected
                    .iter()
                    .copied()
                    .eq(prior.iter().map(String::as_str)),
                "rule order before mismatch"
            );
            ensure!(
                prior.len() == order.len()
                    && prior.iter().collect::<BTreeSet<_>>()
                        == order.iter().collect::<BTreeSet<_>>()
                    && order.iter().collect::<BTreeSet<_>>().len() == order.len(),
                "rule order changed membership"
            );
            let mut next = order.iter();
            let reordered = rows
                .iter()
                .map(|r| {
                    if r["chain"].as_str() == Some(chain.as_str()) {
                        let wanted = next.next().context("invalid rule order")?;
                        rows.iter()
                            .find(|r| id(r).ok() == Some(wanted.as_str()))
                            .cloned()
                            .context("ordered rule missing")
                    } else {
                        Ok(r.clone())
                    }
                })
                .collect::<Result<Vec<_>>>()?;
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

fn safe_intent_evidence(preview: &NativePreview) -> String {
    let target = match &preview.intent {
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
        NativeIntent::Create(_) => None,
    }
}

fn verify_marker(data: &Value, approved: &ApprovedChange, after: &ConfigGuard) -> Result<String> {
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
            ensure!(
                collection(after, name)?
                    .iter()
                    .filter(|row| id(row).ok() == Some(marker) && matches_properties(row, identity))
                    .count()
                    == 1,
                "created marker identity mismatch"
            );
        }
        ApprovedChange::Patch { id, .. } | ApprovedChange::Remove { id, .. } => {
            ensure!(marker == id, "mutation marker identity mismatch")
        }
        ApprovedChange::RuleOrder { .. } => {
            anyhow::bail!("rule order has no neighbor result marker")
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
    receipt.unapplied_steps = steps.iter().map(|s| s.safe_label.clone()).collect();
    for (index, step) in steps.into_iter().enumerate() {
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
                            let marker = verify_marker(&data, &step.approved, &after)?;
                            advance_expected(&expected, &after, &step.approved)?;
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
    fn mikrotik_apply_advance_ruleorder_cannot_accept_other_chain_or_properties() {
        let mut inv = documented_inventory();
        inv.rules.push(record(
            json!({".id":"*7","chain":"blue-in","rule":"accept;","disabled":false}),
        ));
        let before = config_guard(&inv, "blue").unwrap();
        let change = ApprovedChange::RuleOrder {
            chain: "blue-in".into(),
            before: vec!["*5".into(), "*7".into()],
            after: vec!["*7".into(), "*5".into()],
        };
        inv.rules.swap(0, 2);
        let after = config_guard(&inv, "blue").unwrap();
        assert!(advance_expected(&before, &after, &change).is_ok());
        inv.rules[1].props.insert("disabled".into(), json!(true));
        assert!(advance_expected(&before, &config_guard(&inv, "blue").unwrap(), &change).is_err());
    }
}
