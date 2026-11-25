//! Native RouterOS monitoring through a pinned SSH lease.

mod apply;
mod codec;
mod model;
mod read;
mod scope;

#[cfg(test)]
pub(crate) mod test_support;

pub use crate::router::commands::mikrotik::preview_native;
pub use apply::apply_native;
pub(crate) use apply::rejected_receipt;
pub use codec::{decode_envelope, presentation_text, require_target_version, ros_string};
pub use model::{
    ConfigGuard, MikroTikSnapshot, NativeConnectionDraft, NativeConnectionRef, NativeDiscovery,
    NativeIntent, NativeInventory, NativeOutcome, NativePatch, NativePeerRow, NativePreview,
    NativeRead, NativeReceipt, NativeRecord, NativeWireError, Properties, ScopeEligibility,
    SecretChange,
};
pub(crate) use read::effective_local_as;
pub use read::fetch_native;
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "retained native join/compiler API for guarded consumers and offline fixtures"
    )
)]
pub use read::{join_native_peers, native_read_command, NativeMenu};
pub use scope::{config_guard, connection_scope};

use crate::router::{ConnectionStatus, RouterConfig, RouterVendor};
use crate::ssh::{NativeLease, NativeRegistration, SshSessionManager};
use anyhow::{ensure, Context, Result};
use std::sync::Arc;
use uuid::Uuid;

pub struct MikroTikBackend {
    config: RouterConfig,
    registration: Option<NativeRegistration>,
    ssh: Arc<SshSessionManager>,
    status: ConnectionStatus,
}

#[cfg(test)]
mod registration_tests {
    use super::*;
    use crate::router::mikrotik::test_support::{documented_snapshot, TranscriptExecutor};
    use crate::router::RouterVendor;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn config() -> RouterConfig {
        RouterConfig {
            id: Uuid::nil(),
            hostname: "lab.invalid".into(),
            username: "tester".into(),
            vendor: RouterVendor::MikroTik,
            mikrotik_instance: Some("blue".into()),
            ..RouterConfig::default()
        }
    }

    #[tokio::test]
    async fn mikrotik_cache_discovery_atomic_decision_cannot_retarget_new_registration() {
        for change in ["same-config", "endpoint", "scope", "vendor"] {
            let original = config();
            let ssh = SshSessionManager::new(&[original.clone()]);
            let (captured, registration) = ssh.registered_snapshot(original.id).await.unwrap();
            let backend =
                MikroTikBackend::new_registered(&captured, registration.clone(), Arc::clone(&ssh));
            let mut replacement = original;
            match change {
                "endpoint" => replacement.hostname = "replacement.invalid".into(),
                "scope" => replacement.mikrotik_instance = Some("green".into()),
                "vendor" => replacement.vendor = RouterVendor::Cisco,
                _ => {}
            }
            ssh.register_router(replacement).await;
            let read_called = AtomicBool::new(false);
            let read_flag = &read_called;
            let result = backend
                .discover_bound_with(
                    Uuid::new_v4(),
                    Some("blue"),
                    &registration,
                    |lease, request, _| async move {
                        read_flag.store(true, Ordering::SeqCst);
                        let mut snapshot = documented_snapshot();
                        snapshot.registration = lease.registration().clone();
                        snapshot.request = request;
                        Ok(NativeDiscovery::Snapshot(snapshot))
                    },
                )
                .await;
            assert!(result.is_err());
            assert!(!read_called.load(Ordering::SeqCst));
            assert_eq!(captured.hostname, "lab.invalid");
            assert_eq!(captured.vendor, RouterVendor::MikroTik);
            assert_eq!(registration.endpoint.hostname, "lab.invalid");
            if change != "same-config" {
                assert!(backend.resolve_registration().await.is_err());
            }
        }
    }

    #[tokio::test]
    async fn mikrotik_cache_discovery_scope_mismatch_rejects_before_read() {
        let original = config();
        let ssh = SshSessionManager::new(&[original.clone()]);
        let (captured, registration) = ssh.registered_snapshot(original.id).await.unwrap();
        let backend = MikroTikBackend::new(&captured, ssh);
        let io = TranscriptExecutor::new(vec![]);
        let read_io = &io;
        let result = backend
            .discover_bound_with(
                Uuid::new_v4(),
                Some("green"),
                &registration,
                |lease, request, instance| async move {
                    fetch_native(read_io, lease.registration(), request, instance.as_deref()).await
                },
            )
            .await;
        assert!(result.is_err());
        assert!(io.seen_labels().is_empty());
    }

    #[tokio::test]
    async fn mikrotik_cache_discovery_queued_original_token_and_scope_survive_wait() {
        let original = config();
        let ssh = SshSessionManager::new(&[original.clone()]);
        let (captured, registration) = ssh.registered_snapshot(original.id).await.unwrap();
        let held = ssh.native_lease(&registration).await.unwrap();
        let backend = MikroTikBackend::new(&captured, Arc::clone(&ssh));
        let called = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&called);
        let task = tokio::spawn(async move {
            backend
                .discover_bound_with(
                    Uuid::new_v4(),
                    Some("blue"),
                    &registration,
                    |_, _, _| async move {
                        observed.store(true, Ordering::SeqCst);
                        anyhow::bail!("unexpected read after replacement")
                    },
                )
                .await
        });
        tokio::task::yield_now().await;
        let mut replacement = original;
        replacement.hostname = "other.invalid".into();
        replacement.mikrotik_instance = Some("red".into());
        ssh.register_router(replacement).await;
        drop(held);
        assert!(task.await.unwrap().is_err());
        assert!(!called.load(Ordering::SeqCst));
    }
}

#[cfg(test)]
mod neighbor_operation_tests {
    use super::test_support::*;
    use super::*;
    use serde_json::{json, Value};

    fn admin(snapshot: &MikroTikSnapshot, disabled: bool) -> NativePreview {
        preview_native(
            snapshot,
            NativeIntent::SetDisabled {
                target: snapshot.peers[0].connection.clone().unwrap(),
                disabled,
            },
            Uuid::from_u128(42),
        )
        .unwrap()
    }

    fn os_reads(
        inv: &NativeInventory,
    ) -> Vec<crate::ssh::native_process_test_support::ScriptedReply> {
        use crate::ssh::native_process_test_support::ScriptedReply;
        vec![
            ScriptedReply::data("version", json!(inv.version)),
            ScriptedReply::data("instances", json!(inv.instances)),
            ScriptedReply::data("connections", json!(inv.connections)),
            ScriptedReply::data("templates", json!(inv.templates)),
            ScriptedReply::data("sessions", json!(inv.sessions)),
            ScriptedReply::data("rules", json!(inv.rules)),
        ]
    }

    fn cfg() -> RouterConfig {
        RouterConfig {
            id: Uuid::nil(),
            hostname: "lab.invalid".into(),
            username: "tester".into(),
            vendor: RouterVendor::MikroTik,
            mikrotik_instance: Some("blue".into()),
            ..RouterConfig::default()
        }
    }

    #[tokio::test]
    async fn mikrotik_apply_backend_original_token_rejects_queued_replacement_and_removal() {
        use futures::poll;
        for mode in ["endpoint", "credentials", "instance", "same", "removed"] {
            let original = cfg();
            let manager = SshSessionManager::new(&[original.clone()]);
            let registration = manager.native_registration(original.id).await.unwrap();
            let held = manager.native_lease(&registration).await.unwrap();
            let mut snapshot = documented_snapshot();
            snapshot.registration = registration.clone();
            let backend = MikroTikBackend::new(&original, Arc::clone(&manager));
            let processes = crate::ssh::native_process_test_support::FakeProcesses::new(os_reads(
                &snapshot.inventory,
            ));
            let worker_processes = Arc::clone(&processes);
            let mut applying = Box::pin(backend.apply_with(
                admin(&snapshot, true),
                move |lease, preview| async move {
                    apply_native(&worker_processes.executor(lease), preview).await
                },
            ));
            assert!(poll!(applying.as_mut()).is_pending()); // actual endpoint lease queue, no sleeps
            if mode == "removed" {
                manager.unregister_router(original.id).await;
            } else {
                let mut replacement = original.clone();
                match mode {
                    "endpoint" => replacement.hostname = "replacement.invalid".into(),
                    "credentials" => replacement.password = Some("synthetic-only".into()),
                    "instance" => replacement.mikrotik_instance = Some("green".into()),
                    _ => {}
                }
                manager.register_router(replacement).await;
            }
            drop(held);
            let receipt = applying.await;
            assert_eq!(receipt.outcome, NativeOutcome::RejectedBeforeWrite);
            assert_eq!(receipt.registration, registration);
            assert!(processes.launches().is_empty());
            processes.assert_drained();
        }
    }

    #[tokio::test]
    async fn mikrotik_apply_backend_launched_a_never_retargets_b_and_receipt_stays_uncertain_a() {
        use crate::ssh::native_process_test_support::{FakeProcesses, LaunchGate, ScriptedReply};
        let original = cfg();
        let manager = SshSessionManager::new(&[original.clone()]);
        let registration = manager.native_registration(original.id).await.unwrap();
        let mut snapshot = documented_snapshot();
        snapshot.registration = registration.clone();
        let backend = MikroTikBackend::new(&original, Arc::clone(&manager));
        let gate = LaunchGate::new(); // RAII releases even on panic; task owns no release handle
        let mut replies = os_reads(&snapshot.inventory);
        replies.push(
            ScriptedReply::data("neighbor.admin", json!({"id":"*2","applied":true}))
                .blocked(&gate)
                .failed_status(),
        );
        let processes = FakeProcesses::new(replies);
        let worker_processes = Arc::clone(&processes);
        let preview = admin(&snapshot, true);
        let task = tokio::spawn(async move {
            backend
                .apply_with(preview, move |lease, preview| async move {
                    apply_native(&worker_processes.executor(lease), preview).await
                })
                .await
        });
        gate.launched().await;
        let mut replacement = original;
        replacement.hostname = "replacement.invalid".into();
        manager.register_router(replacement).await;
        gate.release();
        let receipt = task.await.unwrap();
        assert_eq!(receipt.outcome, NativeOutcome::Indeterminate);
        assert_eq!(receipt.registration, registration);
        let launches = processes.launches();
        assert_eq!(
            launches
                .iter()
                .filter(|(_, kind, _)| *kind == crate::ssh::NativeCommandKind::Mutation)
                .count(),
            1
        );
        assert!(launches
            .iter()
            .all(|(_, _, target)| target == "tester@lab.invalid"));
        assert_eq!(receipt.uncertain_steps.len(), 1);
        processes.assert_drained();
    }

    fn reads(inv: &NativeInventory) -> Vec<Reply> {
        configuration_replies(inv)
    }

    fn sec001_source_snapshot(sources: &[Value], direct: Option<Value>) -> MikroTikSnapshot {
        let mut snapshot = documented_snapshot();
        let mut names = Vec::new();
        for (index, source) in sources.iter().enumerate() {
            let name = format!("source-{index}");
            snapshot.inventory.templates.push(record(json!({
                ".id":format!("*F{index}"), "name":name, "local.address":source
            })));
            names.push(name);
        }
        let row = &mut snapshot.inventory.connections[1]; // sessionless, configured peer-b
        row.props.remove("local.address");
        if let Some(source) = direct {
            row.props.insert("local.address".into(), source);
        }
        if !names.is_empty() {
            row.props.insert("templates".into(), json!(names));
        }
        snapshot.guard = config_guard(&snapshot.inventory, "blue").unwrap();
        snapshot.peers =
            join_native_peers(&snapshot.inventory, "blue", snapshot.generation).unwrap();
        snapshot
    }

    fn sec001_intent(snapshot: &MikroTikSnapshot, action: &str) -> NativeIntent {
        let target = snapshot.peers[1].connection.clone().unwrap();
        match action {
            "patch" => NativeIntent::Patch {
                target,
                changes: NativePatch {
                    properties: Properties::from([("comment".into(), json!("fix1 comment"))]),
                    secret: SecretChange::Keep,
                },
            },
            "admin" => NativeIntent::SetDisabled {
                target,
                disabled: false,
            },
            "delete" => NativeIntent::Delete(target),
            _ => panic!("unknown test action"),
        }
    }

    #[test]
    fn mikrotik_neighbor_sec001_inherited_source_must_be_resolved_before_any_intent_preview() {
        for sources in [
            vec![json!("ether1")],
            vec![json!("malformed")],
            vec![json!(null)],
            vec![json!("")],
            vec![json!({"address":"192.0.2.1"})],
            vec![json!("2001:db8::1")],
            vec![json!("192.0.2.10"), json!("192.0.2.11")],
        ] {
            let snapshot = sec001_source_snapshot(&sources, None);
            for action in ["patch", "admin", "delete"] {
                assert!(
                    preview_native(&snapshot, sec001_intent(&snapshot, action), Uuid::new_v4())
                        .is_err(),
                    "{action} must reject unsupported/unresolved effective source {sources:?}"
                );
            }
        }
        for (sources, direct) in [
            (vec![], Some(json!("192.0.2.10"))),
            (vec![json!("192.0.2.10")], None),
            (vec![json!("192.0.2.10"), json!("192.0.2.10")], None),
            (vec![json!("ether1")], Some(json!("192.0.2.10"))),
            (vec![], None), // observable absence retains the supported native source default
        ] {
            let snapshot = sec001_source_snapshot(&sources, direct);
            for action in ["patch", "admin", "delete"] {
                assert!(
                    preview_native(&snapshot, sec001_intent(&snapshot, action), Uuid::new_v4())
                        .is_ok(),
                    "{action}"
                );
            }
        }
    }

    #[tokio::test]
    async fn mikrotik_apply_sec001_inherited_source_preflight_rejects_with_zero_mutations() {
        for sources in [
            vec![json!("ether1")],
            vec![json!(null)],
            vec![json!("bad")],
            vec![json!("192.0.2.10"), json!("192.0.2.11")],
        ] {
            let snapshot = sec001_source_snapshot(&sources, None);
            for action in ["patch", "admin", "delete"] {
                // Exercise worker authorization independently of UI preview, as
                // with a preview generated before this security repair.
                let preview = NativePreview {
                    router_id: snapshot.router_id,
                    operation: Uuid::new_v4(),
                    registration: snapshot.registration.clone(),
                    generation: snapshot.generation,
                    instance: snapshot.instance.clone(),
                    guard: snapshot.guard.clone(),
                    intent: sec001_intent(&snapshot, action),
                    visible_diff: vec![],
                    warnings: vec![],
                };
                let mut after = snapshot.inventory.clone();
                match action {
                    "patch" => {
                        after.connections[1]
                            .props
                            .insert("comment".into(), json!("fix1 comment"));
                    }
                    "admin" => {
                        after.connections[1]
                            .props
                            .insert("disabled".into(), json!(false));
                    }
                    "delete" => {
                        after.connections.remove(1);
                    }
                    _ => unreachable!(),
                }
                let mut replies = reads(&snapshot.inventory);
                replies.push(Reply::Data(json!({"id":"*3","applied":true})));
                replies.extend(reads(&after));
                let io = TranscriptExecutor::new(replies);
                let receipt = apply_native(&io, preview).await;
                assert_eq!(
                    receipt.outcome,
                    NativeOutcome::RejectedBeforeWrite,
                    "{action} / {sources:?}"
                );
                assert_eq!(io.mutation_attempts(), 0);
            }
        }
    }

    fn sec002_binding_snapshot(key: &str, value: Value, inherited: bool) -> MikroTikSnapshot {
        let mut snapshot = documented_snapshot();
        if inherited {
            snapshot.inventory.connections[1].props.remove(key);
            snapshot.inventory.connections[1]
                .props
                .insert("templates".into(), json!("binding-parent"));
            snapshot.inventory.templates.push(record(json!({
                ".id":"*F0", "name":"binding-parent", (key):value
            })));
        } else {
            snapshot.inventory.connections[1]
                .props
                .insert(key.into(), value);
        }
        snapshot.guard = config_guard(&snapshot.inventory, "blue").unwrap();
        snapshot.peers =
            join_native_peers(&snapshot.inventory, "blue", snapshot.generation).unwrap();
        snapshot
    }

    #[test]
    fn mikrotik_neighbor_sec002_enable_rejects_unknown_direct_or_inherited_binding_effects() {
        for key in ["input.filter", "output.filter-chain"] {
            for inherited in [false, true] {
                for value in [
                    json!(null),
                    json!(""),
                    json!(false),
                    json!(42),
                    json!(["blue-in"]),
                    json!({"chain":"blue-in"}),
                    json!("unobserved-chain"),
                ] {
                    let snapshot = sec002_binding_snapshot(key, value.clone(), inherited);
                    assert!(
                        preview_native(
                            &snapshot,
                            sec001_intent(&snapshot, "admin"),
                            Uuid::new_v4()
                        )
                        .is_err(),
                        "enable must reject {key} {value:?}, inherited={inherited}"
                    );
                    let disabled = preview_native(
                        &snapshot,
                        NativeIntent::SetDisabled {
                            target: snapshot.peers[1].connection.clone().unwrap(),
                            disabled: true,
                        },
                        Uuid::new_v4(),
                    )
                    .unwrap();
                    let warning = disabled
                        .warnings
                        .iter()
                        .find(|s| s.starts_with(key))
                        .unwrap();
                    assert!(
                        warning.contains("unknown")
                            && !warning.contains("configured filter applies"),
                        "{warning}"
                    );
                }
            }
        }
    }

    #[test]
    fn mikrotik_neighbor_sec002_enable_review_distinguishes_observed_bound_from_absent_unbound() {
        for key in ["input.filter", "output.filter-chain"] {
            for inherited in [false, true] {
                let snapshot = sec002_binding_snapshot(key, json!("blue-in"), inherited);
                let preview =
                    preview_native(&snapshot, sec001_intent(&snapshot, "admin"), Uuid::new_v4())
                        .unwrap();
                assert!(preview
                    .visible_diff
                    .iter()
                    .any(|s| s.starts_with(key) && s.contains("bound") && s.contains("blue-in")));
                assert!(!preview
                    .warnings
                    .iter()
                    .any(|s| s.starts_with(key) && s.contains("ACCEPT")));

                let mut absent = snapshot;
                absent.inventory.connections[1].props.remove(key);
                for template in &mut absent.inventory.templates {
                    template.props.remove(key);
                }
                absent.guard = config_guard(&absent.inventory, "blue").unwrap();
                let preview =
                    preview_native(&absent, sec001_intent(&absent, "admin"), Uuid::new_v4())
                        .unwrap();
                assert!(preview
                    .warnings
                    .iter()
                    .any(|s| s.starts_with(key) && s.contains("unbound") && s.contains("ACCEPT")));
            }
        }
    }

    #[test]
    fn mikrotik_neighbor_sec002_conflicting_inherited_bindings_are_unknown_not_protection() {
        let mut snapshot = sec002_binding_snapshot("input.filter", json!("blue-in"), true);
        snapshot.inventory.templates.push(record(
            json!({".id":"*F1","name":"other-binding","input.filter":"blue-out"}),
        ));
        snapshot.inventory.connections[1].props.insert(
            "templates".into(),
            json!(["binding-parent", "other-binding"]),
        );
        snapshot.guard = config_guard(&snapshot.inventory, "blue").unwrap();
        assert!(
            preview_native(&snapshot, sec001_intent(&snapshot, "admin"), Uuid::new_v4()).is_err()
        );
        let preview = preview_native(
            &snapshot,
            NativeIntent::SetDisabled {
                target: snapshot.peers[1].connection.clone().unwrap(),
                disabled: true,
            },
            Uuid::new_v4(),
        )
        .unwrap();
        assert!(preview
            .warnings
            .iter()
            .any(|s| s.starts_with("input.filter") && s.contains("unknown")));

        // A directly observed binding wins over a single, known inherited value.
        let mut direct = sec002_binding_snapshot("input.filter", json!("blue-out"), true);
        direct.inventory.connections[1]
            .props
            .insert("input.filter".into(), json!("blue-in"));
        direct.guard = config_guard(&direct.inventory, "blue").unwrap();
        let preview =
            preview_native(&direct, sec001_intent(&direct, "admin"), Uuid::new_v4()).unwrap();
        assert!(preview
            .visible_diff
            .iter()
            .any(|s| s.starts_with("input.filter")
                && s.contains("bound to observed chain \"blue-in\"")));
    }

    #[tokio::test]
    async fn mikrotik_apply_sec002_unknown_enable_binding_preflight_sends_zero_mutations() {
        for key in ["input.filter", "output.filter-chain"] {
            for inherited in [false, true] {
                for value in [json!(null), json!(""), json!(["blue-in"])] {
                    let snapshot = sec002_binding_snapshot(key, value, inherited);
                    let preview = NativePreview {
                        router_id: snapshot.router_id,
                        operation: Uuid::new_v4(),
                        registration: snapshot.registration.clone(),
                        generation: snapshot.generation,
                        instance: snapshot.instance.clone(),
                        guard: snapshot.guard.clone(),
                        intent: sec001_intent(&snapshot, "admin"),
                        visible_diff: vec![],
                        warnings: vec![],
                    };
                    let mut after = snapshot.inventory.clone();
                    after.connections[1]
                        .props
                        .insert("disabled".into(), json!(false));
                    let mut replies = reads(&snapshot.inventory);
                    replies.push(Reply::Data(json!({"id":"*3","applied":true})));
                    replies.extend(reads(&after));
                    let io = TranscriptExecutor::new(replies);
                    let receipt = apply_native(&io, preview).await;
                    assert_eq!(receipt.outcome, NativeOutcome::RejectedBeforeWrite);
                    assert_eq!(io.mutation_attempts(), 0);
                }
            }
        }
    }

    #[tokio::test]
    async fn mikrotik_receipt_sec004_admin_evidence_survives_rejection_unknown_and_verified_outcomes(
    ) {
        let snapshot = documented_snapshot();
        for (index, name, id, disabled, direction) in [
            (0, "peer-a", "*2", true, "Disable (disabled=true)"),
            (1, "peer-b", "*3", false, "Enable (disabled=false)"),
        ] {
            for outcome in [
                "read-rejected",
                "prelaunch",
                "unknown",
                "verified",
                "lease-rejected",
            ] {
                let preview = preview_native(
                    &snapshot,
                    NativeIntent::SetDisabled {
                        target: snapshot.peers[index].connection.clone().unwrap(),
                        disabled,
                    },
                    Uuid::new_v4(),
                )
                .unwrap();
                let receipt = if outcome == "lease-rejected" {
                    // Actual backend acquisition rejection, not only the wrapper.
                    let backend = MikroTikBackend::new(&cfg(), SshSessionManager::new(&[]));
                    backend.apply(preview).await
                } else {
                    let mut after = snapshot.inventory.clone();
                    after.connections[index]
                        .props
                        .insert("disabled".into(), json!(disabled));
                    let replies = if outcome == "read-rejected" {
                        vec![Reply::Failure {
                            code: "timeout",
                            started: true,
                        }]
                    } else {
                        let mut replies = reads(&snapshot.inventory);
                        match outcome {
                            "prelaunch" => replies.push(Reply::Failure {
                                code: "spawn",
                                started: false,
                            }),
                            "unknown" => {
                                replies.push(Reply::Failure {
                                    code: "timeout",
                                    started: true,
                                });
                                replies.extend(reads(&after));
                            }
                            "verified" => {
                                replies.push(Reply::Data(json!({"id":id,"applied":true})));
                                replies.extend(reads(&after));
                            }
                            _ => unreachable!(),
                        }
                        replies
                    };
                    apply_native(&TranscriptExecutor::new(replies), preview).await
                };
                let expected = match outcome {
                    "unknown" => NativeOutcome::Indeterminate,
                    "verified" => NativeOutcome::VerifiedApplied,
                    _ => NativeOutcome::RejectedBeforeWrite,
                };
                assert_eq!(receipt.outcome, expected);
                assert!(
                    receipt.summary.contains(&format!("name=\"{name}\""))
                        && receipt.summary.contains(&format!("id=\"{id}\"")),
                    "{}",
                    receipt.summary
                );
                assert!(
                    receipt.summary.contains(direction)
                        && receipt.summary.contains("Authentication: Keep"),
                    "{}",
                    receipt.summary
                );
            }
        }
    }

    #[tokio::test]
    async fn mikrotik_receipt_sec004_patch_lists_only_safe_property_names_and_auth_intention() {
        for authentication in ["Keep", "Replace", "Clear"] {
            for outcome in ["read-rejected", "unknown", "verified"] {
                let mut snapshot = documented_snapshot();
                snapshot.inventory.connections[0]
                    .props
                    .insert("name".into(), json!("peer-\n\"quoted\""));
                snapshot.guard = config_guard(&snapshot.inventory, "blue").unwrap();
                snapshot.peers =
                    join_native_peers(&snapshot.inventory, "blue", snapshot.generation).unwrap();
                let properties = Properties::from([
                    ("comment".into(), json!("SEC004_COMMENT_VALUE")),
                    ("hold-time".into(), json!("4m")),
                    ("nexthop-choice".into(), json!("force-self")),
                ]);
                let secret = match authentication {
                    "Keep" => SecretChange::Keep,
                    "Replace" => SecretChange::Replace("SEC004_MD5_VALUE".into()),
                    _ => SecretChange::Clear,
                };
                let preview = preview_native(
                    &snapshot,
                    NativeIntent::Patch {
                        target: snapshot.peers[0].connection.clone().unwrap(),
                        changes: NativePatch {
                            properties: properties.clone(),
                            secret,
                        },
                    },
                    Uuid::new_v4(),
                )
                .unwrap();
                let mut after = snapshot.inventory.clone();
                after.connections[0].props.extend(properties);
                let replies = if outcome == "read-rejected" {
                    vec![Reply::Failure {
                        code: "timeout",
                        started: true,
                    }]
                } else {
                    let mut replies = reads(&snapshot.inventory);
                    if outcome == "unknown" {
                        replies.push(Reply::Failure {
                            code: "timeout",
                            started: true,
                        });
                        replies.extend(reads(&after));
                    } else {
                        replies.push(Reply::Data(json!({"id":"*2","applied":true})));
                        replies.extend(reads(&after));
                        if authentication != "Keep" {
                            replies.push(Reply::Data(json!({"id":"*2","verified":true})));
                        }
                    }
                    replies
                };
                let receipt = apply_native(&TranscriptExecutor::new(replies), preview).await;
                assert_eq!(
                    receipt.outcome,
                    match outcome {
                        "unknown" => NativeOutcome::Indeterminate,
                        "verified" => NativeOutcome::VerifiedApplied,
                        _ => NativeOutcome::RejectedBeforeWrite,
                    }
                );
                assert!(
                    receipt.summary.contains("Patch") && receipt.summary.contains("id=\"*2\""),
                    "{}",
                    receipt.summary
                );
                for name in ["comment", "hold-time", "nexthop-choice"] {
                    assert!(
                        receipt.summary.contains(name),
                        "missing {name}: {}",
                        receipt.summary
                    );
                }
                assert!(receipt
                    .summary
                    .contains(&format!("Authentication: {authentication}")));
                assert!(!receipt.summary.chars().any(char::is_control));
                assert!(receipt.summary.contains("\\n"));
                let stored = serde_json::to_string(&receipt).unwrap();
                for value in [
                    "SEC004_COMMENT_VALUE",
                    "SEC004_MD5_VALUE",
                    "force-self",
                    "/routing/bgp/connection",
                ] {
                    assert!(
                        !stored.contains(value),
                        "receipt leaked intended value/script"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn mikrotik_secret_sec004_invalid_patch_property_names_cannot_leak_on_rejection() {
        let snapshot = documented_snapshot();
        let preview = NativePreview {
            router_id: snapshot.router_id,
            operation: Uuid::new_v4(),
            registration: snapshot.registration.clone(),
            generation: snapshot.generation,
            instance: snapshot.instance.clone(),
            guard: snapshot.guard.clone(),
            visible_diff: vec![],
            warnings: vec![],
            intent: NativeIntent::Patch {
                target: snapshot.peers[0].connection.clone().unwrap(),
                changes: NativePatch {
                    properties: Properties::from([(
                        "tcp-md5-key=SEC004_UNKNOWN_KEY_VALUE".into(),
                        json!("SEC004_UNKNOWN_PROPERTY_VALUE"),
                    )]),
                    secret: SecretChange::Replace("SEC004_REPLACEMENT_VALUE".into()),
                },
            },
        };
        let io = TranscriptExecutor::new(reads(&snapshot.inventory));
        let receipt = apply_native(&io, preview).await;
        assert_eq!(receipt.outcome, NativeOutcome::RejectedBeforeWrite);
        assert_eq!(io.mutation_attempts(), 0);
        assert!(
            receipt
                .summary
                .contains("unsupported property names redacted")
                && receipt.summary.contains("Authentication: Replace")
        );
        let stored = serde_json::to_string(&receipt).unwrap();
        for value in [
            "SEC004_UNKNOWN_KEY_VALUE",
            "SEC004_UNKNOWN_PROPERTY_VALUE",
            "SEC004_REPLACEMENT_VALUE",
        ] {
            assert!(!stored.contains(value));
        }
    }

    #[test]
    fn mikrotik_receipt_sec004_early_rejection_sanitizes_target_control_characters() {
        let snapshot = documented_snapshot();
        let mut target = snapshot.peers[0].connection.clone().unwrap();
        target.name = "peer-\u{1b}[2J\n\"quoted\"".into();
        let preview = NativePreview {
            router_id: snapshot.router_id,
            operation: Uuid::new_v4(),
            registration: snapshot.registration.clone(),
            generation: snapshot.generation,
            instance: snapshot.instance.clone(),
            guard: snapshot.guard.clone(),
            visible_diff: vec![],
            warnings: vec![],
            intent: NativeIntent::Delete(target),
        };
        let receipt = rejected_receipt(&preview);
        assert!(!receipt.summary.chars().any(char::is_control));
        assert!(receipt.summary.contains("\\u{1b}") && receipt.summary.contains("id=\"*2\""));
    }

    #[tokio::test]
    async fn mikrotik_receipt_sec004_create_and_delete_keep_target_and_action_evidence() {
        let snapshot = documented_snapshot();
        let operation = Uuid::from_u128(42);
        let stages = create_inventory_steps(&snapshot, operation);
        for outcome in ["read-rejected", "partial", "unknown", "verified"] {
            let preview =
                preview_native(&snapshot, NativeIntent::Create(draft()), operation).unwrap();
            let replies = if outcome == "read-rejected" {
                vec![Reply::Failure {
                    code: "timeout",
                    started: true,
                }]
            } else {
                let mut replies = reads(&snapshot.inventory);
                if outcome == "unknown" {
                    replies.push(Reply::Failure {
                        code: "timeout",
                        started: true,
                    });
                    replies.extend(reads(&snapshot.inventory));
                } else {
                    replies.push(Reply::Data(json!({"id":"*A","applied":true})));
                    replies.extend(reads(&stages[0]));
                    replies.extend(reads(&stages[0]));
                    if outcome == "partial" {
                        replies.push(Reply::Failure {
                            code: "spawn",
                            started: false,
                        });
                    } else {
                        replies.push(Reply::Data(json!({"id":"*B","applied":true})));
                        replies.extend(reads(&stages[1]));
                        replies.extend(reads(&stages[1]));
                        replies.push(Reply::Data(json!({"id":"*C","applied":true})));
                        replies.extend(reads(&stages[2]));
                    }
                }
                replies
            };
            let receipt = apply_native(&TranscriptExecutor::new(replies), preview).await;
            assert_eq!(
                receipt.outcome,
                match outcome {
                    "partial" => NativeOutcome::PartialApplication,
                    "unknown" => NativeOutcome::Indeterminate,
                    "verified" => NativeOutcome::VerifiedApplied,
                    _ => NativeOutcome::RejectedBeforeWrite,
                }
            );
            assert!(
                receipt.summary.contains("name=\"new-peer\"")
                    && receipt.summary.contains("Create")
                    && receipt.summary.contains("disabled=true")
                    && receipt.summary.contains("Authentication: Keep"),
                "{}",
                receipt.summary
            );
            if outcome == "verified" {
                assert!(receipt
                    .verified_steps
                    .iter()
                    .any(|s| s.contains("id=\"*C\"")));
            }
        }
        let target = snapshot.peers[1].connection.clone().unwrap();
        let preview =
            preview_native(&snapshot, NativeIntent::Delete(target), Uuid::new_v4()).unwrap();
        let mut after = snapshot.inventory.clone();
        after.connections.remove(1);
        let mut replies = reads(&snapshot.inventory);
        replies.push(Reply::Data(json!({"id":"*3","applied":true})));
        replies.extend(reads(&after));
        let receipt = apply_native(&TranscriptExecutor::new(replies), preview).await;
        assert_eq!(receipt.outcome, NativeOutcome::VerifiedApplied);
        assert!(
            receipt.summary.contains("Delete")
                && receipt.summary.contains("name=\"peer-b\"")
                && receipt.summary.contains("id=\"*3\"")
        );
    }

    fn stale_template_transcript(snapshot: &MikroTikSnapshot) -> TranscriptExecutor {
        let mut inv = snapshot.inventory.clone();
        inv.templates.push(record(
            json!({".id":"*T", "name":"scope", "vrf":"customer"}),
        ));
        inv.connections[0]
            .props
            .insert("templates".into(), json!("scope"));
        TranscriptExecutor::new(reads(&inv))
    }

    #[tokio::test]
    async fn mikrotik_apply_stale_scope_sends_no_mutation() {
        let snapshot = documented_snapshot();
        let preview = admin(&snapshot, true);
        let io = stale_template_transcript(&snapshot);
        let receipt = apply_native(&io, preview).await;
        assert_eq!(receipt.outcome, NativeOutcome::RejectedBeforeWrite);
        assert_eq!(io.mutation_attempts(), 0);
    }

    #[tokio::test]
    async fn mikrotik_apply_admin_uses_configured_flag_and_independent_postread() {
        for disabled in [true, false] {
            let mut snapshot = documented_snapshot();
            snapshot.inventory.connections[0]
                .props
                .insert("disabled".into(), json!(!disabled));
            snapshot.guard = config_guard(&snapshot.inventory, "blue").unwrap();
            snapshot.peers =
                join_native_peers(&snapshot.inventory, "blue", snapshot.generation).unwrap();
            let mut after = snapshot.inventory.clone();
            after.connections[0].props.insert(
                "disabled".into(),
                json!(if disabled { "yes" } else { "no" }),
            );
            after.sessions.clear(); // Runtime changes are not configuration changes.
            let mut telemetry = snapshot.inventory.clone();
            telemetry.sessions[0]
                .props
                .insert("uptime".into(), json!("2d3h"));
            telemetry.sessions[0]
                .props
                .insert("prefix-count".into(), json!(987654));
            let mut replies = reads(&telemetry);
            replies.push(Reply::Data(json!({"id":"*2", "applied":true})));
            replies.extend(reads(&after));
            let io = TranscriptExecutor::new(replies);
            let receipt = apply_native(&io, admin(&snapshot, disabled)).await;
            assert_eq!(receipt.outcome, NativeOutcome::VerifiedApplied);
            assert_eq!(receipt.verified_steps.len(), 1);
            assert_eq!(
                io.seen_labels(),
                vec![
                    "version",
                    "instances",
                    "connections",
                    "templates",
                    "sessions",
                    "rules",
                    "neighbor.admin",
                    "version",
                    "instances",
                    "connections",
                    "templates",
                    "sessions",
                    "rules"
                ]
            );
        }
    }

    #[tokio::test]
    async fn mikrotik_apply_complete_guard_rejects_any_unapproved_configuration() {
        for key in ["name", "input.filter", "vendor.future", "remote.as"] {
            let snapshot = documented_snapshot();
            let mut stale = snapshot.inventory.clone();
            stale.connections[0]
                .props
                .insert(key.into(), json!("changed"));
            let io = TranscriptExecutor::new(reads(&stale));
            assert_eq!(
                apply_native(&io, admin(&snapshot, true)).await.outcome,
                NativeOutcome::RejectedBeforeWrite
            );
            assert_eq!(io.mutation_attempts(), 0);
        }
    }

    #[tokio::test]
    async fn mikrotik_apply_launched_failure_is_unknown_and_never_retried() {
        let snapshot = documented_snapshot();
        for code in ["timeout", "stderr", "exit-status", "invalid-envelope"] {
            let mut replies = reads(&snapshot.inventory);
            replies.push(Reply::Failure {
                code,
                started: true,
            });
            replies.extend(reads(&snapshot.inventory)); // read-only reconciliation, no replay
            let io = TranscriptExecutor::new(replies);
            let receipt = apply_native(&io, admin(&snapshot, true)).await;
            assert_eq!(receipt.outcome, NativeOutcome::Indeterminate);
            assert_eq!(
                receipt.uncertain_steps,
                vec!["Set administrative disabled state"]
            );
            assert_eq!(io.mutation_attempts(), 1);
        }
    }

    #[tokio::test]
    async fn mikrotik_apply_postread_cannot_accept_unrelated_external_change() {
        let snapshot = documented_snapshot();
        let mut after = snapshot.inventory.clone();
        after.connections[0]
            .props
            .insert("disabled".into(), json!(true));
        after.connections[1]
            .props
            .insert("comment".into(), json!("external"));
        let mut replies = reads(&snapshot.inventory);
        replies.push(Reply::Data(json!({"id":"*2","applied":true})));
        replies.extend(reads(&after));
        let io = TranscriptExecutor::new(replies);
        assert_eq!(
            apply_native(&io, admin(&snapshot, true)).await.outcome,
            NativeOutcome::Indeterminate
        );
        assert_eq!(io.mutation_attempts(), 1);
    }

    #[tokio::test]
    async fn mikrotik_apply_delete_only_exact_connection_preserves_filters() {
        let snapshot = documented_snapshot();
        let target = snapshot.peers[0].connection.clone().unwrap();
        let preview =
            preview_native(&snapshot, NativeIntent::Delete(target), Uuid::new_v4()).unwrap();
        let mut after = snapshot.inventory.clone();
        after.connections.remove(0);
        let mut replies = reads(&snapshot.inventory);
        replies.push(Reply::Data(json!({"id":"*2","applied":true})));
        replies.extend(reads(&after));
        let io = TranscriptExecutor::new(replies);
        let receipt = apply_native(&io, preview).await;
        assert_eq!(receipt.outcome, NativeOutcome::VerifiedApplied);
        assert_eq!(io.mutation_attempts(), 1);
        assert!(io.seen_labels().contains(&"neighbor.delete"));
    }

    fn draft() -> NativeConnectionDraft {
        NativeConnectionDraft {
            name: "new-peer".into(),
            remote_address: "2001:db8::2".parse().unwrap(),
            remote_as: 65002,
            role: "ebgp".into(),
            afi: vec!["ip".into(), "ipv6".into()],
            source: None,
            comment: "plain".into(),
            hold_time: Some("3m".into()),
            keepalive_time: None,
            nexthop_choice: None,
            use_bfd: None,
            secret: SecretChange::Keep,
        }
    }

    fn create_inventory_steps(snapshot: &MikroTikSnapshot, op: Uuid) -> Vec<NativeInventory> {
        let mut inv = snapshot.inventory.clone();
        let (input, output) = crate::router::commands::mikrotik::chain_names(op);
        inv.rules.push(record(
            json!({".id":"*A","chain":input,"rule":"reject;","disabled":false}),
        ));
        let one = inv.clone();
        inv.rules.push(record(
            json!({".id":"*B","chain":output,"rule":"reject;","disabled":false}),
        ));
        let two = inv.clone();
        inv.connections.push(record(json!({".id":"*C","name":"new-peer","instance":"blue","dynamic":false,
            "remote.address":"2001:db8::2","remote.as":65002,"local.role":"ebgp","afi":"ipv6,ip","comment":"plain",
            "hold-time":"00:03:00","routing-table":"main","vrf":"main","disabled":true,"input.filter":input,"output.filter-chain":output})));
        vec![one, two, inv]
    }

    #[tokio::test]
    async fn mikrotik_apply_create_three_verified_steps_disabled_with_both_bindings() {
        let snapshot = documented_snapshot();
        let op = Uuid::from_u128(42);
        let preview = preview_native(&snapshot, NativeIntent::Create(draft()), op).unwrap();
        let stages = create_inventory_steps(&snapshot, op);
        let mut replies = reads(&snapshot.inventory);
        for (index, inv) in stages.iter().enumerate() {
            if index > 0 {
                replies.extend(reads(&stages[index - 1]));
            }
            replies.push(Reply::Data(
                json!({"id":(["*A","*B","*C"][index]),"applied":true}),
            ));
            replies.extend(reads(inv));
        }
        let io = TranscriptExecutor::new(replies);
        let receipt = apply_native(&io, preview).await;
        assert_eq!(receipt.outcome, NativeOutcome::VerifiedApplied);
        assert_eq!(receipt.verified_steps.len(), 3);
        let mutations = io
            .seen_labels()
            .into_iter()
            .filter(|s| s.starts_with("neighbor."))
            .collect::<Vec<_>>();
        assert_eq!(
            mutations,
            vec![
                "neighbor.reject-in",
                "neighbor.reject-out",
                "neighbor.create"
            ]
        );
        assert_eq!(io.seen_labels().len(), 39); // initial6 + three mutations/posts + two preguards
    }

    #[tokio::test]
    async fn mikrotik_apply_rule_and_connection_ids_are_menu_local_not_cross_collection_targets() {
        let mut snapshot = documented_snapshot();
        let op = Uuid::from_u128(42);
        snapshot.inventory.instances.push(record(
            json!({".id":"*F","name":"green","as":65100,"routing-table":"main","vrf":"main"}),
        ));
        snapshot.inventory.connections.push(record(
            json!({".id":"*A","name":"foreign","instance":"green","local.role":"ebgp",
            "remote.address":"192.0.9.1","remote.as":65101,"disabled":true,"dynamic":false}),
        ));
        snapshot.guard = config_guard(&snapshot.inventory, "blue").unwrap();
        let preview = preview_native(&snapshot, NativeIntent::Create(draft()), op).unwrap();
        let stages = create_inventory_steps(&snapshot, op);
        let mut replies = reads(&snapshot.inventory);
        for (index, inv) in stages.iter().enumerate() {
            if index > 0 {
                replies.extend(reads(&stages[index - 1]));
            }
            replies.push(Reply::Data(
                json!({"id":(["*A","*B","*C"][index]),"applied":true}),
            ));
            replies.extend(reads(inv));
        }
        let io = TranscriptExecutor::new(replies);
        let receipt = apply_native(&io, preview).await;
        assert_eq!(receipt.outcome, NativeOutcome::VerifiedApplied);
        assert_eq!(io.mutation_attempts(), 3);
    }

    #[tokio::test]
    async fn mikrotik_apply_create_prelaunch_failure_reports_verified_orphans_without_cleanup() {
        let snapshot = documented_snapshot();
        let op = Uuid::from_u128(42);
        let preview = preview_native(&snapshot, NativeIntent::Create(draft()), op).unwrap();
        let stages = create_inventory_steps(&snapshot, op);
        let mut replies = reads(&snapshot.inventory);
        replies.push(Reply::Data(json!({"id":"*A","applied":true})));
        replies.extend(reads(&stages[0]));
        replies.extend(reads(&stages[0]));
        replies.push(Reply::Failure {
            code: "spawn",
            started: false,
        });
        let io = TranscriptExecutor::new(replies);
        let receipt = apply_native(&io, preview).await;
        assert_eq!(receipt.outcome, NativeOutcome::PartialApplication);
        assert_eq!(
            receipt.verified_steps,
            vec!["Create enabled reject input chain"]
        );
        assert_eq!(receipt.unapplied_steps.len(), 2);
        assert!(receipt.uncertain_steps.is_empty());
        assert!(receipt
            .summary
            .contains("bgp-lm-in-0000000000000000000000000000002a"));
        assert!(!io.seen_labels().contains(&"neighbor.create"));
        assert_eq!(io.mutation_attempts(), 2);
    }

    #[tokio::test]
    async fn mikrotik_apply_own_progress_does_not_hide_external_change_before_next_step() {
        let snapshot = documented_snapshot();
        let op = Uuid::from_u128(42);
        let preview = preview_native(&snapshot, NativeIntent::Create(draft()), op).unwrap();
        let stages = create_inventory_steps(&snapshot, op);
        let mut replies = reads(&snapshot.inventory);
        replies.push(Reply::Data(json!({"id":"*A","applied":true})));
        replies.extend(reads(&stages[0]));
        let mut external = stages[0].clone();
        external.connections[1]
            .props
            .insert("comment".into(), json!("external"));
        replies.extend(reads(&external));
        let io = TranscriptExecutor::new(replies);
        let receipt = apply_native(&io, preview).await;
        assert_eq!(receipt.outcome, NativeOutcome::PartialApplication);
        assert_eq!(receipt.verified_steps.len(), 1);
        assert_eq!(io.mutation_attempts(), 1);
    }

    #[tokio::test]
    async fn mikrotik_secret_replace_clear_require_private_boolean_and_actual_target_identity() {
        for clear in [false, true] {
            for private in [
                json!({"id":"*2","verified":true}),
                json!({"id":"*2","verified":false}),
                json!({"id":"*wrong","verified":true}),
                json!({}),
                json!(""),
            ] {
                let snapshot = documented_snapshot();
                let preview = preview_native(
                    &snapshot,
                    NativeIntent::Patch {
                        target: snapshot.peers[0].connection.clone().unwrap(),
                        changes: NativePatch {
                            properties: Properties::new(),
                            secret: if clear {
                                SecretChange::Clear
                            } else {
                                SecretChange::Replace("SENTINEL_MD5".into())
                            },
                        },
                    },
                    Uuid::new_v4(),
                )
                .unwrap();
                let mut replies = reads(&snapshot.inventory);
                replies.push(Reply::Data(json!({"id":"*2","applied":true})));
                replies.extend(reads(&snapshot.inventory));
                replies.push(Reply::Data(private.clone()));
                let io = TranscriptExecutor::new(replies);
                let receipt = apply_native(&io, preview).await;
                assert_eq!(
                    receipt.outcome,
                    if private == json!({"id":"*2","verified":true}) {
                        NativeOutcome::VerifiedApplied
                    } else {
                        NativeOutcome::Indeterminate
                    }
                );
                assert_eq!(io.mutation_attempts(), 1);
                assert_eq!(io.seen_labels().last(), Some(&"neighbor.secret-check"));
                assert!(!serde_json::to_string(&receipt)
                    .unwrap()
                    .contains("SENTINEL_MD5"));
            }
        }
    }

    #[tokio::test]
    async fn mikrotik_secret_keep_patch_preserves_unknowns_and_inheritance_without_private_read() {
        let mut snapshot = documented_snapshot();
        snapshot.inventory.connections[0]
            .props
            .insert("vendor.future".into(), json!({"x":7}));
        snapshot.inventory.connections[0]
            .props
            .insert("hold-time".into(), json!("3m"));
        snapshot.guard = config_guard(&snapshot.inventory, "blue").unwrap();
        let preview = preview_native(
            &snapshot,
            NativeIntent::Patch {
                target: snapshot.peers[0].connection.clone().unwrap(),
                changes: NativePatch {
                    properties: Properties::from([("comment".into(), json!("new"))]),
                    secret: SecretChange::Keep,
                },
            },
            Uuid::new_v4(),
        )
        .unwrap();
        let mut after = snapshot.inventory.clone();
        after.connections[0]
            .props
            .insert("comment".into(), json!("new"));
        let mut replies = reads(&snapshot.inventory);
        replies.push(Reply::Data(json!({"id":"*2","applied":true})));
        replies.extend(reads(&after));
        let io = TranscriptExecutor::new(replies);
        assert_eq!(
            apply_native(&io, preview).await.outcome,
            NativeOutcome::VerifiedApplied
        );
        assert!(!io.seen_labels().contains(&"neighbor.secret-check"));
    }

    #[tokio::test]
    async fn mikrotik_secret_inaccessible_private_read_is_indeterminate_and_redacts_echoed_error() {
        let snapshot = documented_snapshot();
        let preview = preview_native(
            &snapshot,
            NativeIntent::Patch {
                target: snapshot.peers[0].connection.clone().unwrap(),
                changes: NativePatch {
                    properties: Properties::new(),
                    secret: SecretChange::Clear,
                },
            },
            Uuid::new_v4(),
        )
        .unwrap();
        let mut replies = reads(&snapshot.inventory);
        replies.push(Reply::Data(json!({"id":"*2","applied":true})));
        replies.extend(reads(&snapshot.inventory));
        replies.push(Reply::Failure {
            code: "SENTINEL_MD5 echoed command",
            started: true,
        });
        let io = TranscriptExecutor::new(replies);
        let receipt = apply_native(&io, preview).await;
        assert_eq!(receipt.outcome, NativeOutcome::Indeterminate);
        assert!(receipt.verified_steps.is_empty());
        assert_eq!(io.mutation_attempts(), 1);
        assert!(
            !format!("{receipt:?} {}", serde_json::to_string(&receipt).unwrap())
                .contains("SENTINEL_MD5")
        );
    }

    #[tokio::test]
    async fn mikrotik_apply_budgets_all_create_commands_before_first_rule_write() {
        let snapshot = documented_snapshot();
        let mut preview =
            preview_native(&snapshot, NativeIntent::Create(draft()), Uuid::new_v4()).unwrap();
        if let NativeIntent::Create(draft) = &mut preview.intent {
            draft.comment = "x".repeat(32768);
        }
        let io = TranscriptExecutor::new(reads(&snapshot.inventory));
        assert_eq!(
            apply_native(&io, preview).await.outcome,
            NativeOutcome::RejectedBeforeWrite
        );
        assert_eq!(io.mutation_attempts(), 0);
    }

    #[test]
    fn mikrotik_neighbor_unset_binding_reviews_actual_inherited_stage_not_false_unbound() {
        let mut snapshot = documented_snapshot();
        snapshot.inventory.templates.push(record(
            json!({".id":"*D","name":"base","input.filter":"blue-in"}),
        ));
        snapshot.inventory.connections[0]
            .props
            .insert("templates".into(), json!("base"));
        snapshot.guard = config_guard(&snapshot.inventory, "blue").unwrap();
        let p = preview_native(
            &snapshot,
            NativeIntent::Patch {
                target: snapshot.peers[0].connection.clone().unwrap(),
                changes: NativePatch {
                    properties: Properties::from([("input.filter".into(), Value::Null)]),
                    secret: SecretChange::Keep,
                },
            },
            Uuid::new_v4(),
        )
        .unwrap();
        assert!(p
            .visible_diff
            .iter()
            .any(|s| s.contains("inherited result") && s.contains("blue-in")));
        assert!(!p.warnings.iter().any(|s| s.contains("ACCEPT everything")));
    }

    #[test]
    fn mikrotik_neighbor_unset_rejects_unmodelable_inherited_binding_or_source() {
        for (key, value) in [
            ("input.filter", json!("")),
            ("local.address", json!("ether1")),
            ("hold-time", json!("opaque")),
        ] {
            let mut snapshot = documented_snapshot();
            snapshot
                .inventory
                .templates
                .push(record(json!({".id":"*D","name":"base",(key):value})));
            snapshot.inventory.connections[0]
                .props
                .insert("templates".into(), json!("base"));
            snapshot.guard = config_guard(&snapshot.inventory, "blue").unwrap();
            assert!(
                preview_native(
                    &snapshot,
                    NativeIntent::Patch {
                        target: snapshot.peers[0].connection.clone().unwrap(),
                        changes: NativePatch {
                            properties: Properties::from([(key.into(), Value::Null)]),
                            secret: SecretChange::Keep
                        }
                    },
                    Uuid::new_v4()
                )
                .is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn mikrotik_secret_preview_budgets_private_verification_not_only_mutation() {
        let snapshot = documented_snapshot();
        assert!(preview_native(
            &snapshot,
            NativeIntent::Patch {
                target: snapshot.peers[0].connection.clone().unwrap(),
                changes: NativePatch {
                    properties: Properties::new(),
                    secret: SecretChange::Replace("x".repeat(31_000))
                }
            },
            Uuid::new_v4()
        )
        .is_err());
    }

    #[tokio::test]
    async fn mikrotik_apply_public_backend_rejects_replaced_registration_without_os_launch() {
        let original = cfg();
        let manager = SshSessionManager::new(&[original.clone()]);
        let registration = manager.native_registration(original.id).await.unwrap();
        let mut snapshot = documented_snapshot();
        snapshot.registration = registration.clone();
        let backend = MikroTikBackend::new(&original, Arc::clone(&manager));
        let mut replacement = original;
        replacement.hostname = "replacement.invalid".into();
        manager.register_router(replacement).await;
        let receipt = backend.apply(admin(&snapshot, true)).await;
        assert_eq!(receipt.outcome, NativeOutcome::RejectedBeforeWrite);
        assert_eq!(receipt.registration, registration);
    }

    #[tokio::test]
    async fn mikrotik_apply_backend_rechecks_registration_after_acquisition_before_first_exec() {
        let original = cfg();
        let manager = SshSessionManager::new(&[original.clone()]);
        let registration = manager.native_registration(original.id).await.unwrap();
        let mut snapshot = documented_snapshot();
        snapshot.registration = registration.clone();
        let backend = MikroTikBackend::new(&original, Arc::clone(&manager));
        let processes = crate::ssh::native_process_test_support::FakeProcesses::new(os_reads(
            &snapshot.inventory,
        ));
        let worker_processes = Arc::clone(&processes);
        let receipt = backend
            .apply_with(admin(&snapshot, true), move |lease, preview| async move {
                // Identical inventory and endpoint, new registration epoch only.
                manager.register_router(original).await;
                apply_native(&worker_processes.executor(lease), preview).await
            })
            .await;
        assert_eq!(receipt.outcome, NativeOutcome::RejectedBeforeWrite);
        assert_eq!(receipt.registration, registration);
        assert!(processes.launches().is_empty());
        processes.assert_drained();
    }

    #[tokio::test]
    async fn mikrotik_apply_marker_and_postconditions_both_required_with_no_retries() {
        for marker in [
            json!({"id":"*2","applied":false}),
            json!({"id":"*3","applied":true}),
            json!(true),
            json!({"id":"*2","applied":true,"extra":true}),
        ] {
            let snapshot = documented_snapshot();
            let mut after = snapshot.inventory.clone();
            after.connections[0]
                .props
                .insert("disabled".into(), json!(true));
            let mut replies = reads(&snapshot.inventory);
            replies.push(Reply::Data(marker));
            replies.extend(reads(&after));
            let io = TranscriptExecutor::new(replies);
            let receipt = apply_native(&io, admin(&snapshot, true)).await;
            assert_eq!(receipt.outcome, NativeOutcome::Indeterminate);
            assert_eq!(io.mutation_attempts(), 1);
            assert!(receipt.verified_steps.is_empty());
        }
    }

    #[tokio::test]
    async fn mikrotik_apply_preflight_read_launch_does_not_mean_mutation_was_launched() {
        let snapshot = documented_snapshot();
        let io = TranscriptExecutor::new(vec![Reply::Failure {
            code: "timeout",
            started: true,
        }]);
        assert_eq!(
            apply_native(&io, admin(&snapshot, true)).await.outcome,
            NativeOutcome::RejectedBeforeWrite
        );
        assert_eq!(io.mutation_attempts(), 0);
    }

    #[tokio::test]
    async fn mikrotik_apply_incomplete_reference_marker_cannot_authorize_writes() {
        let snapshot = documented_snapshot();
        let mut replies = reads(&snapshot.inventory);
        replies[3] = Reply::Failure {
            code: "permission",
            started: true,
        };
        let io = TranscriptExecutor::new(replies);
        assert_eq!(
            apply_native(&io, admin(&snapshot, true)).await.outcome,
            NativeOutcome::RejectedBeforeWrite
        );
        assert_eq!(io.mutation_attempts(), 0);
    }

    #[tokio::test]
    async fn mikrotik_apply_rejected_create_reports_all_unapplied_steps_without_any_exec() {
        let snapshot = documented_snapshot();
        let mut preview =
            preview_native(&snapshot, NativeIntent::Create(draft()), Uuid::new_v4()).unwrap();
        preview.router_id = Uuid::new_v4();
        let io = TranscriptExecutor::new(vec![]);
        let receipt = apply_native(&io, preview).await;
        assert_eq!(receipt.outcome, NativeOutcome::RejectedBeforeWrite);
        assert_eq!(receipt.unapplied_steps.len(), 3);
        assert!(io.seen_labels().is_empty());
    }

    #[tokio::test]
    async fn mikrotik_apply_create_does_not_verify_dynamic_or_unknown_kind() {
        for kind in [Some(json!(true)), None] {
            let snapshot = documented_snapshot();
            let op = Uuid::from_u128(42);
            let preview = preview_native(&snapshot, NativeIntent::Create(draft()), op).unwrap();
            let mut stages = create_inventory_steps(&snapshot, op);
            if let Some(value) = kind {
                stages[2]
                    .connections
                    .last_mut()
                    .unwrap()
                    .props
                    .insert("dynamic".into(), value);
            } else {
                stages[2]
                    .connections
                    .last_mut()
                    .unwrap()
                    .props
                    .remove("dynamic");
            }
            let mut replies = reads(&snapshot.inventory);
            for (index, inv) in stages.iter().enumerate() {
                if index > 0 {
                    replies.extend(reads(&stages[index - 1]));
                }
                replies.push(Reply::Data(
                    json!({"id":(["*A","*B","*C"][index]),"applied":true}),
                ));
                replies.extend(reads(inv));
            }
            let io = TranscriptExecutor::new(replies);
            let receipt = apply_native(&io, preview).await;
            assert_eq!(receipt.outcome, NativeOutcome::Indeterminate);
            assert_eq!(receipt.verified_steps.len(), 2);
            assert_eq!(io.mutation_attempts(), 3);
        }
    }

    #[test]
    fn mikrotik_neighbor_validation_fail_closed_identity_scope_and_fields() {
        let snapshot = documented_snapshot();
        for key in [
            "name",
            "instance",
            "remote.address",
            "routing-table",
            "tcp-md5-key",
            "script",
        ] {
            let intent = NativeIntent::Patch {
                target: snapshot.peers[0].connection.clone().unwrap(),
                changes: NativePatch {
                    properties: Properties::from([(key.into(), json!("bad"))]),
                    secret: SecretChange::Keep,
                },
            };
            assert!(
                preview_native(&snapshot, intent, Uuid::new_v4()).is_err(),
                "{key}"
            );
        }
        let mut stale = snapshot.peers[0].connection.clone().unwrap();
        stale.generation = Uuid::new_v4();
        assert!(preview_native(&snapshot, NativeIntent::Delete(stale), Uuid::new_v4()).is_err());
        for (key, value) in [
            ("dynamic", json!(true)),
            ("disabled", json!(null)),
            ("local.role", json!("ebgp-rs")),
            ("remote.address", json!("192.0.2.0/24")),
        ] {
            let mut s = snapshot.clone();
            s.inventory.connections[0].props.insert(key.into(), value);
            s.guard = config_guard(&s.inventory, "blue").unwrap();
            assert!(preview_native(
                &s,
                NativeIntent::Delete(s.peers[0].connection.clone().unwrap()),
                Uuid::new_v4()
            )
            .is_err());
        }
    }

    #[test]
    fn mikrotik_neighbor_create_validates_role_as_afi_source_timers_and_collisions() {
        let snapshot = documented_snapshot();
        for bad in 0..7 {
            let mut d = draft();
            match bad {
                0 => d.remote_as = 0,
                1 => d.role = "ibgp".into(),
                2 => d.afi = vec!["vpnv4".into()],
                3 => d.source = Some("192.0.2.1".parse().unwrap()),
                4 => d.hold_time = Some("2s".into()),
                5 => d.name = "peer-a".into(),
                _ => d.nexthop_choice = Some("yes".into()),
            }
            assert!(
                preview_native(&snapshot, NativeIntent::Create(d), Uuid::from_u128(42)).is_err(),
                "{bad}"
            );
        }
        let p = preview_native(
            &snapshot,
            NativeIntent::Create(draft()),
            Uuid::from_u128(42),
        )
        .unwrap();
        assert!(p.visible_diff.iter().any(|s| s.contains("disabled")));
        assert!(p
            .visible_diff
            .iter()
            .any(|s| s.contains("bgp-lm-in-0000000000000000000000000000002a")));
        assert!(p.visible_diff.iter().any(|s| s.contains("lab.invalid")));
    }

    #[test]
    fn mikrotik_secret_intents_and_previews_debug_are_redacted() {
        let snapshot = documented_snapshot();
        let intent = NativeIntent::Patch {
            target: snapshot.peers[0].connection.clone().unwrap(),
            changes: NativePatch {
                properties: Properties::new(),
                secret: SecretChange::Replace("SENTINEL_MD5".into()),
            },
        };
        let p = preview_native(&snapshot, intent, Uuid::new_v4()).unwrap();
        assert!(!format!("{p:?} {:?} {:?}", p.intent, p.visible_diff).contains("SENTINEL_MD5"));
        assert!(p.visible_diff.iter().any(|s| s.contains("Replace")));
    }
}

impl MikroTikBackend {
    pub fn new(config: &RouterConfig, ssh: Arc<SshSessionManager>) -> Self {
        Self {
            config: config.clone(),
            registration: None,
            ssh,
            status: ConnectionStatus::Disconnected,
        }
    }

    pub(crate) fn new_registered(
        config: &RouterConfig,
        registration: NativeRegistration,
        ssh: Arc<SshSessionManager>,
    ) -> Self {
        let mut backend = Self::new(config, ssh);
        backend.registration = Some(registration);
        backend
    }

    async fn resolve_registration(&self) -> Result<NativeRegistration> {
        let (config, registration) = self.ssh.registered_snapshot(self.config.id).await?;
        ensure!(
            config == self.config && config.vendor == RouterVendor::MikroTik,
            "native backend configuration changed"
        );
        Ok(registration)
    }

    pub fn status(&self) -> &ConnectionStatus {
        &self.status
    }

    pub async fn connect(&mut self) -> Result<()> {
        let registration = match &self.registration {
            Some(registration) => registration.clone(),
            None => self.resolve_registration().await?,
        };
        let lease = self.ssh.native_lease(&registration).await?;
        crate::ssh::probe_native(&lease).await?;
        self.status = ConnectionStatus::Connected;
        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        self.status = ConnectionStatus::Disconnected;
        Ok(())
    }

    pub async fn discover(&self, request: Uuid, instance: Option<&str>) -> Result<NativeDiscovery> {
        let registration = match &self.registration {
            Some(registration) => registration.clone(),
            None => self
                .resolve_registration()
                .await
                .context("cannot resolve native registration")?,
        };
        self.discover_bound_with(
            request,
            instance,
            &registration,
            |lease, request, instance| async move {
                fetch_native(&lease, lease.registration(), request, instance.as_deref()).await
            },
        )
        .await
    }

    pub async fn apply(&self, preview: NativePreview) -> NativeReceipt {
        self.apply_with(preview, |lease, preview| async move {
            apply_native(&lease, preview).await
        })
        .await
    }

    async fn apply_with<F, Fut>(&self, preview: NativePreview, run: F) -> NativeReceipt
    where
        F: FnOnce(NativeLease, NativePreview) -> Fut,
        Fut: std::future::Future<Output = NativeReceipt>,
    {
        let rejected = apply::rejected_receipt(&preview);
        if self.config.vendor != RouterVendor::MikroTik
            || self.config.id != preview.router_id
            || self.config.mikrotik_instance.as_deref() != Some(preview.instance.as_str())
            || self.config.hostname != preview.registration.endpoint.hostname
            || self.config.username != preview.registration.endpoint.username
            || self.config.ssh_port != preview.registration.endpoint.ssh_port
        {
            return rejected;
        }
        // The reviewed token is mandatory, never replaced by a fresh UUID lookup.
        match self.ssh.native_lease(&preview.registration).await {
            Ok(lease) => run(lease, preview).await,
            Err(_) => rejected,
        }
    }

    async fn discover_bound_with<F, Fut>(
        &self,
        request: Uuid,
        instance: Option<&str>,
        registration: &NativeRegistration,
        read: F,
    ) -> Result<NativeDiscovery>
    where
        F: FnOnce(NativeLease, Uuid, Option<String>) -> Fut,
        Fut: std::future::Future<Output = Result<NativeDiscovery>>,
    {
        let selected = instance.filter(|name| !name.trim().is_empty());
        let configured = self
            .config
            .mikrotik_instance
            .as_deref()
            .filter(|name| !name.trim().is_empty());
        ensure!(
            self.config.vendor == RouterVendor::MikroTik
                && self.config.id == registration.router_id
                && self.config.hostname == registration.endpoint.hostname
                && self.config.ssh_port == registration.endpoint.ssh_port
                && self.config.username == registration.endpoint.username,
            "native registration decision mismatch"
        );
        ensure!(selected == configured, "native selected scope changed");
        // One lease covers version, discovery and every optional read. The
        // actual token/configuration is never reconstructed from the UI.
        let lease = self
            .ssh
            .native_lease(registration)
            .await
            .context("cannot acquire native read lease")?;
        read(lease, request, selected.map(str::to_owned)).await
    }
}
