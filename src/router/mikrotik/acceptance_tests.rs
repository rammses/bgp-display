//! Cross-feature acceptance with synthetic documentation-derived data, NOT
//! RouterOS captures. Only SSH execution is replaced; domain, App, DB and UI run.

use super::test_support::*;
use super::*;
use crate::app::{handle_key, ActiveTab, App, NativeConfigTarget, NativeEditorStage};
use crate::config::AppConfig;
use crate::db::{ConfigHistoryEntry, RouterDb};
use crate::events::{AppEvent, FetchRequest};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};
use serde_json::json;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

const INPUT: &str = "bgp-lm-in-0000000000000000000000000000002a";
const OUTPUT: &str = "bgp-lm-out-0000000000000000000000000000002a";

fn app(instance: Option<&str>) -> (App, UnboundedReceiver<FetchRequest>) {
    let router = RouterConfig {
        id: Uuid::nil(),
        hostname: "lab.invalid".into(),
        username: "tester".into(),
        vendor: RouterVendor::MikroTik,
        mikrotik_instance: instance.map(str::to_owned),
        ..RouterConfig::default()
    };
    let mut app = App::new(
        AppConfig {
            routers: vec![router],
            ..AppConfig::default()
        },
        RouterDb::in_memory().unwrap(),
    );
    let (tx, rx) = unbounded_channel();
    app.set_fetch_tx(tx);
    (app, rx)
}

fn key(app: &mut App, code: KeyCode) {
    handle_key(app, KeyEvent::new(code, KeyModifiers::NONE));
}

fn event(app: &mut App, event: AppEvent) {
    match event {
        AppEvent::NativeData(id, request, data) => app.handle_native_data(id, request, *data),
        AppEvent::NativeError(id, request, error) => app.handle_native_error(id, request, error),
        AppEvent::MikroTikApplied(receipt) => app.handle_native_receipt(receipt),
        _ => panic!("unexpected acceptance event"),
    }
}

fn screen(app: &mut App) -> String {
    let mut terminal = Terminal::new(TestBackend::new(220, 50)).unwrap();
    terminal.draw(|frame| crate::ui::draw(frame, app)).unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .chunks(220)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

fn monitoring_replies(inv: &NativeInventory) -> Vec<Reply> {
    let mut replies = configuration_replies(inv);
    replies.push(Reply::Data(json!([{
        ".id":"*10", "dst-address":"203.0.113.0/24", "afi":"ip4",
        "routing-table":"main", "bgp.session":"peer-a-1",
        "bgp.as-path":"65001,{65002,65003}", "contribution":"filtered"
    }])));
    replies
}

// Expected states below are hand-built device observations, never outputs of
// the compiler, guard advancement, filter simulator or rendered config parser.
fn write_replies(before: &NativeInventory, states: &[(&str, &NativeInventory)]) -> Vec<Reply> {
    let mut replies = configuration_replies(before);
    for (index, (id, after)) in states.iter().enumerate() {
        if index > 0 {
            replies.extend(configuration_replies(states[index - 1].1));
        }
        replies.push(Reply::Data(json!({"id":id,"applied":true})));
        replies.extend(configuration_replies(after));
    }
    replies
}

async fn refresh(
    app: &mut App,
    rx: &mut UnboundedReceiver<FetchRequest>,
    io: &TranscriptExecutor,
    registration: &crate::ssh::NativeRegistration,
) -> NativeDiscovery {
    let FetchRequest::RefreshMikroTik {
        router_id,
        request,
        instance,
    } = rx.try_recv().expect("one tracked native refresh")
    else {
        panic!("refresh must not use a legacy request")
    };
    assert_eq!(router_id, registration.router_id);
    let data = fetch_native(io, registration, request, instance.as_deref())
        .await
        .unwrap();
    event(
        app,
        AppEvent::NativeData(router_id, request, Box::new(data.clone())),
    );
    assert!(rx.try_recv().is_err());
    data
}

fn take_apply(rx: &mut UnboundedReceiver<FetchRequest>) -> NativePreview {
    let FetchRequest::ApplyMikroTik(preview) = rx.try_recv().unwrap() else {
        panic!("native editor must send typed native intention only")
    };
    assert!(rx.try_recv().is_err());
    preview
}

async fn finish_verified(
    app: &mut App,
    io: &TranscriptExecutor,
    preview: NativePreview,
    steps: usize,
) {
    let receipt = apply_native(io, preview).await;
    assert_eq!(
        receipt.outcome,
        NativeOutcome::VerifiedApplied,
        "{receipt:?}"
    );
    assert_eq!(receipt.verified_steps.len(), steps);
    assert!(receipt.uncertain_steps.is_empty() && receipt.unapplied_steps.is_empty());
    event(app, AppEvent::MikroTikApplied(receipt));
    let stage = app
        .native_editor
        .as_ref()
        .map(|e| e.stage)
        .or_else(|| app.native_filter_editor.as_ref().map(|e| e.stage));
    assert_eq!(stage, Some(NativeEditorStage::Result));
    key(app, KeyCode::Enter);
    app.current_tab = ActiveTab::Peers;
}

fn select_connection(app: &mut App, name: &str) {
    let index = app
        .current_peers
        .iter()
        .position(|p| matches!(p.key.as_ref(), Some(crate::bgp::PeerKey::RouterOsConnection { instance, name: n }) if instance == "blue" && n == name))
        .unwrap();
    app.peer_table_state.select(Some(index));
}

#[tokio::test]
async fn mikrotik_acceptance_monitor_create_edit_filter_disable_delete() {
    // A broken native dispatch, disabled-create guard progression, metadata
    // target, minimal filter sequence or receipt persistence breaks this flow.
    let mut initial = documented_inventory();
    initial.version = "7.24.7 (long-term)".into();
    initial.connections[0]
        .props
        .insert("future".into(), json!({"untouched":[null,"0007","α"]}));
    let mut input = initial.clone();
    input.rules.push(record(
        json!({".id":"*A","chain":INPUT,"rule":"reject;","disabled":false}),
    ));
    let mut output = input.clone();
    output.rules.push(record(
        json!({".id":"*B","chain":OUTPUT,"rule":"reject;","disabled":false}),
    ));
    let mut created = output.clone();
    created.connections.push(record(json!({
        ".id":"*C","name":"acceptance-peer","instance":"blue","dynamic":false,
        "remote.address":"2001:db8::2","remote.as":65002,"local.role":"ebgp",
        "afi":"ipv6,ip","comment":"created α","routing-table":"main","vrf":"main",
        "disabled":true,"input.filter":INPUT,"output.filter-chain":OUTPUT
    })));
    let mut enabled = created.clone();
    enabled.connections[2]
        .props
        .insert("disabled".into(), json!(false));
    let mut patched = enabled.clone();
    patched.connections[2]
        .props
        .insert("comment".into(), json!("patched α"));
    let rule_text = "if (dst in 203.0.113.0/24) { accept; }\nreject;";
    let mut inserted = patched.clone();
    inserted.rules.push(record(
        json!({".id":"*D","chain":INPUT,"rule":rule_text,"comment":"","disabled":true}),
    ));
    let mut moved = inserted.clone();
    let row = moved.rules.remove(4);
    moved.rules.insert(2, row); // actual global move-before *A, not selected slots
    let mut filtered = moved.clone();
    filtered.rules[2]
        .props
        .insert("disabled".into(), json!(false));
    let mut disabled = filtered.clone();
    disabled.connections[2]
        .props
        .insert("disabled".into(), json!(true));
    let mut deleted = disabled.clone();
    deleted.connections.remove(2); // definitions deliberately survive deletion

    let mut replies = vec![
        Reply::Data(json!(initial.version)),
        Reply::Data(json!(initial.instances)),
    ];
    replies.extend(monitoring_replies(&initial));
    for (before, states, after) in [
        (
            &initial,
            vec![("*A", &input), ("*B", &output), ("*C", &created)],
            &created,
        ),
        (&created, vec![("*C", &enabled)], &enabled),
        (&enabled, vec![("*C", &patched)], &patched),
        (
            &patched,
            vec![("*D", &inserted), ("*D", &moved), ("*D", &filtered)],
            &filtered,
        ),
        (&filtered, vec![("*C", &disabled)], &disabled),
        (&disabled, vec![("*C", &deleted)], &deleted),
    ] {
        replies.extend(write_replies(before, &states));
        replies.extend(monitoring_replies(after));
    }
    let io = TranscriptExecutor::new(replies);
    let registration = documented_registration();
    let (mut app, mut rx) = app(None);
    app.request_native_refresh(Uuid::nil());
    let discovery = refresh(&mut app, &mut rx, &io, &registration).await;
    assert!(matches!(discovery, NativeDiscovery::Instances { names, .. } if names == ["blue"]));
    assert!(app.current_summary.is_none());
    assert!(app.rendered_config.contains("discovery only"));
    app.wizard_open_create();
    assert!(app.native_editor.is_none()); // no auto-select or instance creation
    for r in [&mut app.routers[0], &mut app.all_routers[0]] {
        r.mikrotik_instance = Some("blue".into());
    }
    app.request_native_refresh(Uuid::nil());
    refresh(&mut app, &mut rx, &io, &registration).await;
    assert_eq!(app.current_peers.len(), 2);
    assert_eq!(app.current_routes[0].as_path_str(), "65001,{65002,65003}");
    assert_eq!(
        app.current_routes[0].status,
        Some(crate::bgp::RouteStatus::Filtered)
    );
    assert_eq!(app.current_summary.as_ref().unwrap().total_prefixes(), None);
    assert!(app
        .current_peers
        .iter()
        .all(|p| p.prefixes_advertised.is_none()));
    app.current_tab = ActiveTab::Peers;
    app.peer_table_state.select(Some(0));
    assert_eq!(
        app.current_peers[0].identity(),
        crate::bgp::PeerKey::RouterOsConnection {
            instance: "blue".into(),
            name: "peer-a".into(),
        }
    );
    let mut terminal = Terminal::new(TestBackend::new(220, 50)).unwrap();
    terminal
        .draw(|frame| crate::ui::draw(frame, &mut app))
        .unwrap();
    let rows = terminal
        .backend()
        .buffer()
        .content
        .chunks(220)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let header = rows
        .iter()
        .find(|row| row.concat().contains("Pfx/Tx"))
        .unwrap();
    let tx_column = header
        .windows(6)
        .position(|cells| cells.concat() == "Pfx/Tx")
        .unwrap();
    let peer = rows
        .iter()
        .find(|row| row.concat().contains("192.0.2.2"))
        .unwrap();
    assert!(
        peer.concat().contains("▶ 192.0.2.2"),
        "assert the selected peer's table row, not a detail label"
    );
    assert_eq!(
        peer[tx_column..tx_column + 7].concat(),
        "N/A    ",
        "peer-a Pfx/Tx must be unavailable, not invented zero"
    );

    key(&mut app, KeyCode::Char('n'));
    let e = app.native_editor.as_mut().unwrap();
    e.operation = Uuid::from_u128(42);
    for (field, value) in [
        (0, "acceptance-peer"),
        (1, "2001:db8::2"),
        (2, "65002"),
        (4, "ip,ipv6"),
        (6, "created α"),
    ] {
        e.draft.values[field] = value.into();
        e.draft.changed.insert(field);
    }
    key(&mut app, KeyCode::Enter);
    assert_eq!(
        app.native_editor.as_ref().unwrap().stage,
        NativeEditorStage::Review
    );
    assert!(rx.try_recv().is_err());
    assert!(app
        .router_db
        .as_ref()
        .unwrap()
        .load_config_history(Uuid::nil())
        .unwrap()
        .is_empty());
    let review = app
        .native_editor
        .as_ref()
        .unwrap()
        .preview
        .as_ref()
        .unwrap();
    assert!(review
        .visible_diff
        .iter()
        .any(|s| s.contains("disabled = true")));
    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::Enter); // never enqueue twice
    let preview = take_apply(&mut rx);
    finish_verified(&mut app, &io, preview, 3).await;
    refresh(&mut app, &mut rx, &io, &registration).await;
    select_connection(&mut app, "acceptance-peer");
    assert_eq!(app.current_peers[2].admin_disabled, Some(true));

    key(&mut app, KeyCode::Char('s')); // separately confirmed enable, not runtime toggle
    assert!(
        matches!(&app.native_editor.as_ref().unwrap().preview.as_ref().unwrap().intent, NativeIntent::SetDisabled { target, disabled:false } if target.observed_id == "*C")
    );
    assert!(rx.try_recv().is_err());
    key(&mut app, KeyCode::Enter);
    let preview = take_apply(&mut rx);
    finish_verified(&mut app, &io, preview, 1).await;
    refresh(&mut app, &mut rx, &io, &registration).await;

    // Config text cannot authorize or retarget a connection: only paired metadata.
    app.current_tab = ActiveTab::Config;
    let line = app
        .native_view
        .as_ref()
        .unwrap()
        .config_targets
        .iter()
        .position(|t| matches!(t, Some(NativeConfigTarget::Connection(c)) if c.observed_id == "*C"))
        .unwrap();
    app.config_lines[line] = "neighbor 192.0.2.2 remote-as 1".into();
    app.config_list_state.select(Some(line));
    key(&mut app, KeyCode::Char('e'));
    let e = app.native_editor.as_mut().unwrap();
    assert_eq!(e.target.as_ref().unwrap().name, "acceptance-peer");
    e.draft.values[6] = "patched α".into();
    e.draft.changed.insert(6);
    assert_eq!(e.draft.values[13], "Keep");
    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::Enter);
    let preview = take_apply(&mut rx);
    assert!(
        matches!(&preview.intent, NativeIntent::Patch { changes, .. } if changes.properties.len() == 1 && matches!(changes.secret, SecretChange::Keep))
    );
    finish_verified(&mut app, &io, preview, 1).await;
    refresh(&mut app, &mut rx, &io, &registration).await;

    app.current_tab = ActiveTab::Config;
    let line = app
        .native_view
        .as_ref()
        .unwrap()
        .config_targets
        .iter()
        .position(|t| matches!(t, Some(NativeConfigTarget::Chain(c)) if c == INPUT))
        .unwrap();
    app.config_list_state.select(Some(line));
    key(&mut app, KeyCode::Char('e'));
    key(&mut app, KeyCode::Char('a'));
    for c in rule_text.chars() {
        key(
            &mut app,
            if c == '\n' {
                KeyCode::Enter
            } else {
                KeyCode::Char(c)
            },
        );
    }
    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
    );
    key(&mut app, KeyCode::Char(' ')); // request enable only after insert and position
    key(&mut app, KeyCode::Enter); // acknowledgment is independent of confirmation
    assert_eq!(
        app.native_filter_editor.as_ref().unwrap().stage,
        NativeEditorStage::Fields
    );
    assert!(rx.try_recv().is_err());
    key(&mut app, KeyCode::Char('s'));
    key(&mut app, KeyCode::Enter);
    let e = app.native_filter_editor.as_ref().unwrap();
    assert_eq!(e.stage, NativeEditorStage::Review);
    assert!(e
        .preview
        .as_ref()
        .unwrap()
        .warnings
        .iter()
        .any(|s| s == "live changes; not atomic; shared consumers may be affected."));
    assert!(rx.try_recv().is_err());
    key(&mut app, KeyCode::Enter);
    let preview = take_apply(&mut rx);
    finish_verified(&mut app, &io, preview, 3).await;
    refresh(&mut app, &mut rx, &io, &registration).await;
    let source = &app.native_view.as_ref().unwrap().snapshot.inventory;
    assert_eq!(
        source
            .rules
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        ["*5", "*6", "*D", "*A", "*B"]
    );
    assert_eq!(source.rules[2].props["rule"], rule_text);
    assert_eq!(source.connections[0], initial.connections[0]);

    select_connection(&mut app, "acceptance-peer");
    key(&mut app, KeyCode::Char('s'));
    assert!(matches!(
        &app.native_editor
            .as_ref()
            .unwrap()
            .preview
            .as_ref()
            .unwrap()
            .intent,
        NativeIntent::SetDisabled { disabled: true, .. }
    ));
    key(&mut app, KeyCode::Enter);
    let preview = take_apply(&mut rx);
    finish_verified(&mut app, &io, preview, 1).await;
    refresh(&mut app, &mut rx, &io, &registration).await;
    select_connection(&mut app, "acceptance-peer");
    key(&mut app, KeyCode::Char('x'));
    key(&mut app, KeyCode::Enter);
    let preview = take_apply(&mut rx);
    assert!(matches!(&preview.intent, NativeIntent::Delete(t) if t.observed_id == "*C"));
    finish_verified(&mut app, &io, preview, 1).await;
    refresh(&mut app, &mut rx, &io, &registration).await;
    let source = &app.native_view.as_ref().unwrap().snapshot.inventory;
    assert_eq!(source.connections.len(), 2);
    assert_eq!(source.rules, filtered.rules);
    assert_eq!(source.templates, initial.templates);
    assert!(app
        .rendered_config
        .starts_with("RouterOS 7.24.7 (long-term) — instance blue / main"));
    assert!(
        !app.rendered_config.contains("router bgp") && !app.rendered_config.contains("route-map")
    );
    app.load_config_history();
    assert_eq!(app.config_history.len(), 6);
    for entry in &app.config_history {
        assert!(!entry.is_replayable() && entry.rollback.is_empty());
        let receipt: NativeReceipt = serde_json::from_str(&entry.commands[0]).unwrap();
        assert_eq!(receipt.outcome, NativeOutcome::VerifiedApplied);
        assert!(!entry.commands[0].contains("/routing/") && !entry.commands[0].contains(rule_text));
    }
    app.execute_rollback(0);
    assert!(rx.try_recv().is_err());
    assert_eq!(io.mutation_attempts(), 10);
    assert_eq!(io.seen_labels().len(), 181); // discovery + reads + exact guarded steps
    assert_eq!(
        io.seen_labels()
            .into_iter()
            .filter(|s| s.starts_with("neighbor.") || s.starts_with("filter."))
            .collect::<Vec<_>>(),
        [
            "neighbor.reject-in",
            "neighbor.reject-out",
            "neighbor.create",
            "neighbor.admin",
            "neighbor.patch",
            "filter.insert",
            "filter.move",
            "filter.patch",
            "neighbor.admin",
            "neighbor.delete"
        ]
    );
    assert!(io.seen_labels().iter().all(|label| [
        "version",
        "instances",
        "connections",
        "templates",
        "sessions",
        "rules",
        "routes",
        "neighbor.reject-in",
        "neighbor.reject-out",
        "neighbor.create",
        "neighbor.admin",
        "neighbor.patch",
        "neighbor.delete",
        "filter.insert",
        "filter.move",
        "filter.patch"
    ]
    .contains(label)));
    for tab in ['1', '2', '3', '4', '5', '6', '7'] {
        key(&mut app, KeyCode::Char(tab));
    }
    assert_eq!(app.current_tab, ActiveTab::ConnLog);
    assert!(
        rx.try_recv().is_err(),
        "ordinary navigation must remain cache-only"
    );
}

#[tokio::test]
async fn mikrotik_acceptance_optional_rib_failure_keeps_last_good_and_stale_template_writes_nothing(
) {
    // Losing optional RIB telemetry must not erase peers/routes or rebase a draft.
    let initial = documented_inventory();
    let mut changed = initial.clone();
    changed.templates.push(record(
        json!({".id":"*E","name":"parent","vrf":"main","comment":"external change"}),
    ));
    changed.connections[1]
        .props
        .insert("templates".into(), json!("parent"));
    let mut replies = monitoring_replies(&initial);
    replies.extend(configuration_replies(&changed));
    replies.push(Reply::Failure {
        code: "timeout",
        started: true,
    });
    replies.extend(configuration_replies(&changed));
    let io = TranscriptExecutor::new(replies);
    let (mut app, mut rx) = app(Some("blue"));
    app.request_native_refresh(Uuid::nil());
    refresh(&mut app, &mut rx, &io, &documented_registration()).await;
    app.current_tab = ActiveTab::Peers;
    select_connection(&mut app, "peer-b");
    key(&mut app, KeyCode::Char('e'));
    let e = app.native_editor.as_mut().unwrap();
    e.draft.values[6] = "local draft".into();
    e.draft.changed.insert(6);
    let generation = e.generation;
    key(&mut app, KeyCode::Enter);
    app.request_native_refresh(Uuid::nil());
    refresh(&mut app, &mut rx, &io, &documented_registration()).await;
    assert_eq!(app.current_peers.len(), 2);
    assert_eq!(app.current_routes.len(), 1);
    assert_eq!(app.current_routes[0].network, "203.0.113.0/24");
    assert!(app.native_cache[&Uuid::nil()]
        .stale_reason
        .as_ref()
        .unwrap()
        .contains("Stored routes unavailable/stale"));
    assert_eq!(app.native_editor.as_ref().unwrap().generation, generation);
    assert_eq!(
        app.native_editor.as_ref().unwrap().draft.values[6],
        "local draft"
    );
    key(&mut app, KeyCode::Enter);
    let receipt = apply_native(&io, take_apply(&mut rx)).await;
    assert_eq!(receipt.outcome, NativeOutcome::RejectedBeforeWrite);
    assert_eq!(io.mutation_attempts(), 0);
    assert_eq!(
        io.seen_labels().iter().filter(|s| **s == "routes").count(),
        2
    );
    assert!(app
        .current_peers
        .iter()
        .all(|p| p.prefixes_advertised.is_none()));
}

#[tokio::test]
async fn mikrotik_acceptance_rf1_secret_intentions_redacted_cleared_and_need_private_proof() {
    // A missing private proof must never be promoted to secret success; typed
    // payloads may hold the secret only until dispatch, never in UI/history.
    for (mode, proof, expected) in [
        ("Replace", false, NativeOutcome::Indeterminate),
        ("Clear", false, NativeOutcome::Indeterminate),
        ("Clear", true, NativeOutcome::VerifiedApplied),
    ] {
        let snapshot = documented_snapshot();
        let mut replies = write_replies(&snapshot.inventory, &[("*2", &snapshot.inventory)]);
        replies.push(Reply::Data(json!({"id":"*2","verified":proof})));
        let io = TranscriptExecutor::new(replies);
        let (mut app, mut rx) = crate::app::filter_test_app(Some(snapshot));
        key(&mut app, KeyCode::Esc);
        app.current_tab = ActiveTab::Peers;
        select_connection(&mut app, "peer-a");
        key(&mut app, KeyCode::Char('e'));
        let e = app.native_editor.as_mut().unwrap();
        e.draft.values[13] = mode.into();
        if mode == "Replace" {
            e.draft.values[14] = "ACCEPTANCE_MD5_SENTINEL".into();
        }
        key(&mut app, KeyCode::Enter);
        let preview = app
            .native_editor
            .as_ref()
            .unwrap()
            .preview
            .as_ref()
            .unwrap();
        assert!(preview
            .visible_diff
            .iter()
            .any(|s| s.contains(&format!("Authentication: {mode}"))));
        assert!(!preview
            .visible_diff
            .join("\n")
            .contains("ACCEPTANCE_MD5_SENTINEL"));
        assert!(!screen(&mut app).contains("ACCEPTANCE_MD5_SENTINEL"));
        key(&mut app, KeyCode::Enter);
        assert!(app.native_editor.as_ref().unwrap().draft.values[14].is_empty());
        let receipt = apply_native(&io, take_apply(&mut rx)).await;
        assert_eq!(receipt.outcome, expected);
        assert_eq!(io.mutation_attempts(), 1);
        assert!(io.seen_labels().contains(&"neighbor.secret-check"));
        event(&mut app, AppEvent::MikroTikApplied(receipt));
        app.load_config_history();
        assert_eq!(app.config_history.len(), 1);
        let stored = &app.config_history[0].commands[0];
        for forbidden in [
            "ACCEPTANCE_MD5_SENTINEL",
            "tcp-md5-key",
            "/routing/",
            "\"intent\"",
        ] {
            assert!(!stored.contains(forbidden));
        }
        assert!(!app.config_history[0].is_replayable());
        key(&mut app, KeyCode::Esc);
        assert!(app.native_editor.is_none());
    }
}

#[tokio::test]
async fn mikrotik_acceptance_rf5_late_origin_events_cannot_change_new_router_editor() {
    let (mut app, mut rx) = crate::app::filter_test_app(None);
    key(&mut app, KeyCode::Esc);
    let old = app.native_view.as_ref().unwrap().snapshot.as_ref().clone();
    app.current_tab = ActiveTab::Peers;
    select_connection(&mut app, "peer-a");
    key(&mut app, KeyCode::Char('s'));
    key(&mut app, KeyCode::Enter);
    let preview = take_apply(&mut rx);
    let mut after = old.inventory.clone();
    after.connections[0]
        .props
        .insert("disabled".into(), json!(true));
    let io = TranscriptExecutor::new(write_replies(&old.inventory, &[("*2", &after)]));
    let receipt = apply_native(&io, preview).await;
    assert_eq!(receipt.outcome, NativeOutcome::VerifiedApplied);
    key(&mut app, KeyCode::Esc); // launched operation still belongs to A
    let mut replacement = app.routers[0].clone();
    replacement.id = Uuid::from_u128(99);
    replacement.hostname = "other.invalid".into();
    app.routers.push(replacement.clone());
    app.all_routers.push(replacement);
    app.router_list_state.select(Some(1));
    app.request_native_refresh(Uuid::from_u128(99));
    let mut registration = documented_registration();
    registration.router_id = Uuid::from_u128(99);
    registration.revision = Uuid::from_u128(100);
    registration.endpoint.hostname = "other.invalid".into();
    let io = TranscriptExecutor::new(monitoring_replies(&documented_inventory()));
    refresh(&mut app, &mut rx, &io, &registration).await;
    key(&mut app, KeyCode::Char('n'));
    let e = app.native_editor.as_mut().unwrap();
    e.draft.values[0] = "new-router-draft".into();
    let operation = e.operation;
    let source = Arc::clone(&e.base);
    app.set_status("new editor owns status");
    event(&mut app, AppEvent::MikroTikApplied(receipt));
    event(
        &mut app,
        AppEvent::NativeData(
            old.router_id,
            old.request,
            Box::new(NativeDiscovery::Snapshot(old.clone())),
        ),
    );
    event(
        &mut app,
        AppEvent::NativeError(old.router_id, old.request, "old read failed".into()),
    );
    let e = app.native_editor.as_ref().unwrap();
    assert_eq!(e.operation, operation);
    assert_eq!(e.stage, NativeEditorStage::Fields);
    assert_eq!(e.draft.values[0], "new-router-draft");
    assert!(Arc::ptr_eq(&e.base, &source));
    assert_eq!(
        app.native_view.as_ref().unwrap().snapshot.router_id,
        Uuid::from_u128(99)
    );
    assert_eq!(
        app.status_message.as_deref(),
        Some("new editor owns status")
    );
    let history = app
        .router_db
        .as_ref()
        .unwrap()
        .load_config_history(Uuid::nil())
        .unwrap();
    assert_eq!(history.len(), 1);
    assert!(history[0].description.contains("original lab.invalid:22"));
    assert!(app
        .router_db
        .as_ref()
        .unwrap()
        .load_config_history(Uuid::from_u128(99))
        .unwrap()
        .is_empty());
}

fn native_receipt_history_entry() -> ConfigHistoryEntry {
    let mut registration = documented_registration();
    registration.revision = Uuid::nil();
    let receipt = NativeReceipt {
        router_id: Uuid::nil(),
        operation: Uuid::nil(),
        instance: "blue".into(),
        registration,
        outcome: NativeOutcome::VerifiedApplied,
        verified_steps: vec!["Verified configured administrative state".into()],
        uncertain_steps: vec![],
        unapplied_steps: vec![],
        summary: "Redacted native receipt; not executable".into(),
    };
    ConfigHistoryEntry {
        id: Uuid::nil(),
        router_id: Uuid::nil(),
        action: "mikrotik_receipt:VerifiedApplied".into(),
        description: "Safe native receipt".into(),
        commands: vec![serde_json::to_string(&receipt).unwrap()],
        rollback: vec![],
        applied_at: "2026-11-24T00:00:00Z".into(),
    }
}

#[test]
fn mikrotik_acceptance_native_history_is_never_legacy_rollback() {
    let entry = native_receipt_history_entry();
    assert!(!entry.is_replayable());
    assert!(entry.rollback.is_empty());
    assert!(entry.action.starts_with("mikrotik_receipt:"));
}

#[test]
fn mikrotik_acceptance_forged_native_rollback_rejected_even_after_vendor_change() {
    let (mut app, mut rx) = app(Some("blue"));
    for r in [&mut app.routers[0], &mut app.all_routers[0]] {
        r.vendor = RouterVendor::Cisco;
    }
    let mut entry = native_receipt_history_entry();
    entry.rollback = vec!["FORGED_LEGACY_ROLLBACK".into()];
    assert!(!entry.is_replayable());
    app.config_history.push(entry);
    app.execute_rollback(0);
    assert!(rx.try_recv().is_err());
    // Control: old vendors' genuine legacy history still dispatches normally.
    app.config_history[0].action = "edit".into();
    app.execute_rollback(0);
    assert!(
        matches!(rx.try_recv().unwrap(), FetchRequest::RollbackConfig { history_action, commands, .. } if history_action == "edit" && commands == ["FORGED_LEGACY_ROLLBACK"])
    );
}

#[test]
fn mikrotik_acceptance_neighbor_fields_direct_filters_to_config_chain_editor() {
    // Reintroducing obsolete read-only guidance must fail at the actual Fields
    // widget, not match unrelated Config/help text elsewhere in the frame.
    let (mut app, mut rx) = crate::app::filter_test_app(None);
    key(&mut app, KeyCode::Esc);
    app.current_tab = ActiveTab::Peers;
    select_connection(&mut app, "peer-a");
    key(&mut app, KeyCode::Char('e'));
    assert_eq!(
        app.native_editor.as_ref().unwrap().stage,
        NativeEditorStage::Fields
    );
    let rendered = screen(&mut app);
    assert!(
        !rendered.contains("Filter editing read-only."),
        "native Fields still deny delivered filter editing:\n{rendered}"
    );
    let guidance = rendered
        .lines()
        .find(|row| row.contains("Bindings here;"))
        .expect("Fields must distinguish neighbor bindings from Config rule editing");
    assert!(guidance.contains("Bindings here; Config chain row/e: ordered filter editor."));
    assert!(rx.try_recv().is_err(), "opening Fields must not send SSH");
}
