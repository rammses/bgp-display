use super::{
    ActiveTab, App, NativeConfigTarget, NativeEditorDraft, NativeEditorMode, NativeEditorStage,
    NativeEditorState,
};
use crate::events::FetchRequest;
use crate::router::commands::mikrotik::{bool_value, target_record};
use crate::router::mikrotik::*;
use crate::router::RouterVendor;
use anyhow::{ensure, Context, Result};
use crossterm::event::{KeyCode, KeyEvent};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) const NATIVE_FIELDS: [&str; 15] = [
    "Name (identity)",
    "Remote host (identity)",
    "Remote AS",
    "Role (Space: cycle)",
    "AFI (independent of transport; Space)",
    "Source / local.address",
    "Comment",
    "Hold time",
    "Keepalive time",
    "Next-hop (Space)",
    "BFD request (Space)",
    "Input filter binding",
    "Output filter binding",
    "MD5 Keep / Replace / Clear (Space)",
    "MD5 replacement (hidden)",
];
const PROPERTY_FIELDS: [(usize, &str); 11] = [
    (2, "remote.as"),
    (3, "local.role"),
    (4, "afi"),
    (5, "local.address"),
    (6, "comment"),
    (7, "hold-time"),
    (8, "keepalive-time"),
    (9, "nexthop-choice"),
    (10, "use-bfd"),
    (11, "input.filter"),
    (12, "output.filter-chain"),
];

fn display_value(value: &Value) -> String {
    match value {
        Value::String(v) => v.clone(),
        Value::Array(v) => v
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(","),
        _ => value.to_string(),
    }
}

impl NativeEditorState {
    pub(crate) fn native_field_hint(&self, index: usize) -> String {
        let Some((_, key)) = PROPERTY_FIELDS.iter().find(|(field, _)| *field == index) else {
            return "<required; enter value>".into();
        };
        let Some(row) = self.target.as_ref().and_then(|target| {
            self.base
                .inventory
                .connections
                .iter()
                .find(|row| row.id == target.observed_id)
        }) else {
            return "<not set; creation uses native default for optional fields>".into();
        };
        if row.props.contains_key(*key) {
            return "<explicit empty value; Keep unless changed>".into();
        }
        match crate::router::commands::mikrotik::inherited_value(&self.base.inventory, row, key) {
            Ok(Some(value)) => {
                format!("<inherited {}; Keep unless changed>", display_value(&value))
            }
            Ok(None) => "<native default; no explicit override; Keep unless changed>".into(),
            Err(_) => "<inheritance unresolved; preserved unless explicitly changed>".into(),
        }
    }
}

fn draft_intent(editor: &NativeEditorState) -> Result<NativeIntent> {
    let values = &editor.draft.values;
    let secret = match values[13].as_str() {
        "Keep" => SecretChange::Keep,
        "Clear" => SecretChange::Clear,
        "Replace" => SecretChange::Replace(values[14].clone()),
        _ => anyhow::bail!("choose Keep, Replace or Clear"),
    };
    let target = || editor.target.clone().context("native target unavailable");
    Ok(match editor.mode {
        NativeEditorMode::Create => {
            let optional = |i: usize| (!values[i].is_empty()).then(|| values[i].clone());
            let source = if values[5].is_empty() {
                None
            } else {
                Some(
                    values[5]
                        .parse()
                        .map_err(|_| anyhow::anyhow!("invalid fixed source address"))?,
                )
            };
            let bfd = if values[10].is_empty() {
                None
            } else {
                Some(bool_value(&json!(values[10])).context("invalid BFD request")?)
            };
            NativeIntent::Create(NativeConnectionDraft {
                name: values[0].clone(),
                remote_address: values[1]
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid fixed remote host"))?,
                remote_as: crate::router::commands::mikrotik::as_value(&json!(values[2]))
                    .context("invalid explicit remote AS")?,
                role: values[3].clone(),
                afi: values[4].split(',').map(str::to_owned).collect(),
                source,
                comment: values[6].clone(),
                hold_time: optional(7),
                keepalive_time: optional(8),
                nexthop_choice: optional(9),
                use_bfd: bfd,
                secret,
            })
        }
        NativeEditorMode::Patch => {
            let mut properties = Properties::new();
            for (index, key) in PROPERTY_FIELDS {
                if editor.draft.changed.contains(&index) {
                    properties.insert(
                        key.into(),
                        if values[index] == "~" && key != "comment" {
                            Value::Null
                        } else {
                            json!(values[index])
                        },
                    );
                }
            }
            NativeIntent::Patch {
                target: target()?,
                changes: NativePatch { properties, secret },
            }
        }
        NativeEditorMode::Admin(disabled) => NativeIntent::SetDisabled {
            target: target()?,
            disabled,
        },
        NativeEditorMode::Delete => NativeIntent::Delete(target()?),
    })
}

impl App {
    pub(crate) fn open_native_create(&mut self) {
        self.open_native_mode(NativeEditorMode::Create);
    }
    pub(crate) fn open_native_edit(&mut self) {
        self.open_native_mode(NativeEditorMode::Patch);
    }
    pub(crate) fn open_native_delete(&mut self) {
        self.open_native_mode(NativeEditorMode::Delete);
    }
    pub(crate) fn open_native_admin(&mut self) {
        self.open_native_mode(NativeEditorMode::Admin(false));
    }

    pub(crate) fn open_native_config_target(&mut self) {
        match self.displayed_native_target().map(|(_, target)| target) {
            Some(NativeConfigTarget::Connection(_)) => self.open_native_edit(),
            Some(NativeConfigTarget::Chain(_)) => self.set_status(
                "Native filter editing is read-only until the guarded filter editor is available",
            ),
            None => self.set_status(
                "Select a native connection source row; text/IP is not an authorization target",
            ),
        }
    }

    fn open_native_mode(&mut self, mut mode: NativeEditorMode) {
        if self.native_editor.is_some() {
            return;
        }
        let opened = (|| -> Result<NativeEditorState> {
            let router = self.selected_router().context("select a native router")?;
            ensure!(
                router.vendor == RouterVendor::MikroTik,
                "native editor requires MikroTik"
            );
            let base = Arc::clone(
                &self
                    .native_view
                    .as_ref()
                    .context("refresh a selected BGP instance first")?
                    .snapshot,
            );
            ensure!(
                base.router_id == router.id
                    && router.mikrotik_instance.as_deref() == Some(base.instance.as_str())
                    && router.hostname == base.registration.endpoint.hostname
                    && router.username == base.registration.endpoint.username
                    && router.ssh_port == base.registration.endpoint.ssh_port,
                "displayed native registration or scope changed; refresh"
            );
            ensure!(
                base.guard == config_guard(&base.inventory, &base.instance)?,
                "native source is not actionable; refresh"
            );
            let target = if mode == NativeEditorMode::Create {
                None
            } else if self.current_tab == ActiveTab::Config {
                match self.displayed_native_target().map(|(_, target)| target) {
                    Some(NativeConfigTarget::Connection(target)) => Some(target.clone()),
                    _ => anyhow::bail!(
                        "select a native connection; filter editing remains read-only"
                    ),
                }
            } else {
                let peer = self
                    .peer_table_state
                    .selected()
                    .and_then(|i| self.peer_indices.get(i))
                    .and_then(|i| self.current_peers.get(*i))
                    .context("select a native configured peer")?;
                let key = peer
                    .key
                    .as_ref()
                    .context("native source identity unavailable")?;
                base.peers
                    .iter()
                    .find(|row| super::mikrotik::native_peer_key(row) == *key)
                    .and_then(|row| row.connection.clone())
                    .context("runtime-only peer has no editable connection")?
                    .into()
            };
            let mut values = vec![String::new(); NATIVE_FIELDS.len()];
            values[3] = "ebgp".into();
            values[13] = "Keep".into();
            if let Some(target) = &target {
                let row = target_record(&base, target, base.generation)?;
                values[0] = target.name.clone();
                values[1] = row
                    .props
                    .get("remote.address")
                    .map(display_value)
                    .unwrap_or_default();
                for (index, key) in PROPERTY_FIELDS {
                    values[index] = row.props.get(key).map(display_value).unwrap_or_default();
                }
                if matches!(mode, NativeEditorMode::Admin(_)) {
                    mode = NativeEditorMode::Admin(
                        !row.props
                            .get("disabled")
                            .and_then(bool_value)
                            .context("configured administrative state unknown")?,
                    );
                }
            }
            Ok(NativeEditorState {
                router_id: base.router_id,
                instance: base.instance.clone(),
                generation: base.generation,
                registration: base.registration.clone(),
                base,
                target,
                draft: NativeEditorDraft {
                    values,
                    changed: Default::default(),
                },
                preview: None,
                stage: NativeEditorStage::Fields,
                operation: Uuid::new_v4(),
                mode,
                field: if mode == NativeEditorMode::Patch {
                    2
                } else {
                    0
                },
                scroll: 0,
                error: None,
                receipt: None,
            })
        })();
        match opened {
            Ok(editor) => {
                let immediate = matches!(
                    editor.mode,
                    NativeEditorMode::Admin(_) | NativeEditorMode::Delete
                );
                self.native_editor = Some(editor);
                if immediate {
                    self.native_generate_preview();
                }
            }
            Err(error) => {
                self.set_status(format!("Native neighbor read-only/unavailable: {error}"))
            }
        }
    }

    pub fn native_generate_preview(&mut self) {
        let Some(editor) = self
            .native_editor
            .as_mut()
            .filter(|e| e.stage == NativeEditorStage::Fields)
        else {
            return;
        };
        let result = draft_intent(editor)
            .and_then(|intent| preview_native(&editor.base, intent, editor.operation));
        match result {
            Ok(preview)=>{editor.preview=Some(preview);editor.stage=NativeEditorStage::Review;editor.scroll=0;editor.error=None;},
            Err(_)=>editor.error=Some("Invalid/unavailable native change. Check explicit AS/role/AFI, fixed source family, native timers/bindings, identity and scope. No command sent.".into()),
        }
    }

    pub fn confirm_native(&mut self) {
        let Some(editor) = self
            .native_editor
            .as_ref()
            .filter(|e| e.stage == NativeEditorStage::Review)
        else {
            return;
        };
        let current = self.selected_router().is_some_and(|r| {
            r.vendor == RouterVendor::MikroTik
                && r.id == editor.router_id
                && r.hostname == editor.registration.endpoint.hostname
                && r.username == editor.registration.endpoint.username
                && r.ssh_port == editor.registration.endpoint.ssh_port
                && r.mikrotik_instance.as_deref() == Some(editor.instance.as_str())
        });
        if !current
            || editor.generation != editor.base.generation
            || editor.registration != editor.base.registration
        {
            self.native_editor = None;
            self.set_status("Native context changed; review canceled. Refresh before editing.");
            return;
        }
        let Some(editor) = self.native_editor.as_mut() else {
            return;
        };
        let Some(preview) = editor.preview.take() else {
            return;
        };
        editor.draft.clear_secret();
        editor.stage = NativeEditorStage::Applying;
        let failure = rejected_receipt(&preview);
        if self
            .fetch_tx
            .as_ref()
            .is_none_or(|tx| tx.send(FetchRequest::ApplyMikroTik(preview)).is_err())
        {
            self.handle_native_receipt(failure);
        }
    }

    pub(crate) fn handle_native_editor_key(&mut self, key: KeyEvent) {
        let Some(editor) = self.native_editor.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc=>{
                let applying=editor.stage==NativeEditorStage::Applying;
                self.native_editor=None;
                if applying {self.set_status("Editor closed; a launched remote operation may continue. Its originating receipt will still be stored.");}
            },
            KeyCode::Enter=>match editor.stage {
                NativeEditorStage::Fields=>self.native_generate_preview(),NativeEditorStage::Review=>self.confirm_native(),
                NativeEditorStage::Applying=>{},NativeEditorStage::Result=>self.native_editor=None,
            },
            KeyCode::BackTab if editor.stage==NativeEditorStage::Review=>{editor.preview=None;editor.stage=NativeEditorStage::Fields;},
            KeyCode::PageDown if editor.stage!=NativeEditorStage::Fields=>editor.scroll=editor.scroll.saturating_add(5),
            KeyCode::PageUp if editor.stage!=NativeEditorStage::Fields=>editor.scroll=editor.scroll.saturating_sub(5),
            KeyCode::Home if editor.stage!=NativeEditorStage::Fields=>editor.scroll=0,
            _ if editor.stage!=NativeEditorStage::Fields=>{},
            KeyCode::Tab|KeyCode::Down=>editor.field=(editor.field+1)%NATIVE_FIELDS.len(),
            KeyCode::BackTab|KeyCode::Up=>editor.field=(editor.field+NATIVE_FIELDS.len()-1)%NATIVE_FIELDS.len(),
            _ if editor.mode==NativeEditorMode::Patch && editor.field<2=>editor.error=Some("Identity/scope fields are read-only. No rename or endpoint change is supported.".into()),
            _ if editor.mode==NativeEditorMode::Create && matches!(editor.field,11|12)=>editor.error=Some("Creation attaches generated deny-all chains; bindings are not user-editable during create.".into()),
            KeyCode::Char(' ') if matches!(editor.field,3|4|9|10|13)=>{
                let choices:&[&str]=match editor.field {3=>&["ebgp","ibgp","ibgp-rr"],4=>&["ip","ipv6","ip,ipv6"],
                    9=>&["default","force-self","propagate","~"],10=>&["yes","no","~"],_=>&["Keep","Replace","Clear"]};
                let current=choices.iter().position(|v|*v==editor.draft.values[editor.field]);
                editor.draft.values[editor.field]=choices[current.map_or(0,|i|(i+1)%choices.len())].into();
                editor.draft.changed.insert(editor.field);
                if editor.field==13 && editor.draft.values[13]!="Replace" {editor.draft.values[14].clear();}
            },
            KeyCode::Char(_) if editor.field==13=>editor.error=Some("Space cycles Keep / Replace / Clear".into()),
            KeyCode::Char(_) | KeyCode::Backspace if editor.field==14 && editor.draft.values[13]!="Replace"=>editor.error=Some("Choose Replace before entering a hidden replacement".into()),
            KeyCode::Backspace=>{editor.draft.values[editor.field].pop();editor.draft.changed.insert(editor.field);},
            KeyCode::Char(c)=>{editor.draft.values[editor.field].push(c);editor.draft.changed.insert(editor.field);},
            _=>{},
        }
    }

    pub fn handle_native_receipt(&mut self, receipt: NativeReceipt) {
        if self.native_receipts.contains_key(&receipt.operation) {
            return;
        }
        let matches_editor = self.native_editor.as_ref().is_some_and(|e| {
            e.stage == NativeEditorStage::Applying
                && e.operation == receipt.operation
                && e.router_id == receipt.router_id
                && e.instance == receipt.instance
                && e.registration == receipt.registration
        });
        let same_context = self.all_routers.iter().any(|r| {
            r.id == receipt.router_id
                && r.vendor == RouterVendor::MikroTik
                && r.hostname == receipt.registration.endpoint.hostname
                && r.username == receipt.registration.endpoint.username
                && r.ssh_port == receipt.registration.endpoint.ssh_port
                && r.mikrotik_instance.as_deref() == Some(receipt.instance.as_str())
        }) && (matches_editor
            || self
                .native_cache
                .get(&receipt.router_id)
                .and_then(|c| c.snapshot.as_ref())
                .is_some_and(|s| s.registration == receipt.registration));
        let stored = if let Some(db) = &self.router_db {
            serde_json::to_string(&receipt)
                .map_err(anyhow::Error::from)
                .and_then(|safe_json| {
                    db.insert_config_history(
                        receipt.router_id,
                        &format!("mikrotik_receipt:{}", receipt.operation),
                        &presentation_text(&format!(
                            "original {}:{} / user {} / revision {} / instance {} — {:?} ({})",
                            receipt.registration.endpoint.hostname,
                            receipt.registration.endpoint.ssh_port,
                            receipt.registration.endpoint.username,
                            receipt.registration.revision,
                            receipt.instance,
                            receipt.outcome,
                            receipt.operation
                        )),
                        &[safe_json],
                        &[],
                    )
                })
                .is_ok()
        } else {
            false
        };
        self.native_receipts
            .insert(receipt.operation, receipt.clone());
        if !stored {
            self.log(format!(
                "Native receipt {} retained in memory; encrypted history persistence failed",
                receipt.operation
            ));
        }
        if same_context {
            // Unlike configuration invalidation, result invalidation NEVER drops
            // another editor (even a new editor for this same router).
            if self.native_editor.is_none() || matches_editor {
                self.invalidate_native_views(receipt.router_id);
            } else {
                self.native_cache.remove(&receipt.router_id);
                self.bgp_cache.remove(&receipt.router_id);
                self.native_refresh_pending.remove(&receipt.router_id);
            }
            self.request_native_refresh(receipt.router_id);
        }
        if matches_editor {
            if let Some(editor) = self.native_editor.as_mut() {
                editor.draft.clear_secret();
                editor.preview = None;
                editor.stage = NativeEditorStage::Result;
                editor.scroll = 0;
                editor.receipt = Some(receipt.clone());
                if !stored {
                    editor.error = Some(
                        "Receipt retained in memory; encrypted history persistence failed".into(),
                    );
                }
            }
            self.set_status(format!(
                "Native outcome: {:?}. Refresh/re-preview required; no replay.",
                receipt.outcome
            ));
        }
        // Do not call generic handle_config_applied or touch desired_neighbors.
    }
}

#[cfg(test)]
mod tests {
    use crate::app::{ActiveTab, App, NativeEditorStage};
    use crate::config::AppConfig;
    use crate::db::RouterDb;
    use crate::events::FetchRequest;
    use crate::router::mikrotik::{test_support::*, *};
    use crate::router::{RouterConfig, RouterVendor};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use uuid::Uuid;

    fn app() -> (App, tokio::sync::mpsc::UnboundedReceiver<FetchRequest>) {
        let cfg = RouterConfig {
            id: Uuid::nil(),
            hostname: "lab.invalid".into(),
            username: "tester".into(),
            vendor: RouterVendor::MikroTik,
            mikrotik_instance: Some("blue".into()),
            ..RouterConfig::default()
        };
        let mut app = App::new(
            AppConfig {
                routers: vec![cfg],
                ..AppConfig::default()
            },
            RouterDb::in_memory().unwrap(),
        );
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        app.set_fetch_tx(tx);
        app.request_native_refresh(Uuid::nil());
        let request = match rx.try_recv().unwrap() {
            FetchRequest::RefreshMikroTik { request, .. } => request,
            _ => panic!(),
        };
        let mut snap = documented_snapshot();
        snap.request = request;
        app.handle_native_data(Uuid::nil(), request, NativeDiscovery::Snapshot(snap));
        app.current_tab = ActiveTab::Peers;
        app.peer_table_state.select(Some(0));
        (app, rx)
    }

    fn result(preview: NativePreview) -> NativeReceipt {
        NativeReceipt {
            router_id: preview.router_id,
            operation: preview.operation,
            instance: preview.instance,
            registration: preview.registration,
            outcome: NativeOutcome::Indeterminate,
            verified_steps: vec![],
            uncertain_steps: vec!["Patch connection properties".into()],
            unapplied_steps: vec![],
            summary: "safe result".into(),
        }
    }

    #[test]
    fn mikrotik_neighbor_editor_review_requires_second_enter_and_duplicate_enter_ignored() {
        let (mut app, mut rx) = app();
        app.wizard_open_edit("not-an-authorization-IP".into());
        assert!(matches!(app.wizard_mode, crate::app::WizardMode::Closed));
        app.native_editor.as_mut().unwrap().draft.values[6] = "new comment".into();
        app.native_editor.as_mut().unwrap().draft.changed.insert(6);
        app.native_generate_preview();
        assert_eq!(
            app.native_editor.as_ref().unwrap().stage,
            NativeEditorStage::Review
        );
        assert!(rx.try_recv().is_err());
        app.confirm_native();
        app.confirm_native();
        assert!(matches!(
            rx.try_recv().unwrap(),
            FetchRequest::ApplyMikroTik(_)
        ));
        assert!(rx.try_recv().is_err());
        assert_eq!(
            app.native_editor.as_ref().unwrap().stage,
            NativeEditorStage::Applying
        );
    }

    #[test]
    fn mikrotik_neighbor_admin_intention_uses_disabled_flag_not_runtime_establishment() {
        for disabled in [false, true] {
            let (mut app, mut rx) = app();
            app.request_native_refresh(Uuid::nil());
            let request = match rx.try_recv().unwrap() {
                FetchRequest::RefreshMikroTik { request, .. } => request,
                _ => panic!(),
            };
            let mut snapshot = documented_snapshot();
            snapshot.request = request;
            snapshot.inventory.connections[0]
                .props
                .insert("disabled".into(), serde_json::json!(disabled));
            snapshot.inventory.sessions[0]
                .props
                .insert("established".into(), serde_json::json!(disabled));
            snapshot.guard = config_guard(&snapshot.inventory, "blue").unwrap();
            snapshot.peers =
                join_native_peers(&snapshot.inventory, "blue", snapshot.generation).unwrap();
            app.handle_native_data(Uuid::nil(), request, NativeDiscovery::Snapshot(snapshot));
            app.toggle_peer_shutdown();
            assert!(
                matches!(&app.native_editor.as_ref().unwrap().preview.as_ref().unwrap().intent,NativeIntent::SetDisabled{disabled:requested,..} if *requested==!disabled)
            );
            assert!(rx.try_recv().is_err());
        }
    }

    #[test]
    fn mikrotik_secret_editor_cancel_confirm_and_result_leave_no_secret_in_state() {
        let (mut app, mut rx) = app();
        app.wizard_open_edit("ignored".into());
        let editor = app.native_editor.as_mut().unwrap();
        editor.draft.values[13] = "Replace".into();
        editor.draft.values[14] = "SENTINEL_MD5".into();
        app.native_generate_preview();
        assert!(!format!("{:?}", app.native_editor).contains("SENTINEL_MD5"));
        app.confirm_native();
        let preview = match rx.try_recv().unwrap() {
            FetchRequest::ApplyMikroTik(p) => p,
            _ => panic!(),
        };
        let editor = app.native_editor.as_ref().unwrap();
        assert!(editor.preview.is_none());
        assert!(editor.draft.values[14].is_empty());
        app.handle_native_receipt(result(preview));
        assert_eq!(
            app.native_editor.as_ref().unwrap().stage,
            NativeEditorStage::Result
        );
        assert!(app.native_editor.as_ref().unwrap().draft.values[14].is_empty());
        crate::app::handle_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.native_editor.is_none());
        assert!(app.desired_neighbors.is_empty());
    }

    #[test]
    fn mikrotik_receipt_rf5_old_result_does_not_overwrite_another_editor_draft_or_status() {
        let (mut app, mut rx) = app();
        app.toggle_peer_shutdown();
        app.confirm_native();
        let preview = match rx.try_recv().unwrap() {
            FetchRequest::ApplyMikroTik(p) => p,
            _ => panic!(),
        };
        app.native_editor = None;
        app.wizard_open_create();
        app.native_editor.as_mut().unwrap().draft.values[0] = "untouched-new".into();
        let op = app.native_editor.as_ref().unwrap().operation;
        app.set_status("new editor status");
        app.handle_native_receipt(result(preview));
        let editor = app.native_editor.as_ref().unwrap();
        assert_eq!(editor.operation, op);
        assert_eq!(editor.stage, NativeEditorStage::Fields);
        assert_eq!(editor.draft.values[0], "untouched-new");
        assert_eq!(app.status_message.as_deref(), Some("new editor status"));
        assert_eq!(
            app.router_db
                .as_ref()
                .unwrap()
                .load_config_history(Uuid::nil())
                .unwrap()
                .len(),
            1
        );
        let refresh = app.native_cache[&Uuid::nil()].latest_request;
        app.handle_native_error(Uuid::nil(), refresh, "synthetic refresh failure".into());
        assert_eq!(app.status_message.as_deref(), Some("new editor status"));
    }

    #[test]
    fn mikrotik_neighbor_editor_base_never_rebases_on_background_refresh_and_config_invalidation_cancels(
    ) {
        let (mut app, _rx) = app();
        app.wizard_open_edit("ignored".into());
        let base = std::sync::Arc::clone(&app.native_editor.as_ref().unwrap().base);
        app.request_native_refresh(Uuid::nil());
        let mut newer = documented_snapshot();
        newer.request = app.native_cache[&Uuid::nil()].latest_request;
        app.handle_native_data(Uuid::nil(), newer.request, NativeDiscovery::Snapshot(newer));
        assert!(std::sync::Arc::ptr_eq(
            &base,
            &app.native_editor.as_ref().unwrap().base
        ));
        app.native_editor.as_mut().unwrap().draft.values[14] = "SENTINEL_MD5".into();
        app.invalidate_native(Uuid::nil());
        assert!(app.native_editor.is_none());
    }

    #[test]
    fn mikrotik_receipt_rf5_other_router_editor_and_re_registered_endpoint_are_not_retargeted() {
        for endpoint_change in [false, true] {
            let (mut app, mut rx) = app();
            app.toggle_peer_shutdown();
            app.confirm_native();
            let preview = match rx.try_recv().unwrap() {
                FetchRequest::ApplyMikroTik(p) => p,
                _ => panic!(),
            };
            app.native_editor = None;
            let new_id = if endpoint_change {
                Uuid::nil()
            } else {
                Uuid::new_v4()
            };
            let replacement = RouterConfig {
                id: new_id,
                hostname: "replacement.invalid".into(),
                username: "tester".into(),
                vendor: RouterVendor::MikroTik,
                mikrotik_instance: Some("blue".into()),
                ..RouterConfig::default()
            };
            if endpoint_change {
                app.invalidate_native(Uuid::nil());
                app.routers[0] = replacement.clone();
                app.all_routers[0] = replacement;
            } else {
                app.routers.push(replacement.clone());
                app.all_routers.push(replacement);
                app.router_list_state.select(Some(1));
            }
            app.request_native_refresh(new_id);
            let request = match rx.try_recv().unwrap() {
                FetchRequest::RefreshMikroTik { request, .. } => request,
                _ => panic!(),
            };
            let mut new_snapshot = documented_snapshot();
            new_snapshot.router_id = new_id;
            new_snapshot.registration.router_id = new_id;
            new_snapshot.registration.revision = Uuid::new_v4();
            new_snapshot.registration.endpoint.hostname = "replacement.invalid".into();
            new_snapshot.request = request;
            app.handle_native_data(new_id, request, NativeDiscovery::Snapshot(new_snapshot));
            app.wizard_open_create();
            let operation = app.native_editor.as_ref().unwrap().operation;
            app.native_editor.as_mut().unwrap().draft.values[0] = "new untouched".into();
            app.set_status("other editor status");
            app.handle_native_receipt(result(preview));
            let editor = app.native_editor.as_ref().unwrap();
            assert_eq!(editor.operation, operation);
            assert_eq!(editor.stage, NativeEditorStage::Fields);
            assert_eq!(editor.draft.values[0], "new untouched");
            assert_eq!(app.status_message.as_deref(), Some("other editor status"));
            assert_eq!(
                app.router_db
                    .as_ref()
                    .unwrap()
                    .load_config_history(Uuid::nil())
                    .unwrap()
                    .len(),
                1
            );
            let history = app
                .router_db
                .as_ref()
                .unwrap()
                .load_config_history(Uuid::nil())
                .unwrap();
            assert!(history[0].description.contains("original lab.invalid:22"),"history must label the ORIGINAL endpoint rather than imply the new registration changed");
            if endpoint_change {
                assert!(rx.try_recv().is_err());
            } else {
                assert!(
                    matches!(rx.try_recv().unwrap(),FetchRequest::RefreshMikroTik{router_id,..} if router_id==Uuid::nil())
                );
            }
        }
    }
}
