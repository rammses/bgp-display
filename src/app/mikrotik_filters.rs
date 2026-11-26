//! Native filter drafts are isolated from the cache and the neighbor editor.
use super::{App, NativeConfigTarget, NativeEditorStage};
use crate::events::FetchRequest;
use crate::router::mikrotik::filter::{
    changed_properties, filter_eligibility, known_filter_consumers, rule_draft, simulate_rule_edit,
};
use crate::router::mikrotik::*;
use crate::router::RouterVendor;
use crate::ssh::NativeRegistration;
use anyhow::{ensure, Context, Result};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeFilterField {
    Text,
    Comment,
}

pub struct NativeFilterEditorState {
    pub base: Arc<MikroTikSnapshot>,
    pub router_id: Uuid,
    pub instance: String,
    pub generation: Uuid,
    pub registration: NativeRegistration,
    pub operation: Uuid,
    pub chain: String,
    pub rules: Vec<NativeRecord>,
    pub edits: Vec<NativeRuleEdit>,
    pub selected: usize,
    pub text: String,
    pub comment: String,
    pub disabled: bool,
    pub raw_field: Option<NativeFilterField>,
    pub editing_id: Option<String>,
    pub cursor: usize,
    pub scroll: u16,
    pub(crate) raw_viewport: Option<(u16, u16)>,
    pub(crate) raw_follow_cursor: bool,
    pub shared_acknowledged: bool,
    pub read_only_reason: Option<String>,
    pub consumers: Vec<String>,
    pub stage: NativeEditorStage,
    pub preview: Option<NativePreview>,
    pub error: Option<String>,
    pub receipt: Option<NativeReceipt>,
}
impl std::fmt::Debug for NativeFilterEditorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeFilterEditorState")
            .field("stage", &self.stage)
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

// Rebuild a minimal typed edit list from the local ordered records. New rows are
// local-only identities, never numeric RouterOS rows or public insertion IDs.
// Enabling patches precede insertions; disabling/deleting follows insertions.
// The real validator still checks EVERY resulting intermediate state.
fn edits_for_rules(
    base: &MikroTikSnapshot,
    chain: &str,
    desired: &[NativeRecord],
) -> Result<Vec<NativeRuleEdit>> {
    let original = base
        .inventory
        .rules
        .iter()
        .filter(|r| r.props.get("chain").and_then(Value::as_str) == Some(chain))
        .cloned()
        .collect::<Vec<_>>();
    let observed = original
        .iter()
        .map(|r| r.id.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        desired
            .iter()
            .map(|r| r.id.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            == desired.len(),
        "duplicate local rule identity"
    );
    ensure!(
        desired.iter().all(
            |r| r.props.get("chain").and_then(Value::as_str) == Some(chain)
                && (observed.contains(r.id.as_str()) || r.id.starts_with("@local/"))
        ),
        "invalid local rule source"
    );
    let mut working = original.clone();
    let mut edits = Vec::new();
    // Positive enabled state can make subsequent live operations safe.
    for row in desired.iter().filter(|r| observed.contains(r.id.as_str())) {
        let old = original
            .iter()
            .find(|r| r.id == row.id)
            .context("local source missing")?;
        if rule_draft(old)?.disabled && !rule_draft(row)?.disabled {
            let edit = NativeRuleEdit::Update {
                id: row.id.clone(),
                rule: rule_draft(row)?,
            };
            working = simulate_rule_edit(&working, &edit)?;
            edits.push(edit);
        }
    }
    let ordered = desired
        .iter()
        .filter(|r| observed.contains(r.id.as_str()))
        .map(|r| r.id.as_str())
        .collect::<Vec<_>>();
    let retained = ordered.iter().copied().collect::<BTreeSet<_>>();
    let mut anchor: Option<String> = None;
    for id in ordered.iter().rev() {
        let projected = working
            .iter()
            .filter(|r| retained.contains(r.id.as_str()))
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>();
        let pos = projected
            .iter()
            .position(|v| v == id)
            .context("local move target missing")?;
        if projected.get(pos + 1).copied() != anchor.as_deref() {
            let edit = NativeRuleEdit::Move {
                id: (*id).into(),
                before: anchor.clone(),
            };
            working = simulate_rule_edit(&working, &edit)?;
            edits.push(edit);
        }
        anchor = Some((*id).into());
    }
    for (index, row) in desired
        .iter()
        .enumerate()
        .filter(|(_, r)| !observed.contains(r.id.as_str()))
    {
        let before = desired[index + 1..]
            .iter()
            .find(|r| observed.contains(r.id.as_str()))
            .map(|r| r.id.clone());
        edits.push(NativeRuleEdit::Insert {
            before,
            rule: rule_draft(row)?,
        });
    }
    for row in desired.iter().filter(|r| observed.contains(r.id.as_str())) {
        let current = working
            .iter()
            .find(|r| r.id == row.id)
            .context("local source missing")?;
        let draft = rule_draft(row)?;
        if !changed_properties(current, &draft).is_empty() {
            let edit = NativeRuleEdit::Update {
                id: row.id.clone(),
                rule: draft,
            };
            working = simulate_rule_edit(&working, &edit)?;
            edits.push(edit);
        }
    }
    for row in original
        .iter()
        .filter(|r| !retained.contains(r.id.as_str()))
    {
        edits.push(NativeRuleEdit::Delete { id: row.id.clone() });
    }
    if !edits.is_empty() {
        validate_filter_change(
            base,
            &NativeFilterChange {
                chain: chain.into(),
                edits: edits.clone(),
                shared_acknowledged: true,
            },
        )?;
    }
    Ok(edits)
}

impl NativeFilterEditorState {
    fn replace_local_rules(&mut self, rules: Vec<NativeRecord>) -> Result<()> {
        let edits = edits_for_rules(&self.base, &self.chain, &rules)?;
        self.rules = rules;
        self.edits = edits;
        self.preview = None;
        self.error = None;
        self.scroll = 0;
        self.selected = self.selected.min(self.rules.len().saturating_sub(1));
        Ok(())
    }
    fn start_raw(&mut self, field: NativeFilterField, adding: bool) -> Result<()> {
        ensure!(self.read_only_reason.is_none(), "native chain is read-only");
        if adding {
            self.editing_id = None;
            self.text.clear();
            self.comment.clear();
            self.disabled = true;
        } else {
            let row = self
                .rules
                .get(self.selected)
                .context("select a native rule")?;
            let draft = rule_draft(row)?;
            self.editing_id = Some(row.id.clone());
            self.text = draft.text;
            self.comment = draft.comment;
            self.disabled = draft.disabled;
        }
        self.cursor = match field {
            NativeFilterField::Text => self.text.len(),
            NativeFilterField::Comment => self.comment.len(),
        };
        self.raw_field = Some(field);
        self.scroll = 0;
        self.raw_viewport = None;
        self.raw_follow_cursor = true;
        self.error = None;
        Ok(())
    }
    fn save_raw(&mut self) -> Result<()> {
        let draft = NativeRuleDraft {
            text: self.text.clone(),
            comment: self.comment.clone(),
            disabled: self.disabled,
        };
        ensure!(
            !draft.text.trim().is_empty(),
            "native rule text cannot be empty"
        );
        let mut rules = self.rules.clone();
        if let Some(id) = &self.editing_id {
            let row = rules
                .iter_mut()
                .find(|r| r.id == *id)
                .context("local rule source missing")?;
            row.props.extend(changed_properties(row, &draft));
        } else {
            let mut props = crate::router::mikrotik::filter::draft_properties(&draft);
            props.insert("chain".into(), json!(self.chain));
            rules.insert(
                self.selected.min(rules.len()),
                NativeRecord {
                    id: format!("@local/{}", Uuid::new_v4()),
                    props,
                },
            );
        }
        self.replace_local_rules(rules)?;
        self.cancel_raw();
        Ok(())
    }
    fn cancel_raw(&mut self) {
        self.raw_field = None;
        self.editing_id = None;
        self.text.clear();
        self.comment.clear();
        self.cursor = 0;
        self.scroll = 0;
    }
    fn raw_key(&mut self, key: KeyEvent) -> Result<()> {
        if key.code == KeyCode::Esc {
            self.cancel_raw();
            return Ok(());
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return if key.code == KeyCode::Char('s') {
                self.save_raw()
            } else {
                Ok(())
            };
        }
        let text = match self.raw_field {
            Some(NativeFilterField::Text) => &mut self.text,
            Some(NativeFilterField::Comment) => &mut self.comment,
            None => return Ok(()),
        };
        self.cursor = self.cursor.min(text.len());
        match key.code {
            KeyCode::Char(c) => {
                text.insert(self.cursor, c);
                self.cursor += c.len_utf8();
            }
            KeyCode::Enter => {
                text.insert(self.cursor, '\n');
                self.cursor += 1;
            }
            KeyCode::Backspace => {
                if let Some((pos, _)) = text[..self.cursor].char_indices().next_back() {
                    text.replace_range(pos..self.cursor, "");
                    self.cursor = pos;
                }
            }
            KeyCode::Delete => {
                if let Some(c) = text[self.cursor..].chars().next() {
                    text.replace_range(self.cursor..self.cursor + c.len_utf8(), "");
                }
            }
            KeyCode::Left => {
                self.cursor = text[..self.cursor]
                    .char_indices()
                    .next_back()
                    .map_or(0, |(i, _)| i);
            }
            KeyCode::Right => {
                self.cursor += text[self.cursor..].chars().next().map_or(0, char::len_utf8);
            }
            KeyCode::Home => self.cursor = text[..self.cursor].rfind('\n').map_or(0, |i| i + 1),
            KeyCode::End => {
                self.cursor += text[self.cursor..]
                    .find('\n')
                    .unwrap_or(text.len() - self.cursor)
            }
            KeyCode::Up => {
                let start = text[..self.cursor].rfind('\n').map_or(0, |i| i + 1);
                if start > 0 {
                    let previous = text[..start - 1].rfind('\n').map_or(0, |i| i + 1);
                    let column = text[start..self.cursor].chars().count();
                    self.cursor = text[previous..start - 1]
                        .char_indices()
                        .nth(column)
                        .map_or(start - 1, |(i, _)| previous + i);
                }
            }
            KeyCode::Down => {
                let start = text[..self.cursor].rfind('\n').map_or(0, |i| i + 1);
                let column = text[start..self.cursor].chars().count();
                if let Some(end) = text[self.cursor..].find('\n') {
                    let next = self.cursor + end + 1;
                    let end = text[next..].find('\n').map_or(text.len(), |n| next + n);
                    self.cursor = text[next..end]
                        .char_indices()
                        .nth(column)
                        .map_or(end, |(i, _)| next + i);
                }
            }
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(5);
                self.raw_follow_cursor = false;
                return Ok(());
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(5);
                self.raw_follow_cursor = false;
                return Ok(());
            }
            _ => return Ok(()),
        }
        // Visibility is resolved against the actual rendered raw area, not an
        // assumed number of rows. Explicit page scrolling opts out until input.
        self.raw_follow_cursor = true;
        Ok(())
    }
}

impl App {
    pub(crate) fn open_native_filter(&mut self) {
        if self.native_editor.is_some() || self.native_filter_editor.is_some() {
            return;
        }
        let opened = (|| -> Result<NativeFilterEditorState> {
            let router = self.selected_router().context("select a native router")?;
            let chain = match self.displayed_native_target().map(|(_, t)| t) {
                Some(NativeConfigTarget::Chain(c)) => c.clone(),
                _ => anyhow::bail!("select native chain metadata"),
            };
            let base = Arc::clone(
                &self
                    .native_view
                    .as_ref()
                    .context("refresh native source")?
                    .snapshot,
            );
            ensure!(
                router.vendor == RouterVendor::MikroTik
                    && router.id == base.router_id
                    && router.mikrotik_instance.as_deref() == Some(base.instance.as_str())
                    && router.hostname == base.registration.endpoint.hostname
                    && router.username == base.registration.endpoint.username
                    && router.ssh_port == base.registration.endpoint.ssh_port,
                "displayed registration or scope changed; refresh"
            );
            let read_only_reason = filter_eligibility(&base, &chain)
                .err()
                .map(|e| e.to_string())
                .or_else(|| {
                    (!config_guard(&base.inventory, &base.instance).is_ok_and(|g| g == base.guard))
                        .then(|| "source guard is not actionable; refresh".into())
                });
            Ok(NativeFilterEditorState {
                router_id: base.router_id,
                instance: base.instance.clone(),
                generation: base.generation,
                registration: base.registration.clone(),
                operation: Uuid::new_v4(),
                chain: chain.clone(),
                rules: base
                    .inventory
                    .rules
                    .iter()
                    .filter(|r| {
                        r.props.get("chain").and_then(Value::as_str) == Some(chain.as_str())
                    })
                    .cloned()
                    .collect(),
                consumers: known_filter_consumers(&base, &chain),
                base,
                edits: vec![],
                selected: 0,
                text: String::new(),
                comment: String::new(),
                disabled: true,
                raw_field: None,
                editing_id: None,
                cursor: 0,
                scroll: 0,
                raw_viewport: None,
                raw_follow_cursor: true,
                shared_acknowledged: false,
                read_only_reason,
                stage: NativeEditorStage::Fields,
                preview: None,
                error: None,
                receipt: None,
            })
        })();
        match opened {
            Ok(editor) => self.native_filter_editor = Some(editor),
            Err(error) => self.set_status(format!("Native filter unavailable: {error}")),
        }
    }
    fn review_native_filter(&mut self) {
        let Some(e) = self.native_filter_editor.as_mut() else {
            return;
        };
        if e.read_only_reason.is_some()
            || e.raw_field.is_some()
            || e.stage != NativeEditorStage::Fields
        {
            return;
        }
        let intent = NativeIntent::Filter(NativeFilterChange {
            chain: e.chain.clone(),
            edits: e.edits.clone(),
            shared_acknowledged: e.shared_acknowledged,
        });
        match preview_native(&e.base,intent,e.operation) {
            Ok(p)=>{e.preview=Some(p);e.stage=NativeEditorStage::Review;e.scroll=0;e.error=None;},
            Err(_)=>e.error=Some("Cannot Review: check changes, shared acknowledgment (s), enabled-rule survival, scope, anchors and 32 KiB byte budget. No command sent.".into()),
        }
    }
    fn confirm_native_filter(&mut self) {
        let Some(e) = self
            .native_filter_editor
            .as_ref()
            .filter(|e| e.stage == NativeEditorStage::Review)
        else {
            return;
        };
        let current = self.selected_router().is_some_and(|r| {
            r.vendor == RouterVendor::MikroTik
                && r.id == e.router_id
                && r.hostname == e.registration.endpoint.hostname
                && r.ssh_port == e.registration.endpoint.ssh_port
                && r.username == e.registration.endpoint.username
                && r.mikrotik_instance.as_deref() == Some(e.instance.as_str())
        });
        if !current || e.base.generation != e.generation || e.base.registration != e.registration {
            self.native_filter_editor = None;
            self.set_status(
                "Native filter context changed; review canceled. Refresh before editing.",
            );
            return;
        }
        let Some(e) = self.native_filter_editor.as_mut() else {
            return;
        };
        let Some(preview) = e.preview.take() else {
            return;
        };
        e.stage = NativeEditorStage::Applying;
        e.cancel_raw();
        let failure = rejected_receipt(&preview);
        if self
            .fetch_tx
            .as_ref()
            .is_none_or(|tx| tx.send(FetchRequest::ApplyMikroTik(preview)).is_err())
        {
            self.handle_native_receipt(failure);
        }
    }
    pub(crate) fn handle_native_filter_key(&mut self, key: KeyEvent) {
        let Some(e) = self.native_filter_editor.as_mut() else {
            return;
        };
        if e.raw_field.is_some() {
            if let Err(_error) = e.raw_key(key) {
                e.error=Some("Local save rejected: keep at least one enabled rule and valid native text/identity/scope. Full raw buffer retained; Esc cancels field.".into());
            }
            return;
        }
        match key.code {
            KeyCode::Esc | KeyCode::BackTab if e.stage == NativeEditorStage::Review => {
                e.preview = None;
                e.stage = NativeEditorStage::Fields;
                e.scroll = 0;
            }
            KeyCode::Esc => {
                let applying = e.stage == NativeEditorStage::Applying;
                self.native_filter_editor = None;
                if applying {
                    self.set_status("Filter editor closed; a launched remote operation may continue. Its originating receipt will still be stored.");
                }
            }
            KeyCode::Enter if e.stage == NativeEditorStage::Review => self.confirm_native_filter(),
            KeyCode::Enter if e.stage == NativeEditorStage::Result => {
                self.native_filter_editor = None
            }
            KeyCode::PageDown => e.scroll = e.scroll.saturating_add(5),
            KeyCode::PageUp => e.scroll = e.scroll.saturating_sub(5),
            KeyCode::Home => e.scroll = 0,
            _ if e.stage != NativeEditorStage::Fields => {}
            KeyCode::Up | KeyCode::Char('k') => {
                e.selected = e.selected.saturating_sub(1);
                e.scroll = 0;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                e.selected = (e.selected + 1).min(e.rules.len().saturating_sub(1));
                e.scroll = 0;
            }
            _ if e.read_only_reason.is_some() => {}
            KeyCode::Enter | KeyCode::Char('r') => self.review_native_filter(),
            KeyCode::Char('s') => {
                e.shared_acknowledged = !e.shared_acknowledged;
                e.preview = None;
                e.error = None;
            }
            KeyCode::Char('a') | KeyCode::Char('e') | KeyCode::Char('c') => {
                let field = if key.code == KeyCode::Char('c') {
                    NativeFilterField::Comment
                } else {
                    NativeFilterField::Text
                };
                if e.start_raw(field, key.code == KeyCode::Char('a')).is_err() {
                    e.error = Some("Select an editable native rule".into());
                }
            }
            KeyCode::Char('d') | KeyCode::Char(' ') | KeyCode::Char('U') | KeyCode::Char('D') => {
                let mut rules = e.rules.clone();
                let selected = e.selected;
                let result = (|| -> Result<()> {
                    ensure!(selected < rules.len(), "select a rule");
                    match key.code {
                        KeyCode::Char('d') => {
                            rules.remove(selected);
                        }
                        KeyCode::Char(' ') => {
                            let state = rule_draft(&rules[selected])?.disabled;
                            rules[selected]
                                .props
                                .insert("disabled".into(), json!(!state));
                        }
                        KeyCode::Char('U') if selected > 0 => rules.swap(selected, selected - 1),
                        KeyCode::Char('D') if selected + 1 < rules.len() => {
                            rules.swap(selected, selected + 1)
                        }
                        _ => return Ok(()),
                    }
                    e.replace_local_rules(rules)?;
                    if key.code == KeyCode::Char('U') {
                        e.selected = selected.saturating_sub(1);
                    }
                    if key.code == KeyCode::Char('D') {
                        e.selected = (selected + 1).min(e.rules.len().saturating_sub(1));
                    }
                    Ok(())
                })();
                if result.is_err() {
                    e.error=Some("Local change rejected: every intermediate state must retain an enabled rule; scope/targets must remain eligible. No command sent.".into());
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::app::{handle_key, ActiveTab, NativeConfigTarget};
    use crate::config::AppConfig;
    use crate::db::RouterDb;
    use crate::events::FetchRequest;
    use crate::router::mikrotik::test_support::*;
    use crate::router::{RouterConfig, RouterVendor};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    pub(crate) fn filter_app(
        snapshot: Option<MikroTikSnapshot>,
    ) -> (App, tokio::sync::mpsc::UnboundedReceiver<FetchRequest>) {
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
        let mut s = snapshot.unwrap_or_else(documented_snapshot);
        s.request = request;
        app.handle_native_data(Uuid::nil(), request, NativeDiscovery::Snapshot(s));
        app.current_tab = ActiveTab::Config;
        let index = app
            .native_view
            .as_ref()
            .unwrap()
            .config_targets
            .iter()
            .position(|t| matches!(t,Some(NativeConfigTarget::Chain(c)) if c=="blue-in"))
            .unwrap();
        app.config_list_state.select(Some(index));
        key(&mut app, KeyCode::Char('e'));
        (app, rx)
    }
    pub(crate) fn key(app: &mut App, code: KeyCode) {
        handle_key(app, KeyEvent::new(code, KeyModifiers::NONE));
    }
    fn save(app: &mut App) {
        handle_key(
            app,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
        );
    }

    #[test]
    fn mikrotik_filter_editor_raw_enter_newline_ctrl_s_local_save_and_esc_cancel() {
        let (mut app, mut rx) = filter_app(None);
        assert!(
            app.native_filter_editor.is_some(),
            "Config e on chain metadata must open native filter editor"
        );
        let base = Arc::clone(&app.native_filter_editor.as_ref().unwrap().base);
        key(&mut app, KeyCode::Char('e'));
        key(&mut app, KeyCode::End);
        key(&mut app, KeyCode::Enter);
        for c in "α\"\\$".chars() {
            key(&mut app, KeyCode::Char(c));
        }
        save(&mut app);
        let e = app.native_filter_editor.as_ref().unwrap();
        assert_eq!(e.rules[0].props["rule"], "reject;\nα\"\\$");
        assert_eq!(base.inventory.rules[0].props["rule"], "reject;");
        assert!(e.raw_field.is_none() && e.edits.len() == 1);
        assert!(rx.try_recv().is_err());
        key(&mut app, KeyCode::Char('c'));
        key(&mut app, KeyCode::Char('X'));
        key(&mut app, KeyCode::Esc);
        assert!(!app.native_filter_editor.as_ref().unwrap().rules[0]
            .props
            .contains_key("comment"));
        assert!(!format!("{:?}", app.native_filter_editor).contains("reject;"));
    }

    #[test]
    fn mikrotik_filter_editor_ack_review_second_enter_once_and_back_clears_preview() {
        let (mut app, mut rx) = filter_app(None);
        key(&mut app, KeyCode::Char('e'));
        key(&mut app, KeyCode::Char(' '));
        save(&mut app);
        key(&mut app, KeyCode::Enter);
        assert_eq!(
            app.native_filter_editor.as_ref().unwrap().stage,
            NativeEditorStage::Fields
        );
        assert!(rx.try_recv().is_err());
        key(&mut app, KeyCode::Char('s'));
        key(&mut app, KeyCode::Enter);
        assert_eq!(
            app.native_filter_editor.as_ref().unwrap().stage,
            NativeEditorStage::Review
        );
        key(&mut app, KeyCode::BackTab);
        assert!(app.native_filter_editor.as_ref().unwrap().preview.is_none());
        assert!(rx.try_recv().is_err());
        key(&mut app, KeyCode::Enter);
        key(&mut app, KeyCode::Enter);
        key(&mut app, KeyCode::Enter);
        let p = match rx.try_recv().unwrap() {
            FetchRequest::ApplyMikroTik(p) => p,
            _ => panic!(),
        };
        assert!(
            matches!(&p.intent,NativeIntent::Filter(c) if c.shared_acknowledged && c.chain=="blue-in")
        );
        assert!(rx.try_recv().is_err());
        assert!(app.desired_neighbors.is_empty());
    }

    #[test]
    fn mikrotik_filter_editor_background_refresh_never_rebases_and_invalidation_cancels() {
        let (mut app, _rx) = filter_app(None);
        let base = Arc::clone(&app.native_filter_editor.as_ref().unwrap().base);
        key(&mut app, KeyCode::Char('e'));
        key(&mut app, KeyCode::Char('X'));
        app.request_native_refresh(Uuid::nil());
        let mut newer = documented_snapshot();
        newer.request = app.native_cache[&Uuid::nil()].latest_request;
        app.handle_native_data(Uuid::nil(), newer.request, NativeDiscovery::Snapshot(newer));
        let e = app.native_filter_editor.as_ref().unwrap();
        assert!(Arc::ptr_eq(&base, &e.base));
        assert!(e.text.contains('X'));
        app.invalidate_native(Uuid::nil());
        assert!(app.native_filter_editor.is_none());
    }

    #[test]
    fn mikrotik_filter_editor_last_enabled_and_overbudget_existing_are_read_only() {
        let (mut app, _) = filter_app(None);
        key(&mut app, KeyCode::Char('d'));
        key(&mut app, KeyCode::Char(' '));
        let e = app.native_filter_editor.as_ref().unwrap();
        assert_eq!(e.rules.len(), 1);
        assert!(e.edits.is_empty());
        let mut s = documented_snapshot();
        let raw = "α".repeat(20000);
        s.inventory.rules[0]
            .props
            .insert("rule".into(), serde_json::json!(raw));
        s.guard = config_guard(&s.inventory, "blue").unwrap();
        let (mut app, mut rx) = filter_app(Some(s));
        assert!(app
            .native_filter_editor
            .as_ref()
            .unwrap()
            .read_only_reason
            .is_some());
        key(&mut app, KeyCode::Char('e'));
        key(&mut app, KeyCode::Char('d'));
        key(&mut app, KeyCode::Enter);
        let e = app.native_filter_editor.as_ref().unwrap();
        assert_eq!(e.rules[0].props["rule"], raw);
        assert!(e.edits.is_empty());
        assert!(rx.try_recv().is_err());
    }

    fn applied_request(
        app: &mut App,
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<FetchRequest>,
    ) -> NativePreview {
        key(app, KeyCode::Char('e'));
        key(app, KeyCode::Char(' '));
        save(app);
        key(app, KeyCode::Char('s'));
        key(app, KeyCode::Enter);
        key(app, KeyCode::Enter);
        match rx.try_recv().unwrap() {
            FetchRequest::ApplyMikroTik(p) => p,
            _ => panic!(),
        }
    }
    fn receipt(p: NativePreview) -> NativeReceipt {
        NativeReceipt{router_id:p.router_id,operation:p.operation,instance:p.instance,registration:p.registration,
            outcome:NativeOutcome::Indeterminate,verified_steps:vec!["Insert disabled native rule; observed rule id=\"*AB\"".into()],
            uncertain_steps:vec!["Position exact native rule".into()],unapplied_steps:vec![],summary:"Target filter chain=\"blue-in\"; Action: Insert; launched but unverified; no replay".into()}
    }
    #[test]
    fn mikrotik_filter_receipt_correlates_result_and_nonreplayable_encrypted_history_once() {
        let (mut app, mut rx) = filter_app(None);
        let p = applied_request(&mut app, &mut rx);
        let r = receipt(p);
        app.handle_native_receipt(r.clone());
        app.handle_native_receipt(r.clone());
        let e = app.native_filter_editor.as_ref().unwrap();
        assert_eq!(e.stage, NativeEditorStage::Result);
        assert!(e.preview.is_none());
        assert_eq!(e.receipt.as_ref().unwrap(), &r);
        let history = app
            .router_db
            .as_ref()
            .unwrap()
            .load_config_history(Uuid::nil())
            .unwrap();
        assert_eq!(history.len(), 1);
        assert!(!history[0].is_replayable());
        assert!(history[0].rollback.is_empty());
        assert!(app.desired_neighbors.is_empty());
    }

    #[test]
    fn mikrotik_filter_rf5_old_result_never_overwrites_new_filter_or_neighbor_editor() {
        for next in ["filter", "neighbor"] {
            let (mut app, mut rx) = filter_app(None);
            let p = applied_request(&mut app, &mut rx);
            key(&mut app, KeyCode::Esc);
            let op = if next == "filter" {
                key(&mut app, KeyCode::Char('e'));
                key(&mut app, KeyCode::Char('e'));
                key(&mut app, KeyCode::Char('X'));
                app.native_filter_editor.as_ref().unwrap().operation
            } else {
                app.current_tab = ActiveTab::Peers;
                app.peer_table_state.select(Some(0));
                app.open_native_edit();
                let e = app.native_editor.as_mut().unwrap();
                e.draft.values[6] = "new neighbor draft".into();
                e.operation
            };
            app.set_status("new editor status");
            app.handle_native_receipt(receipt(p));
            if next == "filter" {
                let e = app.native_filter_editor.as_ref().unwrap();
                assert_eq!(e.operation, op);
                assert!(e.text.ends_with('X'));
                assert_eq!(e.stage, NativeEditorStage::Fields);
            } else {
                let e = app.native_editor.as_ref().unwrap();
                assert_eq!(e.operation, op);
                assert_eq!(e.draft.values[6], "new neighbor draft");
            }
            assert_eq!(app.status_message.as_deref(), Some("new editor status"));
            let request = app.native_cache[&Uuid::nil()].latest_request;
            app.handle_native_error(Uuid::nil(), request, "synthetic failure".into());
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
        }
    }

    #[test]
    fn mikrotik_filter_editor_add_state_delete_move_and_untouched_metadata() {
        let mut s = documented_snapshot();
        s.inventory.rules.push(record(json!({".id":"*7","chain":"blue-in","rule":"accept;","disabled":false,"comment":"untouched α\n$","future":{"opaque":[null,"0007"]}})));
        s.inventory.rules.push(record(
            json!({".id":"*8","chain":"blue-in","rule":"reject;","disabled":false}),
        ));
        s.guard = config_guard(&s.inventory, "blue").unwrap();
        let untouched = s.inventory.rules[2].clone();
        let (mut app, mut rx) = filter_app(Some(s));
        key(&mut app, KeyCode::Char('D'));
        let e = app.native_filter_editor.as_ref().unwrap();
        assert_eq!(
            e.rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["*7", "*5", "*8"]
        );
        assert_eq!(e.rules[0], untouched);
        assert!(
            matches!(&e.edits[..],[NativeRuleEdit::Move{id,before:Some(anchor)}] if id=="*5" && anchor=="*8")
        );
        key(&mut app, KeyCode::Char('a'));
        for c in "accept;".chars() {
            key(&mut app, KeyCode::Char(c));
        }
        save(&mut app);
        key(&mut app, KeyCode::Char(' ')); // requested enabled, still LOCAL
        key(&mut app, KeyCode::Down);
        key(&mut app, KeyCode::Char('d'));
        let e = app.native_filter_editor.as_ref().unwrap();
        assert_eq!(e.rules[0], untouched);
        assert_eq!(e.rules[1].props["rule"], "accept;");
        assert_eq!(e.rules[1].props["disabled"], false);
        assert!(!e.rules.iter().any(|r| r.id == "*5"));
        assert!(e
            .edits
            .iter()
            .any(|e| matches!(e,NativeRuleEdit::Insert{rule,..} if !rule.disabled)));
        assert!(e
            .edits
            .iter()
            .any(|e| matches!(e,NativeRuleEdit::Delete{id} if id=="*5")));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn mikrotik_filter_rf5_neighbor_receipt_preserves_new_filter_raw_draft_and_status() {
        let (mut app, mut rx) = filter_app(None);
        key(&mut app, KeyCode::Esc);
        app.current_tab = ActiveTab::Peers;
        app.peer_table_state.select(Some(0));
        app.open_native_edit();
        {
            let e = app.native_editor.as_mut().unwrap();
            e.draft.values[6] = "neighbor change".into();
            e.draft.changed.insert(6);
        }
        app.native_generate_preview();
        app.confirm_native();
        let p = match rx.try_recv().unwrap() {
            FetchRequest::ApplyMikroTik(p) => p,
            _ => panic!(),
        };
        key(&mut app, KeyCode::Esc);
        app.current_tab = ActiveTab::Config;
        key(&mut app, KeyCode::Char('e'));
        key(&mut app, KeyCode::Char('e'));
        key(&mut app, KeyCode::Enter);
        key(&mut app, KeyCode::Char('α'));
        let operation = app.native_filter_editor.as_ref().unwrap().operation;
        app.set_status("filter owns status");
        app.handle_native_receipt(receipt(p));
        let e = app.native_filter_editor.as_ref().unwrap();
        assert_eq!(e.operation, operation);
        assert_eq!(e.text, "reject;\nα");
        assert_eq!(e.raw_field, Some(NativeFilterField::Text));
        assert_eq!(e.stage, NativeEditorStage::Fields);
        assert_eq!(app.status_message.as_deref(), Some("filter owns status"));
    }

    #[test]
    fn mikrotik_filter_readonly_consumer_inventory_and_changed_confirm_context_are_safe() {
        let mut s = documented_snapshot();
        s.inventory.connections[0]
            .props
            .insert("routing-table".into(), json!("red"));
        s.guard = config_guard(&s.inventory, "blue").unwrap();
        let (mut app, mut rx) = filter_app(Some(s));
        let e = app.native_filter_editor.as_ref().unwrap();
        assert!(e.read_only_reason.is_some());
        assert!(
            e.consumers.iter().any(|s| s.contains("peer-a"))
                && e.consumers.iter().any(|s| s.contains("peer-b"))
        );
        key(&mut app, KeyCode::Char('a'));
        key(&mut app, KeyCode::Char('s'));
        key(&mut app, KeyCode::Enter);
        assert!(rx.try_recv().is_err());
        let (mut app, mut rx) = filter_app(None);
        key(&mut app, KeyCode::Char('e'));
        key(&mut app, KeyCode::Char(' '));
        save(&mut app);
        key(&mut app, KeyCode::Char('s'));
        key(&mut app, KeyCode::Enter);
        app.routers[0].hostname = "replacement.invalid".into();
        key(&mut app, KeyCode::Enter);
        assert!(app.native_filter_editor.is_none());
        assert!(rx.try_recv().is_err());
    }
}
