use super::{
    apply_buf_to_draft, editor_field_value, App, ConfirmAction, EditorMode, EDITOR_NFIELDS,
};
use crate::router::RouterConfig;
use uuid::Uuid;

impl App {
    // ── Router editor ─────────────────────────────────────────────────────────

    pub fn editor_start_add(&mut self) {
        self.editor_draft = Some(RouterConfig::default());
        self.editor_field = 0;
        self.editor_buf = String::new();
        self.editor_mode = EditorMode::EditField;
        self.set_status("New router — Tab/Enter: next field  Shift-Tab: prev  Esc: cancel");
    }

    pub fn editor_start_edit(&mut self) {
        if let Some(idx) = self.editor_list_state.selected() {
            if let Some(router) = self.routers.get(idx) {
                let draft = router.clone();
                self.editor_buf = editor_field_value(&draft, 0);
                self.editor_field = 0;
                self.editor_draft = Some(draft);
                self.editor_mode = EditorMode::EditField;
                self.set_status(
                    "Editing router — Tab/Enter: next field  Shift-Tab: prev  Esc: cancel",
                );
            }
        }
    }

    pub fn editor_request_delete(&mut self) {
        if let Some(idx) = self.editor_list_state.selected() {
            if idx < self.routers.len() {
                self.confirm_action = Some(ConfirmAction::DeleteRouter(self.routers[idx].id));
            }
        }
    }

    pub fn editor_delete_selected(&mut self) {
        if let Some(idx) = self.editor_list_state.selected() {
            if idx < self.routers.len() {
                let removed = self.routers.remove(idx);
                self.router_status.remove(&removed.id);
                if let Some(pos) = self.all_routers.iter().position(|r| r.id == removed.id) {
                    self.all_routers.remove(pos);
                }
                self.db_delete(removed.id);
                let msg = format!("Router '{}' removed", removed.name);
                self.conn_log(msg);
                if self.routers.is_empty() {
                    self.editor_list_state.select(None);
                } else {
                    self.editor_list_state
                        .select(Some(idx.min(self.routers.len() - 1)));
                }
                self.set_status(format!("Deleted '{}' — saved to DB", removed.name));
            }
        }
    }

    pub fn editor_save_config(&mut self) {
        // No-op: all mutations are now auto-persisted. Keep the method so
        // existing key-bindings compile without changes.
        self.set_status("All changes are auto-saved to the encrypted DB");
    }

    pub fn editor_commit_and_advance(&mut self) {
        if let Some(draft) = self.editor_draft.as_mut() {
            apply_buf_to_draft(draft, self.editor_field, &self.editor_buf.clone());
        }
        if self.editor_field + 1 < EDITOR_NFIELDS {
            self.editor_field += 1;
            if let Some(draft) = self.editor_draft.as_ref() {
                self.editor_buf = editor_field_value(draft, self.editor_field);
            }
        } else {
            self.editor_persist_draft();
        }
    }

    pub fn editor_commit_and_retreat(&mut self) {
        if let Some(draft) = self.editor_draft.as_mut() {
            apply_buf_to_draft(draft, self.editor_field, &self.editor_buf.clone());
        }
        if self.editor_field > 0 {
            self.editor_field -= 1;
            if let Some(draft) = self.editor_draft.as_ref() {
                self.editor_buf = editor_field_value(draft, self.editor_field);
            }
        }
    }

    fn editor_persist_draft(&mut self) {
        if let Some(draft) = self.editor_draft.take() {
            let name = draft.name.clone();
            if let Some(pos) = self.routers.iter().position(|r| r.id == draft.id) {
                self.routers[pos] = draft.clone();
                // Also update in all_routers
                if let Some(apos) = self.all_routers.iter().position(|r| r.id == draft.id) {
                    self.all_routers[apos] = draft.clone();
                }
                self.conn_log(format!("Router '{name}' updated"));
            } else {
                self.routers.push(draft.clone());
                self.all_routers.push(draft.clone());
                let new_idx = self.routers.len() - 1;
                self.editor_list_state.select(Some(new_idx));
                if self.router_list_state.selected().is_none() {
                    self.router_list_state.select(Some(0));
                }
                self.conn_log(format!("Router '{name}' added"));
            }
            // Auto-persist to encrypted DB immediately
            self.db_upsert(&draft);
            self.editor_mode = EditorMode::Browse;
            self.editor_buf.clear();
            self.set_status(format!("'{name}' saved to DB ✓"));
        }
    }

    // ── DB write helpers ──────────────────────────────────────────────────────

    fn db_upsert(&self, r: &RouterConfig) {
        if let Some(db) = self.router_db.as_ref() {
            if let Err(e) = db.upsert(r) {
                eprintln!("warn: db upsert failed for '{}': {e}", r.name);
            }
        }
    }

    fn db_delete(&self, id: Uuid) {
        if let Some(db) = self.router_db.as_ref() {
            if let Err(e) = db.delete(id) {
                eprintln!("warn: db delete failed: {e}");
            }
        }
    }
}
