use super::{App, ConfirmAction, ProjectEditorMode};
use crate::router::Project;
use uuid::Uuid;

impl App {
    // ── Project management ────────────────────────────────────────────────────

    /// Rebuild `self.routers` from visible set and reset selection.
    pub fn apply_project_filter(&mut self) {
        let ids: Option<Vec<Uuid>> = self.active_project.and_then(|pid| {
            self.projects
                .iter()
                .find(|p| p.id == pid)
                .map(|p| p.router_ids.clone())
        });
        self.routers = match ids {
            Some(ref ids) => self
                .all_routers
                .iter()
                .filter(|r| ids.contains(&r.id))
                .cloned()
                .collect(),
            None => self.all_routers.clone(),
        };
        // Reset selection
        if self.routers.is_empty() {
            self.router_list_state.select(None);
            self.editor_list_state.select(None);
        } else {
            self.router_list_state.select(Some(0));
            self.editor_list_state.select(Some(0));
        }
        self.reload_selected_router();
    }

    /// Active project name for display.
    pub fn active_project_name(&self) -> Option<&str> {
        self.active_project.and_then(|pid| {
            self.projects
                .iter()
                .find(|p| p.id == pid)
                .map(|p| p.name.as_str())
        })
    }

    pub fn select_project(&mut self, idx: Option<usize>) {
        match idx {
            Some(i) => {
                if let Some(proj) = self.projects.get(i) {
                    self.active_project = Some(proj.id);
                    let name = proj.name.clone();
                    self.apply_project_filter();
                    self.log(format!("Switched to project '{name}'"));
                    self.set_status(format!("Project: {name}"));
                }
            }
            None => {
                self.active_project = None;
                self.apply_project_filter();
                self.log("Showing all routers");
                self.set_status("All routers");
            }
        }
    }

    pub fn project_add(&mut self) {
        self.project_editor_mode = ProjectEditorMode::EditName;
        self.project_editor_buf = String::new();
        self.set_status("Enter project name — Enter: save  Esc: cancel");
    }

    pub fn project_save_name(&mut self) {
        let name = self.project_editor_buf.trim().to_string();
        if name.is_empty() {
            self.project_editor_mode = ProjectEditorMode::Browse;
            return;
        }
        let proj = Project::new(name.clone());
        self.db_upsert_project(&proj);
        self.projects.push(proj);
        let idx = self.projects.len() - 1;
        self.project_list_state.select(Some(idx));
        self.project_editor_mode = ProjectEditorMode::Browse;
        self.project_editor_buf.clear();
        self.log(format!("Project '{name}' created"));
        self.set_status(format!("Project '{name}' created"));
    }

    pub fn project_request_delete(&mut self) {
        if let Some(idx) = self.project_list_state.selected() {
            if idx < self.projects.len() {
                self.confirm_action = Some(ConfirmAction::DeleteProject(self.projects[idx].id));
            }
        }
    }

    pub fn project_delete_selected(&mut self) {
        if let Some(idx) = self.project_list_state.selected() {
            if idx < self.projects.len() {
                let removed = self.projects.remove(idx);
                self.db_delete_project(removed.id);
                if self.active_project == Some(removed.id) {
                    self.active_project = None;
                    self.apply_project_filter();
                }
                let msg = format!("Project '{}' deleted", removed.name);
                self.log(msg.clone());
                self.set_status(msg);
                if self.projects.is_empty() {
                    self.project_list_state.select(None);
                } else {
                    self.project_list_state
                        .select(Some(idx.min(self.projects.len() - 1)));
                }
            }
        }
    }

    pub fn confirm_action_execute(&mut self) {
        if let Some(action) = self.confirm_action.take() {
            match action {
                ConfirmAction::DeleteRouter(_) => self.editor_delete_selected(),
                ConfirmAction::DeleteProject(_) => self.project_delete_selected(),
            }
        }
    }

    pub fn confirm_action_cancel(&mut self) {
        self.confirm_action = None;
    }

    pub fn project_enter_toggle_routers(&mut self) {
        if self.project_list_state.selected().is_some() {
            self.project_editor_mode = ProjectEditorMode::ToggleRouters;
            if !self.all_routers.is_empty() {
                self.project_toggle_state.select(Some(0));
            }
            self.set_status("Space: toggle router  Enter/Esc: done");
        }
    }

    pub fn project_toggle_router(&mut self) {
        let proj_idx = match self.project_list_state.selected() {
            Some(i) => i,
            None => return,
        };
        let router_idx = match self.project_toggle_state.selected() {
            Some(i) => i,
            None => return,
        };
        let rid = match self.all_routers.get(router_idx) {
            Some(r) => r.id,
            None => return,
        };
        let proj = match self.projects.get_mut(proj_idx) {
            Some(p) => p,
            None => return,
        };
        if let Some(pos) = proj.router_ids.iter().position(|&id| id == rid) {
            proj.router_ids.remove(pos);
        } else {
            proj.router_ids.push(rid);
        }
        let proj_snapshot = proj.clone();
        self.db_upsert_project(&proj_snapshot);
        // Re-apply filter if this is the active project
        if self.active_project == Some(proj_snapshot.id) {
            let ids = proj_snapshot.router_ids;
            self.routers = self
                .all_routers
                .iter()
                .filter(|r| ids.contains(&r.id))
                .cloned()
                .collect();
            if self.routers.is_empty() {
                self.router_list_state.select(None);
            } else if self
                .router_list_state
                .selected()
                .map(|i| i >= self.routers.len())
                .unwrap_or(true)
            {
                self.router_list_state.select(Some(0));
            }
        }
    }

    pub(crate) fn db_upsert_project(&self, p: &Project) {
        if let Some(db) = self.router_db.as_ref() {
            if let Err(e) = db.upsert_project(p) {
                eprintln!("warn: db upsert_project failed for '{}': {e}", p.name);
            }
        }
    }

    fn db_delete_project(&self, id: Uuid) {
        if let Some(db) = self.router_db.as_ref() {
            if let Err(e) = db.delete_project(id) {
                eprintln!("warn: db delete_project failed: {e}");
            }
        }
    }
}
