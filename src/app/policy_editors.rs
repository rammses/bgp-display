use super::types::{WizardMode, WizardStep};
use super::App;
use crate::bgp::CommunityListEntry;
use crate::router::RouterVendor;

impl App {
    // ── Route-map editor helpers ──────────────────────────────────────────────

    pub fn open_routemap_editor(&mut self, name: &str) {
        let router_id = match self.selected_router() {
            Some(r) => r.id,
            None => return,
        };
        let detail = self.routemap_cache.get(&(router_id, name.to_string()));
        let entries = detail.map(|d| d.entries.clone()).unwrap_or_default();

        self.wizard_mode = WizardMode::RouteMapEdit(name.to_string());
        self.wizard_step = WizardStep::Fields;
        self.wizard_error = None;
        self.wizard_result_msg = None;
        self.rm_editor_name = name.to_string();
        self.rm_editor_entries = entries;
        self.rm_editor_selected = 0;
        self.rm_editor_editing = false;
        self.rm_clause_mode = false;
        self.rm_clause_editing = false;
    }

    pub fn rm_editor_generate_preview(&mut self) {
        let vendor = self
            .selected_router()
            .map(|r| r.vendor.clone())
            .unwrap_or(RouterVendor::Cisco);
        self.wizard_preview = crate::router::commands::routemap_save_commands(
            &vendor,
            &self.rm_editor_name,
            &self.rm_editor_entries,
        );
        self.wizard_step = WizardStep::Review;
    }

    // ── Prefix-list editor helpers ────────────────────────────────────────────

    pub fn open_prefixlist_editor(&mut self, name: &str) {
        let router_id = match self.selected_router() {
            Some(r) => r.id,
            None => return,
        };
        let entries = self
            .prefix_list_cache
            .get(&(router_id, name.to_string()))
            .cloned()
            .or_else(|| {
                self.routemap_cache
                    .values()
                    .flat_map(|d| d.prefix_lists.get(name).cloned())
                    .next()
            })
            .unwrap_or_default();

        self.wizard_mode = WizardMode::PrefixListEdit(name.to_string());
        self.wizard_step = WizardStep::Fields;
        self.wizard_error = None;
        self.wizard_result_msg = None;
        self.pl_editor_name = name.to_string();
        self.pl_editor_entries = entries;
        self.pl_editor_selected = 0;
        self.pl_editor_editing = false;
    }

    pub fn pl_editor_generate_preview(&mut self) {
        // Validate all entries before generating commands
        for (i, entry) in self.pl_editor_entries.iter().enumerate() {
            if let Err(e) = entry.validate() {
                self.wizard_error = Some(format!("Entry {} (seq {}): {e}", i + 1, entry.seq));
                return;
            }
        }
        self.wizard_error = None;

        let vendor = self
            .selected_router()
            .map(|r| r.vendor.clone())
            .unwrap_or(RouterVendor::Cisco);
        self.wizard_preview = crate::router::commands::prefixlist_save_commands(
            &vendor,
            &self.pl_editor_name,
            &self.pl_editor_entries,
        );
        self.wizard_step = WizardStep::Review;
    }

    // ── Community-list editor helpers ─────────────────────────────────────────

    pub fn open_communitylist_editor(&mut self, name: &str) {
        let router_id = match self.selected_router() {
            Some(r) => r.id,
            None => return,
        };
        let entries: Vec<CommunityListEntry> = self
            .community_list_cache
            .get(&(router_id, name.to_string()))
            .cloned()
            .unwrap_or_else(|| {
                self.routemap_cache
                    .values()
                    .flat_map(|d| d.community_lists.get(name).cloned())
                    .next()
                    .unwrap_or_default()
                    .iter()
                    .enumerate()
                    .map(|(i, raw)| {
                        let parts: Vec<&str> = raw.splitn(2, char::is_whitespace).collect();
                        CommunityListEntry {
                            seq: ((i + 1) * 5) as u32,
                            action: parts.first().unwrap_or(&"permit").to_string(),
                            community: parts.get(1).unwrap_or(&"").to_string(),
                        }
                    })
                    .collect()
            });

        self.wizard_mode = WizardMode::CommunityListEdit(name.to_string());
        self.wizard_step = WizardStep::Fields;
        self.wizard_error = None;
        self.wizard_result_msg = None;
        self.cl_editor_name = name.to_string();
        self.cl_editor_entries = entries;
        self.cl_editor_selected = 0;
        self.cl_editor_editing = false;
    }

    pub fn cl_editor_generate_preview(&mut self) {
        for (i, entry) in self.cl_editor_entries.iter().enumerate() {
            if let Err(e) = entry.validate() {
                self.wizard_error = Some(format!("Entry {} (seq {}): {e}", i + 1, entry.seq));
                return;
            }
        }
        self.wizard_error = None;

        let vendor = self
            .selected_router()
            .map(|r| r.vendor.clone())
            .unwrap_or(RouterVendor::Cisco);
        self.wizard_preview = crate::router::commands::communitylist_save_commands(
            &vendor,
            &self.cl_editor_name,
            &self.cl_editor_entries,
        );
        self.wizard_step = WizardStep::Review;
    }
}
