use crate::bgp::{CommunityListEntry, NeighborDraft, PrefixListEntry, RouteMapEntry};

use super::types::{WizardMode, WizardStep};
use super::App;

// ─── Wizard Key Handler ──────────────────────────────────────────────────────

pub(super) fn handle_wizard_key(app: &mut App, key: crossterm::event::KeyEvent) {
    match &app.wizard_mode {
        WizardMode::Closed => {}
        WizardMode::NeighborCreate | WizardMode::NeighborEdit(_) => {
            handle_neighbor_wizard_key(app, key);
        }
        WizardMode::NeighborDelete(_) => {
            handle_delete_wizard_key(app, key);
        }
        WizardMode::RouteMapEdit(_) => {
            handle_routemap_editor_key(app, key);
        }
        WizardMode::PrefixListEdit(_) => {
            handle_prefixlist_editor_key(app, key);
        }
        WizardMode::CommunityListEdit(_) => {
            handle_communitylist_editor_key(app, key);
        }
    }
}

fn handle_neighbor_wizard_key(app: &mut App, key: crossterm::event::KeyEvent) {
    use crossterm::event::KeyCode;

    match app.wizard_step {
        WizardStep::Fields => match key.code {
            KeyCode::Esc => app.wizard_close(),
            KeyCode::Tab | KeyCode::Down => {
                if let Some(draft) = app.wizard_draft.as_mut() {
                    if !NeighborDraft::is_toggle_field(app.wizard_field) {
                        draft.set_field(app.wizard_field, &app.wizard_buf);
                    }
                }
                app.wizard_field = (app.wizard_field + 1) % NeighborDraft::NFIELDS;
                app.wizard_buf = app
                    .wizard_draft
                    .as_ref()
                    .map(|d| match app.wizard_field {
                        8 => d.password.clone(),
                        f => d.field_value(f),
                    })
                    .unwrap_or_default();
            }
            KeyCode::BackTab | KeyCode::Up => {
                if let Some(draft) = app.wizard_draft.as_mut() {
                    if !NeighborDraft::is_toggle_field(app.wizard_field) {
                        draft.set_field(app.wizard_field, &app.wizard_buf);
                    }
                }
                app.wizard_field = if app.wizard_field == 0 {
                    NeighborDraft::NFIELDS - 1
                } else {
                    app.wizard_field - 1
                };
                app.wizard_buf = app
                    .wizard_draft
                    .as_ref()
                    .map(|d| match app.wizard_field {
                        8 => d.password.clone(),
                        f => d.field_value(f),
                    })
                    .unwrap_or_default();
            }
            KeyCode::Enter => {
                if let Some(draft) = app.wizard_draft.as_mut() {
                    if !NeighborDraft::is_toggle_field(app.wizard_field) {
                        draft.set_field(app.wizard_field, &app.wizard_buf);
                    }
                }
                app.wizard_generate_preview();
            }
            KeyCode::Char(' ') if NeighborDraft::is_toggle_field(app.wizard_field) => {
                if let Some(draft) = app.wizard_draft.as_mut() {
                    draft.toggle_field(app.wizard_field);
                }
            }
            KeyCode::Backspace => {
                if !NeighborDraft::is_toggle_field(app.wizard_field) {
                    app.wizard_buf.pop();
                }
            }
            KeyCode::Char(c) => {
                if !NeighborDraft::is_toggle_field(app.wizard_field) {
                    app.wizard_buf.push(c);
                }
            }
            _ => {}
        },
        WizardStep::Review => match key.code {
            KeyCode::Esc => {
                app.wizard_step = WizardStep::Fields;
                app.wizard_buf = app
                    .wizard_draft
                    .as_ref()
                    .map(|d| match app.wizard_field {
                        8 => d.password.clone(),
                        f => d.field_value(f),
                    })
                    .unwrap_or_default();
            }
            KeyCode::Enter => app.wizard_apply(),
            _ => {}
        },
        WizardStep::Applying => {}
        WizardStep::Result(_) => match key.code {
            KeyCode::Enter | KeyCode::Esc => app.wizard_close(),
            _ => {}
        },
    }
}

fn handle_delete_wizard_key(app: &mut App, key: crossterm::event::KeyEvent) {
    use crossterm::event::KeyCode;

    match app.wizard_step {
        WizardStep::Review => match key.code {
            KeyCode::Esc => app.wizard_close(),
            KeyCode::Char('y') | KeyCode::Enter => app.wizard_apply(),
            KeyCode::Char('n') => app.wizard_close(),
            _ => {}
        },
        WizardStep::Applying => {}
        WizardStep::Result(_) => match key.code {
            KeyCode::Enter | KeyCode::Esc => app.wizard_close(),
            _ => {}
        },
        _ => {}
    }
}

fn handle_routemap_editor_key(app: &mut App, key: crossterm::event::KeyEvent) {
    use crossterm::event::KeyCode;

    // ── Clause sub-list mode ────────────────────────────────────────────────
    if app.rm_clause_mode {
        handle_rm_clause_key(app, key);
        return;
    }

    match app.wizard_step {
        WizardStep::Fields => {
            if app.rm_editor_editing {
                // field 100 = insert-seq prompt
                if app.rm_editor_field == 100 {
                    match key.code {
                        KeyCode::Esc => {
                            app.rm_editor_editing = false;
                            app.wizard_error = None;
                        }
                        KeyCode::Enter => {
                            if let Ok(seq) = app.rm_editor_buf.parse::<u32>() {
                                if app.rm_editor_entries.iter().any(|e| e.sequence == seq) {
                                    app.wizard_error = Some(format!("Seq {seq} already exists"));
                                } else {
                                    app.wizard_error = None;
                                    app.rm_editor_entries.push(RouteMapEntry {
                                        sequence: seq,
                                        action: "permit".into(),
                                        ..Default::default()
                                    });
                                    app.rm_editor_entries.sort_by_key(|e| e.sequence);
                                    app.rm_editor_selected = app
                                        .rm_editor_entries
                                        .iter()
                                        .position(|e| e.sequence == seq)
                                        .unwrap_or(0);
                                    app.rm_editor_editing = true;
                                    app.rm_editor_field = 1;
                                    app.rm_editor_buf = "permit".into();
                                }
                            } else {
                                app.wizard_error = Some("Invalid sequence number".into());
                            }
                        }
                        KeyCode::Backspace => {
                            app.rm_editor_buf.pop();
                        }
                        KeyCode::Char(c) if c.is_ascii_digit() => {
                            app.rm_editor_buf.push(c);
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Esc => {
                            app.rm_editor_editing = false;
                        }
                        KeyCode::Tab => {
                            if app.rm_editor_field == 0 {
                                let cur_seq = app
                                    .rm_editor_entries
                                    .get(app.rm_editor_selected)
                                    .map(|e| e.sequence)
                                    .unwrap_or(0);
                                let new_seq: u32 = app.rm_editor_buf.parse().unwrap_or(cur_seq);
                                if new_seq != cur_seq
                                    && app.rm_editor_entries.iter().enumerate().any(|(j, e)| {
                                        j != app.rm_editor_selected && e.sequence == new_seq
                                    })
                                {
                                    app.wizard_error =
                                        Some(format!("Seq {new_seq} already exists"));
                                    return;
                                }
                                app.wizard_error = None;
                                if let Some(entry) =
                                    app.rm_editor_entries.get_mut(app.rm_editor_selected)
                                {
                                    entry.sequence = new_seq;
                                }
                            } else if let Some(entry) =
                                app.rm_editor_entries.get_mut(app.rm_editor_selected)
                            {
                                match app.rm_editor_field {
                                    1 => entry.action = app.rm_editor_buf.clone(),
                                    2 => {
                                        entry.match_clauses = app
                                            .rm_editor_buf
                                            .lines()
                                            .map(|s| s.to_string())
                                            .collect()
                                    }
                                    3 => {
                                        entry.set_clauses = app
                                            .rm_editor_buf
                                            .lines()
                                            .map(|s| s.to_string())
                                            .collect()
                                    }
                                    _ => {}
                                }
                            }
                            app.rm_editor_field = (app.rm_editor_field + 1) % 4;
                            if let Some(entry) = app.rm_editor_entries.get(app.rm_editor_selected) {
                                app.rm_editor_buf = match app.rm_editor_field {
                                    0 => entry.sequence.to_string(),
                                    1 => entry.action.clone(),
                                    2 => entry.match_clauses.join("\n"),
                                    3 => entry.set_clauses.join("\n"),
                                    _ => String::new(),
                                };
                            }
                        }
                        KeyCode::Enter => {
                            if app.rm_editor_field == 0 {
                                let cur_seq = app
                                    .rm_editor_entries
                                    .get(app.rm_editor_selected)
                                    .map(|e| e.sequence)
                                    .unwrap_or(0);
                                let new_seq: u32 = app.rm_editor_buf.parse().unwrap_or(cur_seq);
                                if new_seq != cur_seq
                                    && app.rm_editor_entries.iter().enumerate().any(|(j, e)| {
                                        j != app.rm_editor_selected && e.sequence == new_seq
                                    })
                                {
                                    app.wizard_error =
                                        Some(format!("Seq {new_seq} already exists"));
                                    return;
                                }
                                app.wizard_error = None;
                                if let Some(entry) =
                                    app.rm_editor_entries.get_mut(app.rm_editor_selected)
                                {
                                    entry.sequence = new_seq;
                                }
                            } else if let Some(entry) =
                                app.rm_editor_entries.get_mut(app.rm_editor_selected)
                            {
                                match app.rm_editor_field {
                                    1 => entry.action = app.rm_editor_buf.clone(),
                                    2 => {
                                        entry.match_clauses = app
                                            .rm_editor_buf
                                            .lines()
                                            .map(|s| s.to_string())
                                            .collect()
                                    }
                                    3 => {
                                        entry.set_clauses = app
                                            .rm_editor_buf
                                            .lines()
                                            .map(|s| s.to_string())
                                            .collect()
                                    }
                                    _ => {}
                                }
                            }
                            app.rm_editor_editing = false;
                            app.rm_editor_entries.sort_by_key(|e| e.sequence);
                        }
                        KeyCode::Char(' ') if app.rm_editor_field == 1 => {
                            app.rm_editor_buf = if app.rm_editor_buf == "permit" {
                                "deny".into()
                            } else {
                                "permit".into()
                            };
                        }
                        KeyCode::Backspace => {
                            app.rm_editor_buf.pop();
                        }
                        KeyCode::Char(c) => app.rm_editor_buf.push(c),
                        _ => {}
                    }
                }
            } else {
                match key.code {
                    KeyCode::Esc => app.wizard_close(),
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.rm_editor_selected > 0 {
                            app.rm_editor_selected -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.rm_editor_selected + 1 < app.rm_editor_entries.len() {
                            app.rm_editor_selected += 1;
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(entry) = app.rm_editor_entries.get(app.rm_editor_selected) {
                            app.rm_editor_editing = true;
                            app.rm_editor_field = 0;
                            app.rm_editor_buf = entry.sequence.to_string();
                        }
                    }
                    KeyCode::Char('i') => {
                        app.rm_editor_editing = true;
                        app.rm_editor_field = 100;
                        app.rm_editor_buf.clear();
                        app.wizard_error = None;
                    }
                    KeyCode::Char('a') => {
                        let seq = app
                            .rm_editor_entries
                            .last()
                            .map(|e| e.sequence + 10)
                            .unwrap_or(10);
                        if app.rm_editor_entries.iter().any(|e| e.sequence == seq) {
                            let mut s = seq;
                            while app.rm_editor_entries.iter().any(|e| e.sequence == s) {
                                s += 1;
                            }
                            app.rm_editor_entries.push(RouteMapEntry {
                                sequence: s,
                                action: "permit".into(),
                                ..Default::default()
                            });
                        } else {
                            app.rm_editor_entries.push(RouteMapEntry {
                                sequence: seq,
                                action: "permit".into(),
                                ..Default::default()
                            });
                        }
                        app.rm_editor_entries.sort_by_key(|e| e.sequence);
                        app.rm_editor_selected = app.rm_editor_entries.len() - 1;
                    }
                    KeyCode::Char(' ') => {
                        if let Some(entry) = app.rm_editor_entries.get_mut(app.rm_editor_selected) {
                            entry.action = if entry.action == "permit" {
                                "deny".into()
                            } else {
                                "permit".into()
                            };
                        }
                    }
                    KeyCode::Char('m') => {
                        if !app.rm_editor_entries.is_empty() {
                            app.rm_clause_mode = true;
                            app.rm_clause_type = "match".into();
                            app.rm_clause_idx = 0;
                            app.rm_clause_editing = false;
                            app.rm_clause_buf.clear();
                        }
                    }
                    KeyCode::Char('t') => {
                        if !app.rm_editor_entries.is_empty() {
                            app.rm_clause_mode = true;
                            app.rm_clause_type = "set".into();
                            app.rm_clause_idx = 0;
                            app.rm_clause_editing = false;
                            app.rm_clause_buf.clear();
                        }
                    }
                    KeyCode::Char('d') => {
                        if !app.rm_editor_entries.is_empty() {
                            app.rm_editor_entries.remove(app.rm_editor_selected);
                            if app.rm_editor_selected > 0
                                && app.rm_editor_selected >= app.rm_editor_entries.len()
                            {
                                app.rm_editor_selected =
                                    app.rm_editor_entries.len().saturating_sub(1);
                            }
                        }
                    }
                    KeyCode::Char('s') => {
                        app.rm_editor_generate_preview();
                    }
                    _ => {}
                }
            }
        }
        WizardStep::Review => match key.code {
            KeyCode::Esc => {
                app.wizard_step = WizardStep::Fields;
            }
            KeyCode::Enter => app.wizard_apply(),
            _ => {}
        },
        WizardStep::Applying => {}
        WizardStep::Result(_) => match key.code {
            KeyCode::Enter | KeyCode::Esc => app.wizard_close(),
            _ => {}
        },
    }
}

fn handle_rm_clause_key(app: &mut App, key: crossterm::event::KeyEvent) {
    use crossterm::event::KeyCode;

    let is_match = app.rm_clause_type == "match";

    if app.rm_clause_editing {
        match key.code {
            KeyCode::Esc => {
                app.rm_clause_editing = false;
            }
            KeyCode::Enter => {
                let val = app.rm_clause_buf.clone();
                if let Some(entry) = app.rm_editor_entries.get_mut(app.rm_editor_selected) {
                    let list = if is_match {
                        &mut entry.match_clauses
                    } else {
                        &mut entry.set_clauses
                    };
                    if app.rm_clause_idx < list.len() {
                        list[app.rm_clause_idx] = val;
                    }
                }
                app.rm_clause_editing = false;
            }
            KeyCode::Backspace => {
                app.rm_clause_buf.pop();
            }
            KeyCode::Char(c) => app.rm_clause_buf.push(c),
            _ => {}
        }
        return;
    }

    let clause_len = app
        .rm_editor_entries
        .get(app.rm_editor_selected)
        .map(|e| {
            if is_match {
                e.match_clauses.len()
            } else {
                e.set_clauses.len()
            }
        })
        .unwrap_or(0);

    match key.code {
        KeyCode::Esc => {
            app.rm_clause_mode = false;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.rm_clause_idx > 0 {
                app.rm_clause_idx -= 1;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.rm_clause_idx + 1 < clause_len {
                app.rm_clause_idx += 1;
            }
        }
        KeyCode::Enter => {
            if let Some(entry) = app.rm_editor_entries.get(app.rm_editor_selected) {
                let list = if is_match {
                    &entry.match_clauses
                } else {
                    &entry.set_clauses
                };
                if let Some(val) = list.get(app.rm_clause_idx) {
                    app.rm_clause_buf = val.clone();
                    app.rm_clause_editing = true;
                }
            }
        }
        KeyCode::Char('a') => {
            let placeholder = if is_match {
                "ip address prefix-list NAME"
            } else {
                "local-preference 100"
            };
            if let Some(entry) = app.rm_editor_entries.get_mut(app.rm_editor_selected) {
                let list = if is_match {
                    &mut entry.match_clauses
                } else {
                    &mut entry.set_clauses
                };
                list.push(placeholder.to_string());
                app.rm_clause_idx = list.len() - 1;
                app.rm_clause_buf = placeholder.to_string();
                app.rm_clause_editing = true;
            }
        }
        KeyCode::Char('d') => {
            if clause_len > 0 {
                if let Some(entry) = app.rm_editor_entries.get_mut(app.rm_editor_selected) {
                    let list = if is_match {
                        &mut entry.match_clauses
                    } else {
                        &mut entry.set_clauses
                    };
                    list.remove(app.rm_clause_idx);
                    if app.rm_clause_idx >= list.len() && !list.is_empty() {
                        app.rm_clause_idx = list.len() - 1;
                    }
                }
            }
        }
        KeyCode::Char('p') => {
            if is_match {
                if let Some(entry) = app.rm_editor_entries.get(app.rm_editor_selected) {
                    if let Some(clause) = entry.match_clauses.get(app.rm_clause_idx) {
                        if clause.contains("prefix-list") {
                            let pl_name =
                                clause.split_whitespace().last().unwrap_or("").to_string();
                            if !pl_name.is_empty() {
                                app.rm_clause_mode = false;
                                app.open_prefixlist_editor(&pl_name);
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn handle_prefixlist_editor_key(app: &mut App, key: crossterm::event::KeyEvent) {
    use crossterm::event::KeyCode;

    match app.wizard_step {
        WizardStep::Fields => {
            if app.pl_editor_editing {
                // field 100 = insert-seq prompt
                if app.pl_editor_field == 100 {
                    match key.code {
                        KeyCode::Esc => {
                            app.pl_editor_editing = false;
                            app.wizard_error = None;
                        }
                        KeyCode::Enter => {
                            if let Ok(seq) = app.pl_editor_buf.parse::<u32>() {
                                if app.pl_editor_entries.iter().any(|e| e.seq == seq) {
                                    app.wizard_error = Some(format!("Seq {seq} already exists"));
                                } else {
                                    app.wizard_error = None;
                                    app.pl_editor_entries.push(PrefixListEntry {
                                        seq,
                                        action: "permit".into(),
                                        prefix: String::new(),
                                    });
                                    app.pl_editor_entries.sort_by_key(|e| e.seq);
                                    app.pl_editor_selected = app
                                        .pl_editor_entries
                                        .iter()
                                        .position(|e| e.seq == seq)
                                        .unwrap_or(0);
                                    app.pl_editor_editing = true;
                                    app.pl_editor_field = 2;
                                    app.pl_editor_buf.clear();
                                }
                            } else {
                                app.wizard_error = Some("Invalid sequence number".into());
                            }
                        }
                        KeyCode::Backspace => {
                            app.pl_editor_buf.pop();
                        }
                        KeyCode::Char(c) if c.is_ascii_digit() => {
                            app.pl_editor_buf.push(c);
                        }
                        _ => {}
                    }
                } else if app.pl_editor_field == 99 {
                    match key.code {
                        KeyCode::Esc => {
                            app.pl_editor_editing = false;
                        }
                        KeyCode::Enter => {
                            if !app.pl_editor_buf.is_empty() {
                                app.pl_editor_name = app.pl_editor_buf.clone();
                            }
                            app.pl_editor_editing = false;
                        }
                        KeyCode::Backspace => {
                            app.pl_editor_buf.pop();
                        }
                        KeyCode::Char(c) => app.pl_editor_buf.push(c),
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Esc => {
                            app.pl_editor_editing = false;
                        }
                        KeyCode::Tab => {
                            if app.pl_editor_field == 0 {
                                let cur_seq = app
                                    .pl_editor_entries
                                    .get(app.pl_editor_selected)
                                    .map(|e| e.seq)
                                    .unwrap_or(0);
                                let new_seq: u32 = app.pl_editor_buf.parse().unwrap_or(cur_seq);
                                if new_seq != cur_seq
                                    && app.pl_editor_entries.iter().enumerate().any(|(j, e)| {
                                        j != app.pl_editor_selected && e.seq == new_seq
                                    })
                                {
                                    app.wizard_error =
                                        Some(format!("Seq {new_seq} already exists"));
                                    return;
                                }
                                app.wizard_error = None;
                                if let Some(entry) =
                                    app.pl_editor_entries.get_mut(app.pl_editor_selected)
                                {
                                    entry.seq = new_seq;
                                }
                            } else if let Some(entry) =
                                app.pl_editor_entries.get_mut(app.pl_editor_selected)
                            {
                                match app.pl_editor_field {
                                    1 => entry.action = app.pl_editor_buf.clone(),
                                    2 => entry.prefix = app.pl_editor_buf.clone(),
                                    _ => {}
                                }
                            }
                            app.pl_editor_field = (app.pl_editor_field + 1) % 3;
                            if let Some(entry) = app.pl_editor_entries.get(app.pl_editor_selected) {
                                app.pl_editor_buf = match app.pl_editor_field {
                                    0 => entry.seq.to_string(),
                                    1 => entry.action.clone(),
                                    2 => entry.prefix.clone(),
                                    _ => String::new(),
                                };
                            }
                        }
                        KeyCode::Enter => {
                            if app.pl_editor_field == 0 {
                                let cur_seq = app
                                    .pl_editor_entries
                                    .get(app.pl_editor_selected)
                                    .map(|e| e.seq)
                                    .unwrap_or(0);
                                let new_seq: u32 = app.pl_editor_buf.parse().unwrap_or(cur_seq);
                                if new_seq != cur_seq
                                    && app.pl_editor_entries.iter().enumerate().any(|(j, e)| {
                                        j != app.pl_editor_selected && e.seq == new_seq
                                    })
                                {
                                    app.wizard_error =
                                        Some(format!("Seq {new_seq} already exists"));
                                    return;
                                }
                                app.wizard_error = None;
                                if let Some(entry) =
                                    app.pl_editor_entries.get_mut(app.pl_editor_selected)
                                {
                                    entry.seq = new_seq;
                                }
                                app.pl_editor_field = 1;
                                if let Some(entry) =
                                    app.pl_editor_entries.get(app.pl_editor_selected)
                                {
                                    app.pl_editor_buf = entry.action.clone();
                                }
                            } else if app.pl_editor_field == 1 {
                                if let Some(entry) =
                                    app.pl_editor_entries.get_mut(app.pl_editor_selected)
                                {
                                    entry.action = app.pl_editor_buf.clone();
                                }
                                app.pl_editor_field = 2;
                                if let Some(entry) =
                                    app.pl_editor_entries.get(app.pl_editor_selected)
                                {
                                    app.pl_editor_buf = entry.prefix.clone();
                                }
                            } else {
                                if let Some(entry) =
                                    app.pl_editor_entries.get_mut(app.pl_editor_selected)
                                {
                                    entry.prefix = app.pl_editor_buf.clone();
                                }
                                app.pl_editor_editing = false;
                                app.pl_editor_entries.sort_by_key(|e| e.seq);
                            }
                        }
                        KeyCode::Char(' ') if app.pl_editor_field == 1 => {
                            app.pl_editor_buf = if app.pl_editor_buf == "permit" {
                                "deny".into()
                            } else {
                                "permit".into()
                            };
                        }
                        KeyCode::Backspace => {
                            app.pl_editor_buf.pop();
                        }
                        KeyCode::Char(c) => app.pl_editor_buf.push(c),
                        _ => {}
                    }
                }
            } else {
                match key.code {
                    KeyCode::Esc => app.wizard_close(),
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.pl_editor_selected > 0 {
                            app.pl_editor_selected -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.pl_editor_selected + 1 < app.pl_editor_entries.len() {
                            app.pl_editor_selected += 1;
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(entry) = app.pl_editor_entries.get(app.pl_editor_selected) {
                            app.pl_editor_editing = true;
                            if entry.prefix.trim().is_empty() {
                                app.pl_editor_field = 2;
                                app.pl_editor_buf.clear();
                            } else {
                                app.pl_editor_field = 0;
                                app.pl_editor_buf = entry.seq.to_string();
                            }
                        }
                    }
                    KeyCode::Char('i') => {
                        app.pl_editor_editing = true;
                        app.pl_editor_field = 100;
                        app.pl_editor_buf.clear();
                        app.wizard_error = None;
                    }
                    KeyCode::Char('a') => {
                        let mut seq = app.pl_editor_entries.last().map(|e| e.seq + 5).unwrap_or(5);
                        while app.pl_editor_entries.iter().any(|e| e.seq == seq) {
                            seq += 1;
                        }
                        app.pl_editor_entries.push(PrefixListEntry {
                            seq,
                            action: "permit".into(),
                            prefix: String::new(),
                        });
                        app.pl_editor_entries.sort_by_key(|e| e.seq);
                        app.pl_editor_selected = app
                            .pl_editor_entries
                            .iter()
                            .position(|e| e.seq == seq)
                            .unwrap_or(app.pl_editor_entries.len() - 1);
                        app.pl_editor_editing = true;
                        app.pl_editor_field = 2;
                        app.pl_editor_buf.clear();
                    }
                    KeyCode::Char(' ') => {
                        if let Some(entry) = app.pl_editor_entries.get_mut(app.pl_editor_selected) {
                            entry.action = if entry.action == "permit" {
                                "deny".into()
                            } else {
                                "permit".into()
                            };
                        }
                    }
                    KeyCode::Char('d') => {
                        if !app.pl_editor_entries.is_empty() {
                            app.pl_editor_entries.remove(app.pl_editor_selected);
                            if app.pl_editor_selected > 0
                                && app.pl_editor_selected >= app.pl_editor_entries.len()
                            {
                                app.pl_editor_selected =
                                    app.pl_editor_entries.len().saturating_sub(1);
                            }
                        }
                    }
                    KeyCode::Char('N') => {
                        app.pl_editor_editing = true;
                        app.pl_editor_field = 99;
                        app.pl_editor_buf = app.pl_editor_name.clone();
                    }
                    KeyCode::Char('s') => {
                        app.pl_editor_generate_preview();
                    }
                    _ => {}
                }
            }
        }
        WizardStep::Review => match key.code {
            KeyCode::Esc => {
                app.wizard_step = WizardStep::Fields;
            }
            KeyCode::Enter => app.wizard_apply(),
            _ => {}
        },
        WizardStep::Applying => {}
        WizardStep::Result(_) => match key.code {
            KeyCode::Enter | KeyCode::Esc => app.wizard_close(),
            _ => {}
        },
    }
}

fn handle_communitylist_editor_key(app: &mut App, key: crossterm::event::KeyEvent) {
    use crossterm::event::KeyCode;

    match app.wizard_step {
        WizardStep::Fields => {
            if app.cl_editor_editing {
                // field 100 = insert-seq prompt
                if app.cl_editor_field == 100 {
                    match key.code {
                        KeyCode::Esc => {
                            app.cl_editor_editing = false;
                            app.wizard_error = None;
                        }
                        KeyCode::Enter => {
                            if let Ok(seq) = app.cl_editor_buf.parse::<u32>() {
                                if app.cl_editor_entries.iter().any(|e| e.seq == seq) {
                                    app.wizard_error = Some(format!("Seq {seq} already exists"));
                                } else {
                                    app.wizard_error = None;
                                    app.cl_editor_entries.push(CommunityListEntry {
                                        seq,
                                        action: "permit".into(),
                                        community: String::new(),
                                    });
                                    app.cl_editor_entries.sort_by_key(|e| e.seq);
                                    app.cl_editor_selected = app
                                        .cl_editor_entries
                                        .iter()
                                        .position(|e| e.seq == seq)
                                        .unwrap_or(0);
                                    app.cl_editor_editing = true;
                                    app.cl_editor_field = 1;
                                    app.cl_editor_buf = "permit".into();
                                }
                            } else {
                                app.wizard_error = Some("Invalid sequence number".into());
                            }
                        }
                        KeyCode::Backspace => {
                            app.cl_editor_buf.pop();
                        }
                        KeyCode::Char(c) if c.is_ascii_digit() => {
                            app.cl_editor_buf.push(c);
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Esc => {
                            app.cl_editor_editing = false;
                        }
                        KeyCode::Tab => {
                            if app.cl_editor_field == 0 {
                                let cur_seq = app
                                    .cl_editor_entries
                                    .get(app.cl_editor_selected)
                                    .map(|e| e.seq)
                                    .unwrap_or(0);
                                let new_seq: u32 = app.cl_editor_buf.parse().unwrap_or(cur_seq);
                                if new_seq != cur_seq
                                    && app.cl_editor_entries.iter().enumerate().any(|(j, e)| {
                                        j != app.cl_editor_selected && e.seq == new_seq
                                    })
                                {
                                    app.wizard_error =
                                        Some(format!("Seq {new_seq} already exists"));
                                    return;
                                }
                                app.wizard_error = None;
                                if let Some(entry) =
                                    app.cl_editor_entries.get_mut(app.cl_editor_selected)
                                {
                                    entry.seq = new_seq;
                                }
                            } else if let Some(entry) =
                                app.cl_editor_entries.get_mut(app.cl_editor_selected)
                            {
                                match app.cl_editor_field {
                                    1 => entry.action = app.cl_editor_buf.clone(),
                                    2 => entry.community = app.cl_editor_buf.clone(),
                                    _ => {}
                                }
                            }
                            app.cl_editor_field = (app.cl_editor_field + 1) % 3;
                            if let Some(entry) = app.cl_editor_entries.get(app.cl_editor_selected) {
                                app.cl_editor_buf = match app.cl_editor_field {
                                    0 => entry.seq.to_string(),
                                    1 => entry.action.clone(),
                                    2 => entry.community.clone(),
                                    _ => String::new(),
                                };
                            }
                        }
                        KeyCode::Enter => {
                            if app.cl_editor_field == 0 {
                                let cur_seq = app
                                    .cl_editor_entries
                                    .get(app.cl_editor_selected)
                                    .map(|e| e.seq)
                                    .unwrap_or(0);
                                let new_seq: u32 = app.cl_editor_buf.parse().unwrap_or(cur_seq);
                                if new_seq != cur_seq
                                    && app.cl_editor_entries.iter().enumerate().any(|(j, e)| {
                                        j != app.cl_editor_selected && e.seq == new_seq
                                    })
                                {
                                    app.wizard_error =
                                        Some(format!("Seq {new_seq} already exists"));
                                    return;
                                }
                                app.wizard_error = None;
                                if let Some(entry) =
                                    app.cl_editor_entries.get_mut(app.cl_editor_selected)
                                {
                                    entry.seq = new_seq;
                                }
                            } else if let Some(entry) =
                                app.cl_editor_entries.get_mut(app.cl_editor_selected)
                            {
                                match app.cl_editor_field {
                                    1 => entry.action = app.cl_editor_buf.clone(),
                                    2 => entry.community = app.cl_editor_buf.clone(),
                                    _ => {}
                                }
                            }
                            app.cl_editor_editing = false;
                            app.cl_editor_entries.sort_by_key(|e| e.seq);
                        }
                        KeyCode::Char(' ') if app.cl_editor_field == 1 => {
                            app.cl_editor_buf = if app.cl_editor_buf == "permit" {
                                "deny".into()
                            } else {
                                "permit".into()
                            };
                        }
                        KeyCode::Backspace => {
                            app.cl_editor_buf.pop();
                        }
                        KeyCode::Char(c) => app.cl_editor_buf.push(c),
                        _ => {}
                    }
                }
            } else {
                match key.code {
                    KeyCode::Esc => app.wizard_close(),
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.cl_editor_selected > 0 {
                            app.cl_editor_selected -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.cl_editor_selected + 1 < app.cl_editor_entries.len() {
                            app.cl_editor_selected += 1;
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(entry) = app.cl_editor_entries.get(app.cl_editor_selected) {
                            app.cl_editor_editing = true;
                            app.cl_editor_field = 0;
                            app.cl_editor_buf = entry.seq.to_string();
                        }
                    }
                    KeyCode::Char('i') => {
                        app.cl_editor_editing = true;
                        app.cl_editor_field = 100;
                        app.cl_editor_buf.clear();
                        app.wizard_error = None;
                    }
                    KeyCode::Char('a') => {
                        let seq = app.cl_editor_entries.last().map(|e| e.seq + 5).unwrap_or(5);
                        if app.cl_editor_entries.iter().any(|e| e.seq == seq) {
                            let mut s = seq;
                            while app.cl_editor_entries.iter().any(|e| e.seq == s) {
                                s += 1;
                            }
                            app.cl_editor_entries.push(CommunityListEntry {
                                seq: s,
                                action: "permit".into(),
                                community: String::new(),
                            });
                        } else {
                            app.cl_editor_entries.push(CommunityListEntry {
                                seq,
                                action: "permit".into(),
                                community: String::new(),
                            });
                        }
                        app.cl_editor_entries.sort_by_key(|e| e.seq);
                        app.cl_editor_selected = app.cl_editor_entries.len() - 1;
                    }
                    KeyCode::Char(' ') => {
                        if let Some(entry) = app.cl_editor_entries.get_mut(app.cl_editor_selected) {
                            entry.action = if entry.action == "permit" {
                                "deny".into()
                            } else {
                                "permit".into()
                            };
                        }
                    }
                    KeyCode::Char('d') => {
                        if !app.cl_editor_entries.is_empty() {
                            app.cl_editor_entries.remove(app.cl_editor_selected);
                            if app.cl_editor_selected > 0
                                && app.cl_editor_selected >= app.cl_editor_entries.len()
                            {
                                app.cl_editor_selected =
                                    app.cl_editor_entries.len().saturating_sub(1);
                            }
                        }
                    }
                    KeyCode::Char('s') => {
                        app.cl_editor_generate_preview();
                    }
                    _ => {}
                }
            }
        }
        WizardStep::Review => match key.code {
            KeyCode::Esc => {
                app.wizard_step = WizardStep::Fields;
            }
            KeyCode::Enter => app.wizard_apply(),
            _ => {}
        },
        WizardStep::Applying => {}
        WizardStep::Result(_) => match key.code {
            KeyCode::Enter | KeyCode::Esc => app.wizard_close(),
            _ => {}
        },
    }
}
