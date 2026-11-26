//! Presentation only. Never parse a rendered line to select/authorize a write.
use super::{C_DIM, C_SELECTED, C_WARN};
use crate::app::{App, NativeEditorStage, NativeFilterField};
use crate::router::mikrotik::{
    filter::{AUDIT_WARNING, LIVE_WARNING},
    presentation_text,
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::Line,
    widgets::{Block, Borders, Clear, List, ListState, Paragraph, Wrap},
    Frame,
};

pub fn draw(frame: &mut Frame, app: &App) {
    let Some(e) = &app.native_filter_editor else {
        return;
    };
    let full = frame.area();
    let area = Rect {
        x: full.x + full.width.saturating_sub(120) / 2,
        y: full.y + 1,
        width: full.width.min(120),
        height: full.height.saturating_sub(2),
    };
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_SELECTED))
        .title(format!(" Native filters — {:?} ", e.stage));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(7),
        ])
        .split(inner);
    let mut header = vec![
        Line::from(presentation_text(&format!(
            "ORIGINAL {}:{} / user {} / instance {} / chain {}",
            e.registration.endpoint.hostname,
            e.registration.endpoint.ssh_port,
            e.registration.endpoint.username,
            e.instance,
            e.chain
        ))),
        Line::from(format!(
            "operation {} / original generation {}",
            e.operation, e.generation
        )),
    ];
    header.push(Line::styled(
        format!(
            "{} | shared acknowledgment: {} | display clipped; full source retained",
            if e.read_only_reason.is_some() {
                "READ-ONLY"
            } else {
                "Local draft — no device writes"
            },
            if e.shared_acknowledged {
                "yes"
            } else {
                "NO (s:ack)"
            }
        ),
        Style::default().fg(C_WARN),
    ));
    if let Some(reason) = &e.read_only_reason {
        header[2] = Line::styled(
            format!("READ-ONLY: {}", presentation_text(reason)),
            Style::default().fg(C_WARN),
        );
    }
    frame.render_widget(Paragraph::new(header), chunks[0]);
    let mut footer = Vec::new();
    let mut body = Vec::new();
    match e.stage {
        NativeEditorStage::Fields if e.raw_field.is_some() => {
            footer.push(Line::from(
                "Enter:newline  Ctrl-S:save LOCAL  Esc:cancel field",
            ));
            footer.push(Line::from("←→/↑↓/Home/End:cursor  PgUp/PgDn:scroll"));
            let raw = if e.raw_field == Some(NativeFilterField::Text) {
                &e.text
            } else {
                &e.comment
            };
            let cursor_label = Line::styled(
                format!(
                    "RAW {:?} — cursor byte {} / line {}",
                    e.raw_field,
                    e.cursor,
                    raw[..e.cursor.min(raw.len())]
                        .bytes()
                        .filter(|b| *b == b'\n')
                        .count()
                        + 1
                ),
                Style::default().fg(C_SELECTED),
            );
            let label_area = Rect {
                height: chunks[1].height.min(1),
                ..chunks[1]
            };
            frame.render_widget(Paragraph::new(cursor_label), label_area);
            let raw_area = Rect {
                y: chunks[1].y + label_area.height,
                height: chunks[1].height.saturating_sub(label_area.height),
                ..chunks[1]
            };
            let mut marked = raw.clone();
            marked.insert(e.cursor.min(marked.len()), '▏');
            // Unwrapped raw viewport: a long earlier prefix cannot push the
            // actual cursor offscreen. Width is PRESENTATION width only; source
            // bytes/cursor stay unmodified, including multibyte Unicode.
            let prefix = raw[..e.cursor.min(raw.len())]
                .rsplit('\n')
                .next()
                .unwrap_or("");
            let column = Line::from(presentation_text(prefix)).width();
            let horizontal = column.saturating_sub(usize::from(raw_area.width).saturating_sub(2));
            let lines = marked
                .split('\n')
                .map(|line| Line::from(presentation_text(line)))
                .collect::<Vec<_>>();
            frame.render_widget(
                Paragraph::new(lines)
                    .scroll((e.scroll, u16::try_from(horizontal).unwrap_or(u16::MAX))),
                raw_area,
            );
        }
        NativeEditorStage::Fields => {
            footer.push(Line::from(
                "a:add e:text c:comment d:delete Space:state U/D:move",
            ));
            footer.push(Line::from(
                "↑↓/j/k:select s:ack Enter/r:Review Esc:close PgUp/PgDn:scroll",
            ));
            let panels = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length((chunks[1].height / 3).clamp(1, 5)),
                    Constraint::Min(0),
                ])
                .split(chunks[1]);
            let items = e
                .rules
                .iter()
                .map(|row| {
                    let id = if row.id.starts_with("@local/") {
                        "(new rule)"
                    } else {
                        row.id.as_str()
                    };
                    Line::from(presentation_text(&format!(
                        "{id} disabled={} inactive={} — {}",
                        row.props
                            .get("disabled")
                            .unwrap_or(&serde_json::Value::Null),
                        row.props
                            .get("inactive")
                            .unwrap_or(&serde_json::Value::Null),
                        row.props
                            .get("rule")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("<unreadable>")
                    )))
                })
                .collect::<Vec<_>>();
            let mut state = ListState::default().with_selected(Some(e.selected));
            frame.render_stateful_widget(
                List::new(items)
                    .highlight_symbol("▶ ")
                    .highlight_style(Style::default().fg(C_SELECTED)),
                panels[0],
                &mut state,
            );
            if let Some(row) = e.rules.get(e.selected) {
                for key in ["rule", "comment", "inactive", "diagnostic"] {
                    if let Some(value) = row.props.get(key) {
                        body.push(Line::styled(format!("{key}:"), Style::default().fg(C_DIM)));
                        let raw = value
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| value.to_string());
                        body.extend(raw.split('\n').map(|s| Line::from(presentation_text(s))));
                    }
                }
            }
            if let Some(reason) = &e.read_only_reason {
                body.push(Line::styled(
                    presentation_text(reason),
                    Style::default().fg(C_WARN),
                ));
            }
            body.push(Line::from(
                "KNOWN DIRECT CONSUMERS (positive observations only):",
            ));
            body.extend(e.consumers.iter().map(|s| Line::from(presentation_text(s))));
            frame.render_widget(
                Paragraph::new(body)
                    .wrap(Wrap { trim: false })
                    .scroll((e.scroll, 0)),
                panels[1],
            );
            body = Vec::new(); // already rendered in the bounded selected-value pane
        }
        NativeEditorStage::Review => {
            footer.push(Line::from(
                "Enter:CONFIRM once  BackTab/Esc:back (clears preview)",
            ));
            footer.push(Line::from(
                "PgUp/PgDn/Home:scroll — exact original source, no rebase",
            ));
            if let Some(p) = &e.preview {
                body.extend(
                    p.visible_diff
                        .iter()
                        .chain(&p.warnings)
                        .map(|s| Line::from(presentation_text(s))),
                );
            }
        }
        NativeEditorStage::Applying => {
            footer.push(Line::from(
                "Applying ONCE in background. Enter ignored. Esc hides.",
            ));
            footer.push(Line::from(
                "Closing does NOT revoke a launched remote operation.",
            ));
            body.push(Line::from("Strict marker + independent post-read required. No automatic retry/replay/rollback."));
        }
        NativeEditorStage::Result => {
            footer.push(Line::from(
                "Enter/Esc:close. Refresh and open a NEW preview to correct.",
            ));
            footer.push(Line::from(
                "Origin-correlated, non-replayable encrypted history receipt.",
            ));
            if let Some(r) = &e.receipt {
                body.push(Line::from(format!("Outcome: {:?}", r.outcome)));
                body.push(Line::from(presentation_text(&r.summary)));
                for (label, steps) in [
                    ("VERIFIED", &r.verified_steps),
                    ("UNCERTAIN", &r.uncertain_steps),
                    ("UNAPPLIED", &r.unapplied_steps),
                ] {
                    body.extend(
                        steps
                            .iter()
                            .map(|s| Line::from(format!("{label}: {}", presentation_text(s)))),
                    );
                }
            }
        }
    }
    if !body.is_empty() {
        frame.render_widget(
            Paragraph::new(body)
                .wrap(Wrap { trim: false })
                .scroll((e.scroll, 0)),
            chunks[1],
        );
    }
    footer.push(Line::styled(LIVE_WARNING, Style::default().fg(C_WARN)));
    footer.push(Line::styled(AUDIT_WARNING, Style::default().fg(C_WARN)));
    footer.push(Line::from(
        "Display clipped; full values retained. Syntax best effort; no wizard/dry-run.",
    ));
    if let Some(error) = &e.error {
        footer.push(Line::styled(
            presentation_text(error),
            Style::default().fg(C_WARN),
        ));
    }
    frame.render_widget(Paragraph::new(footer).wrap(Wrap { trim: false }), chunks[2]);
}

#[cfg(test)]
mod tests {
    use crate::app::{filter_test_app, filter_test_key};
    use crate::router::mikrotik::{config_guard, test_support::*};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{backend::TestBackend, Terminal};
    use serde_json::json;

    fn rows(app: &mut crate::app::App, width: u16, height: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| crate::ui::draw(f, app)).unwrap();
        let b = terminal.backend().buffer();
        (0..height)
            .map(|y| (0..width).map(|x| b[(x, y)].symbol()).collect::<String>())
            .collect()
    }
    #[test]
    fn mikrotik_filter_real_render_and_keys_pin_native_controls_warning_and_raw_cursor() {
        let (mut app, mut rx) = filter_test_app(None);
        app.show_help = true;
        let text = rows(&mut app, 112, 26).join("\n");
        assert!(
            text.contains("Native filters"),
            "native input owner must render above other modals"
        );
        assert!(!text.contains("Keyboard Shortcuts"));
        assert!(text.contains("a:add") && text.contains("U/D") && text.contains("s:ack"));
        filter_test_key(&mut app, KeyCode::Char('e'));
        filter_test_key(&mut app, KeyCode::Enter);
        for c in "α\"\\$".chars() {
            filter_test_key(&mut app, KeyCode::Char(c));
        }
        let text = rows(&mut app, 80, 18).join("\n");
        assert!(text.contains("Ctrl-S") && text.contains("newline") && text.contains("Esc"));
        assert!(text.contains("α\"\\$") && text.contains("cursor"));
        assert!(rx.try_recv().is_err());
        crate::app::handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
        );
        filter_test_key(&mut app, KeyCode::Char('s'));
        filter_test_key(&mut app, KeyCode::Enter);
        let text = rows(&mut app, 112, 26).join("\n");
        assert!(text.contains("live changes; not atomic; shared consumers may be affected."));
        assert!(text.contains("peer-a") && text.contains("peer-b") && text.contains("CONFIRM"));
    }
    #[test]
    fn mikrotik_filter_real_render_sanitizes_controls_only_and_labels_view_only_clipping() {
        let mut s = documented_snapshot();
        let source = "α\u{1b}[2J\n$\"\\".to_owned() + &"long ".repeat(10000);
        s.inventory.rules[0]
            .props
            .insert("rule".into(), json!(source));
        s.guard = config_guard(&s.inventory, "blue").unwrap();
        let (mut app, mut rx) = filter_test_app(Some(s));
        let text = rows(&mut app, 112, 26).join("\n");
        assert!(text.contains("READ-ONLY") && text.contains("clipped"));
        assert!(text.contains("\\u{1b}") && !text.contains('\u{1b}'));
        filter_test_key(&mut app, KeyCode::PageDown);
        assert!(app.native_filter_editor.as_ref().unwrap().scroll > 0);
        assert_eq!(
            app.native_filter_editor.as_ref().unwrap().rules[0].props["rule"],
            source
        );
        filter_test_key(&mut app, KeyCode::Char('e'));
        filter_test_key(&mut app, KeyCode::Enter);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn mikrotik_filter_real_render_long_raw_cursor_and_short_controls_stay_visible() {
        let mut s = documented_snapshot();
        let text = "α".repeat(4000) + "TAIL;";
        s.inventory.rules[0]
            .props
            .insert("rule".into(), json!(text));
        s.guard = config_guard(&s.inventory, "blue").unwrap();
        let (mut app, mut rx) = filter_test_app(Some(s));
        filter_test_key(&mut app, KeyCode::Char('e'));
        let output = rows(&mut app, 64, 16).join("\n");
        assert!(
            output.contains("TAIL;▏"),
            "raw cursor/value must remain visible at end of a long line"
        );
        assert!(
            output.contains("Ctrl-S") && output.contains("Enter:newline") && output.contains("Esc")
        );
        filter_test_key(&mut app, KeyCode::Home);
        filter_test_key(&mut app, KeyCode::Right);
        filter_test_key(&mut app, KeyCode::Backspace);
        crate::app::handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
        );
        let e = app.native_filter_editor.as_ref().unwrap();
        assert_eq!(e.rules[0].props["rule"], "α".repeat(3999) + "TAIL;");
        assert_eq!(e.base.inventory.rules[0].props["rule"], text);
        assert!(rx.try_recv().is_err());
    }
}
