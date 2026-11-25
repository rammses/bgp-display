//! Native-only form/review/result overlay; never displays executable bytes.
use super::{C_DIM, C_HEADER, C_SELECTED, C_WARN};
use crate::app::{App, NativeEditorStage, NATIVE_FIELDS};
use crate::router::mikrotik::presentation_text;
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

pub fn draw(frame: &mut Frame, app: &App) {
    let Some(editor) = &app.native_editor else {
        return;
    };
    let full = frame.area();
    let area = Rect {
        x: full.x + full.width.saturating_sub(112) / 2,
        y: full.y + 1,
        width: 112.min(full.width),
        height: full.height.saturating_sub(2),
    };
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_SELECTED))
        .title(format!(
            " Native neighbor — {:?} — operation {} ",
            editor.stage, editor.operation
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut lines = vec![Line::from(presentation_text(&format!(
        "ORIGINAL {}:{} / user {} / instance {} / revision {}",
        editor.registration.endpoint.hostname,
        editor.registration.endpoint.ssh_port,
        editor.registration.endpoint.username,
        editor.instance,
        editor.registration.revision
    )))];
    match editor.stage {
        NativeEditorStage::Fields => {
            lines.push(Line::styled(
                "Tab/↑↓: field  Space: choices  Enter: REVIEW  Esc: cancel",
                Style::default().fg(C_HEADER),
            ));
            lines.push(Line::from("Edit: untouched fields Keep. ~ explicitly unsets supported optional override; inherited result is reviewed."));
            lines.push(Line::from("Identity/scope immutable on edit. Creation: disabled + both enabled reject chains. Filter editing read-only."));
            for (index, label) in NATIVE_FIELDS.iter().enumerate() {
                let value = if index == 14 {
                    if editor.draft.values[index].is_empty() {
                        "<hidden; not entered>".into()
                    } else {
                        "<hidden replacement entered>".into()
                    }
                } else if editor.draft.values[index].is_empty() {
                    presentation_text(&editor.native_field_hint(index))
                } else {
                    presentation_text(&editor.draft.values[index])
                };
                let style = Style::default().fg(if index == editor.field {
                    C_SELECTED
                } else {
                    C_DIM
                });
                lines.push(Line::styled(
                    format!(
                        "{} {label}: {value}",
                        if index == editor.field { "▶" } else { " " }
                    ),
                    style,
                ));
            }
            lines.push(Line::from("Supported roles ebgp/ibgp/ibgp-rr; AFI ip/ipv6 independently of transport; next-hop default/force-self/propagate."));
            lines.push(Line::from("Native timers: infinity/3m/00:03:00; BFD is a request, not operational proof. Hidden existing MD5 is never assumed empty."));
        }
        NativeEditorStage::Review => {
            lines.push(Line::styled(
                "Enter: CONFIRM | BackTab: edit | PgUp/PgDn/Home: scroll | Esc: cancel",
                Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD),
            ));
            if let Some(preview) = &editor.preview {
                lines.extend(
                    preview
                        .visible_diff
                        .iter()
                        .map(|s| Line::from(presentation_text(s))),
                );
                lines.extend(
                    preview
                        .warnings
                        .iter()
                        .map(|s| Line::styled(presentation_text(s), Style::default().fg(C_WARN))),
                );
            }
        }
        NativeEditorStage::Applying => {
            lines.push(Line::from(
                "Applying once in background. Enter ignored. No automatic retry/replay.",
            ));
            lines.push(Line::from("Esc hides this editor; it does NOT revoke a command already started remotely. The originating receipt is retained."));
        }
        NativeEditorStage::Result => {
            if let Some(receipt) = &editor.receipt {
                lines.push(Line::styled(
                    format!("Outcome: {:?}", receipt.outcome),
                    Style::default().fg(C_WARN),
                ));
                lines.push(Line::from(presentation_text(&receipt.summary)));
                for (label, steps) in [
                    ("VERIFIED", &receipt.verified_steps),
                    ("UNCERTAIN", &receipt.uncertain_steps),
                    ("UNAPPLIED", &receipt.unapplied_steps),
                ] {
                    for step in steps {
                        lines.push(Line::from(format!("{label}: {}", presentation_text(step))));
                    }
                }
            }
            lines.push(Line::from("Non-replayable receipt. Refresh and open a NEW preview for corrective changes. Enter/Esc: close."));
        }
    }
    if let Some(error) = &editor.error {
        lines.push(Line::from(Span::styled(
            presentation_text(error),
            Style::default().fg(C_WARN),
        )));
    }
    // Fields remain navigable even in a short terminal; no source value is
    // truncated on save. Review wraps rather than exposing command payloads.
    let scroll = if editor.stage == NativeEditorStage::Fields {
        ((editor.field + 5) as u16).saturating_sub(inner.height.saturating_sub(3))
    } else {
        editor.scroll
    };
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        inner,
    );
}
