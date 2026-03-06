use crate::{
    app::App,
    bgp::RouteMapDetail,
    ui::{C_BORDER, C_DIM, C_ESTABLISHED, C_HEADER, C_SELECTED, C_WARN},
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

// ─── Config tab ───────────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);

    draw_config_list(f, app, cols[0]);
    draw_right_panel(f, app, cols[1]);
}

// ─── Navigable BGP config list ────────────────────────────────────────────────

fn draw_config_list(f: &mut Frame, app: &mut App, area: Rect) {
    let router_name = app
        .selected_router()
        .map(|r| r.name.clone())
        .unwrap_or_else(|| "—".into());

    let items: Vec<ListItem> = if app.config_lines.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "  No BGP data — press r to refresh",
            Style::default().fg(C_DIM),
        )))]
    } else {
        app.config_lines
            .iter()
            .map(|l| ListItem::new(syntax_highlight(l)))
            .collect()
    };

    let title = format!(" BGP Config: {router_name} ");

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(title, Style::default().fg(C_HEADER))),
        )
        .highlight_style(
            Style::default()
                .bg(ratatui::style::Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut app.config_list_state);
}

// ─── Syntax highlighting ──────────────────────────────────────────────────────

fn syntax_highlight(line: &str) -> Line<'static> {
    let s = line.to_string();
    if s.trim_start().starts_with("router bgp") {
        return Line::from(Span::styled(s, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    }
    // route-map lines are interactive — make them stand out
    if s.contains("route-map") {
        return Line::from(Span::styled(s, Style::default().fg(C_WARN).add_modifier(Modifier::BOLD)));
    }
    if s.contains("remote-as") {
        return Line::from(Span::styled(s, Style::default().fg(Color::LightBlue)));
    }
    if s.contains("description") {
        return Line::from(Span::styled(s, Style::default().fg(Color::White)));
    }
    if s.contains("next-hop-self") || s.contains("update-source") {
        return Line::from(Span::styled(s, Style::default().fg(Color::Yellow)));
    }
    if s.contains("password") {
        return Line::from(Span::styled(s, Style::default().fg(Color::Red)));
    }
    if s.trim_start().starts_with("bgp ") {
        return Line::from(Span::styled(s, Style::default().fg(Color::Magenta)));
    }
    if s.trim() == "!" {
        return Line::from(Span::styled(s, Style::default().fg(Color::DarkGray)));
    }
    Line::from(Span::raw(s))
}

// ─── Right panel (dynamic) ────────────────────────────────────────────────────

fn draw_right_panel(f: &mut Frame, app: &App, area: Rect) {
    if let Some(rm) = &app.config_routemap {
        draw_routemap_detail(f, rm, area);
    } else if let Some(name) = &app.config_rm_name {
        draw_loading_panel(f, name, area);
    } else {
        draw_cli_cheatsheet(f, area);
    }
}

// ─── Route-map detail ─────────────────────────────────────────────────────────

fn draw_routemap_detail(f: &mut Frame, rm: &RouteMapDetail, area: Rect) {
    let permit_sty  = Style::default().fg(C_ESTABLISHED).add_modifier(Modifier::BOLD);
    let deny_sty    = Style::default().fg(Color::Red).add_modifier(Modifier::BOLD);
    let match_hdr   = Style::default().fg(Color::LightBlue).add_modifier(Modifier::UNDERLINED);
    let set_hdr     = Style::default().fg(Color::LightGreen).add_modifier(Modifier::UNDERLINED);
    let clause_sty  = Style::default().fg(Color::White);
    let ref_sty     = Style::default().fg(C_WARN);
    let pfx_permit  = Style::default().fg(C_ESTABLISHED);
    let pfx_deny    = Style::default().fg(Color::Red);
    let dim         = Style::default().fg(C_DIM);
    let seq_sty     = Style::default().fg(Color::DarkGray);

    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            format!("  route-map {}", rm.name),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw("")),
    ];

    for entry in &rm.entries {
        let action_sty = if entry.action.contains("permit") { permit_sty } else { deny_sty };
        lines.push(Line::from(vec![
            Span::styled(format!("  seq {:>4}  ", entry.sequence), seq_sty),
            Span::styled(entry.action.to_uppercase(), action_sty),
        ]));

        // Match clauses
        if !entry.match_clauses.is_empty() {
            lines.push(Line::from(Span::styled("    match:", match_hdr)));
            for clause in &entry.match_clauses {
                if clause.contains("prefix-list") {
                    lines.push(Line::from(Span::styled(format!("      {clause}"), clause_sty)));
                    // Expand each referenced prefix-list inline
                    let names_part = clause.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
                    for pname in names_part.split_whitespace() {
                        lines.push(Line::from(Span::styled(format!("        ▸ {pname}"), ref_sty)));
                        match rm.prefix_lists.get(pname) {
                            Some(pl) if !pl.is_empty() => {
                                for pe in pl {
                                    let ps = if pe.action == "permit" { pfx_permit } else { pfx_deny };
                                    lines.push(Line::from(Span::styled(
                                        format!("          {} {}", pe.action, pe.prefix), ps,
                                    )));
                                }
                            }
                            _ => {
                                lines.push(Line::from(Span::styled("          (no entries)", dim)));
                            }
                        }
                    }
                } else if clause.starts_with("community") && clause.contains(':') {
                    lines.push(Line::from(Span::styled(format!("      {clause}"), clause_sty)));
                    let names_part = clause.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
                    for cname in names_part.split_whitespace() {
                        lines.push(Line::from(Span::styled(format!("        ▸ {cname}"), ref_sty)));
                        match rm.community_lists.get(cname) {
                            Some(cl) if !cl.is_empty() => {
                                for ce in cl {
                                    lines.push(Line::from(Span::styled(
                                        format!("          {ce}"), clause_sty,
                                    )));
                                }
                            }
                            _ => {
                                lines.push(Line::from(Span::styled("          (no entries)", dim)));
                            }
                        }
                    }
                } else {
                    lines.push(Line::from(Span::styled(format!("      {clause}"), clause_sty)));
                }
            }
        } else {
            lines.push(Line::from(Span::styled("    match:  (any)", dim)));
        }

        // Set clauses
        if !entry.set_clauses.is_empty() {
            lines.push(Line::from(Span::styled("    set:", set_hdr)));
            for clause in &entry.set_clauses {
                lines.push(Line::from(Span::styled(format!("      {clause}"), clause_sty)));
            }
        } else {
            lines.push(Line::from(Span::styled("    set:   (nothing)", dim)));
        }
        lines.push(Line::from(Span::raw("")));
    }

    if rm.entries.is_empty() {
        lines.push(Line::from(Span::styled("  (no entries)", dim)));
    }

    let title = format!(" Route-map: {} ", rm.name);
    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(title, Style::default().fg(C_SELECTED))),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

// ─── Loading panel ────────────────────────────────────────────────────────────

fn draw_loading_panel(f: &mut Frame, rm_name: &str, area: Rect) {
    let lines = vec![
        Line::from(Span::raw("")),
        Line::from(Span::styled(
            format!("  Fetching route-map '{rm_name}'…"),
            Style::default().fg(C_DIM),
        )),
    ];
    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(" Route-map Detail ", Style::default().fg(C_SELECTED))),
        );
    f.render_widget(para, area);
}

// ─── CLI cheat-sheet (shown when no route-map line is selected) ───────────────

fn draw_cli_cheatsheet(f: &mut Frame, area: Rect) {
    let entries: &[(&str, &str)] = &[
        ("show ip bgp summary",      "BGP peer summary"),
        ("show ip bgp neighbors",    "Detailed peer info"),
        ("show ip bgp",              "Full BGP table"),
        ("show ip bgp <prefix>",     "Specific prefix detail"),
        ("show ip bgp regexp <re>",  "Filter by AS-path regex"),
        ("",                         ""),
        ("clear ip bgp <peer> soft", "Soft reset peer"),
        ("clear ip bgp <peer>",      "Hard reset peer"),
        ("",                         ""),
        ("router bgp <ASN>",         "Enter BGP config"),
        ("neighbor <ip> remote-as",  "Add/change peer"),
        ("neighbor <ip> shutdown",   "Shutdown peer"),
        ("no neighbor <ip>",         "Remove peer"),
        ("neighbor <ip> soft-reconfiguration inbound", "Enable soft-reset"),
        ("neighbor <ip> route-map <name> in/out", "Apply route-map"),
        ("",                         ""),
        ("show route-map",           "View all route-maps"),
        ("show ip prefix-list",      "View prefix-lists"),
        ("show ip community-list",   "Community lists"),
        ("",                         ""),
        ("",                         ""),
        ("↑/↓  Navigate config lines", ""),
        ("Select a route-map line",  "→ expands detail here"),
    ];

    let key_style = Style::default().fg(Color::Yellow);
    let val_style = Style::default().fg(Color::DarkGray);
    let hint_sty  = Style::default().fg(C_ESTABLISHED);

    let lines: Vec<Line> = entries
        .iter()
        .map(|(cmd, desc)| {
            if cmd.is_empty() && desc.is_empty() {
                Line::from(Span::raw(""))
            } else if desc.is_empty() {
                Line::from(Span::styled(format!("  {cmd}"), hint_sty))
            } else {
                Line::from(vec![
                    Span::styled(format!("  {cmd}"), key_style),
                    Span::styled(format!("  — {desc}"), val_style),
                ])
            }
        })
        .collect();

    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(
                    " Cisco CLI Reference ",
                    Style::default().fg(C_SELECTED),
                )),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}
