use crate::{
    app::App,
    router::ConnectionStatus,
    ui::{
        fmt_num, state_style, C_BORDER, C_DIM, C_EBGP, C_ERROR, C_ESTABLISHED, C_HEADER, C_IBGP,
        C_SELECTED, C_WARN,
    },
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

// ─── Dashboard tab ────────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(30), Constraint::Min(0)])
        .split(area);

    draw_router_list(f, app, cols[0]);
    draw_router_summary(f, app, cols[1]);
}

// ─── Router list (left panel) ─────────────────────────────────────────────────

fn draw_router_list(f: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app
        .routers
        .iter()
        .map(|r| {
            let (dot, dot_style) = match app.router_status.get(&r.id) {
                Some(ConnectionStatus::Connected) => ("●", Style::default().fg(C_ESTABLISHED)),
                Some(ConnectionStatus::Connecting) => ("◌", Style::default().fg(C_WARN)),
                Some(ConnectionStatus::Error(_)) => ("✕", Style::default().fg(C_ERROR)),
                _ => ("○", Style::default().fg(C_DIM)),
            };

            let line = Line::from(vec![
                Span::styled(dot, dot_style),
                Span::raw(" "),
                Span::styled(&r.name, Style::default().fg(C_HEADER)),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(" Routers ", Style::default().fg(C_HEADER))),
        )
        .highlight_style(Style::default().fg(C_SELECTED).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut app.router_list_state);
}

// ─── Router summary (right panel) ────────────────────────────────────────────

fn draw_router_summary(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(9)])
        .split(area);

    draw_summary_info(f, app, rows[0]);
    draw_peer_sparkline(f, app, rows[1]);
}

fn draw_summary_info(f: &mut Frame, app: &App, area: Rect) {
    let router = app.selected_router();
    let summary = app.current_summary.as_ref();

    let mut lines: Vec<Line> = Vec::new();

    if let (Some(r), Some(s)) = (router, summary) {
        let sep = Span::styled(
            "─".repeat(area.width.saturating_sub(4) as usize),
            Style::default().fg(C_DIM),
        );

        lines.push(Line::from(kv(
            "  Router ID  ",
            crate::bgp::known_text(s.router_id),
        )));
        lines.push(Line::from(kv(
            "  Local AS   ",
            crate::bgp::known_text(s.local_as),
        )));
        lines.push(Line::from(kv("  Hostname   ", r.hostname.clone())));
        lines.push(Line::from(kv("  Vendor     ", r.vendor.to_string())));
        lines.push(Line::from(kv(
            "  Table Ver  ",
            crate::bgp::known_text(s.table_version),
        )));
        lines.push(Line::from(sep.clone()));
        lines.push(Line::from(kv("  Total Peers", s.peers.len().to_string())));
        lines.push(Line::from(vec![
            Span::raw("  Established  "),
            Span::styled(
                if s.peers
                    .iter()
                    .any(|p| matches!(p.state, crate::bgp::BgpState::Unknown(_)))
                {
                    format!(
                        "{} known (partial; unobserved present)",
                        s.established_count()
                    )
                } else {
                    s.established_count().to_string()
                },
                Style::default()
                    .fg(C_ESTABLISHED)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" / {}", s.peers.len())),
        ]));
        lines.push(Line::from(kv("  Total Pfx  ", fmt_num(s.total_prefixes()))));
        if r.vendor == crate::router::RouterVendor::MikroTik {
            lines.push(Line::from(
                "  Selected-main observed peers only; unknown/unscoped audit rows excluded",
            ));
            lines.push(Line::from(
                "  Native neighbors + Config chain ordered filter editing available",
            ));
            lines.push(Line::from(
                "  Generic policy/list editing unsupported; advertisements / MTU unavailable",
            ));
            if let Some(reason) = app
                .native_cache
                .get(&r.id)
                .and_then(|c| c.stale_reason.as_deref())
            {
                lines.push(Line::from(format!("  STALE / N/A: {reason}")));
            }
        }
        lines.push(Line::from(kv(
            "  Fetched    ",
            s.fetched_at.format("%H:%M:%S UTC").to_string(),
        )));
        lines.push(Line::from(sep));
        lines.push(Line::from(Span::styled(
            "  Press [2] for peer details  [3] for routes  [4] for config",
            Style::default().fg(C_DIM),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  No router selected",
            Style::default().fg(C_DIM),
        )));
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" Summary ", Style::default().fg(C_HEADER))),
    );
    f.render_widget(para, area);
}

fn kv(key: &str, val: String) -> Span<'static> {
    Span::raw(format!("{key:<16}{val}"))
}

fn draw_peer_sparkline(f: &mut Frame, app: &App, area: Rect) {
    let summary = match app.current_summary.as_ref() {
        Some(s) => s,
        None => return,
    };

    let total = summary.peers.len();
    let estab = summary.established_count();
    // Build a simple bar chart per peer
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled(
        "  Peer States",
        Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD),
    )));

    for peer in &summary.peers {
        let peer_type_style = if peer.session_type() == "Unknown" {
            Style::default().fg(C_DIM)
        } else if peer.session_type() == "iBGP" {
            Style::default().fg(C_IBGP)
        } else {
            Style::default().fg(C_EBGP)
        };

        let ptype = peer.session_type();
        let desc = peer.description.as_deref().unwrap_or("");

        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!("{:<15}", peer.neighbor_ip),
                Style::default().fg(C_DIM),
            ),
            Span::styled(format!("{:<5}", ptype), peer_type_style),
            Span::styled(
                format!("{:<12}", peer.state.as_str()),
                state_style(&peer.state),
            ),
            Span::styled(
                format!("{:>8} pfx", fmt_num(peer.prefixes_received)),
                Style::default().fg(C_DIM),
            ),
            Span::raw("  "),
            Span::styled(desc, Style::default().fg(C_DIM)),
        ]));
    }

    if total > 0
        && !summary
            .peers
            .iter()
            .any(|peer| matches!(peer.state, crate::bgp::BgpState::Unknown(_)))
    {
        let bar_width = (area.width.saturating_sub(20) as usize).min(40);
        let filled = (estab * bar_width).checked_div(total).unwrap_or(0);
        let empty = bar_width - filled;
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled("▓".repeat(filled), Style::default().fg(C_ESTABLISHED)),
            Span::styled("░".repeat(empty), Style::default().fg(C_DIM)),
            Span::raw(format!("  {estab}/{total} established")),
        ]));
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(
                " Peer Overview ",
                Style::default().fg(C_HEADER),
            )),
    );
    f.render_widget(para, area);
}

#[cfg(test)]
mod tests {
    use crate::app::{filter_test_app, filter_test_key, ActiveTab};
    use crossterm::event::KeyCode;
    use ratatui::{backend::TestBackend, Terminal};

    #[test]
    fn mikrotik_final_005_dashboard_distinguishes_native_filters_from_generic_policies() {
        let (mut app, mut rx) = filter_test_app(None);
        filter_test_key(&mut app, KeyCode::Esc);
        app.current_tab = ActiveTab::Dashboard;
        let mut terminal = Terminal::new(TestBackend::new(180, 45)).unwrap();
        terminal
            .draw(|frame| crate::ui::draw(frame, &mut app))
            .unwrap();
        let rows = terminal
            .backend()
            .buffer()
            .content
            .chunks(180)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>();
        assert!(
            rows.iter().any(|row| row
                .contains("Native neighbors + Config chain ordered filter editing available")),
            "Dashboard must advertise delivered native editing: {rows:?}"
        );
        assert!(rows.iter().any(|row| row.contains(
            "Generic policy/list editing unsupported; advertisements / MTU unavailable"
        )));
        assert!(!rows
            .iter()
            .any(|row| row.contains("filter editing / advertisements / MTU unavailable")));
        assert!(rx.try_recv().is_err(), "Dashboard remains cache-only");
    }
}
