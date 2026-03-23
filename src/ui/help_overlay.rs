use crate::{
    app::{ActiveTab, App},
    ui::{C_DIM, C_HEADER, C_SELECTED},
};
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

pub fn draw(f: &mut Frame, app: &App) {
    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            " Global shortcuts",
            Style::default()
                .fg(C_HEADER)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )),
        key_line("q", "Quit"),
        key_line("Tab / Shift-Tab", "Switch tab"),
        key_line("1-7", "Jump to tab"),
        key_line("↑/↓ or j/k", "Navigate"),
        key_line("r / F5", "Refresh"),
        key_line("p", "Projects"),
        key_line("?", "Toggle this help"),
        Line::from(Span::raw("")),
    ];

    let tab_title = match app.current_tab {
        ActiveTab::Dashboard => "Dashboard",
        ActiveTab::Peers => "Peers",
        ActiveTab::Routes => "Routes",
        ActiveTab::Config => "Config",
        ActiveTab::Logs => "BGP Log",
        ActiveTab::Routers => "Routers",
        ActiveTab::ConnLog => "SSH Log",
    };

    lines.push(Line::from(Span::styled(
        format!(" {tab_title} shortcuts"),
        Style::default()
            .fg(C_HEADER)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    )));

    match app.current_tab {
        ActiveTab::Dashboard => {
            lines.push(key_line("n", "New neighbor"));
        }
        ActiveTab::Peers => {
            lines.push(key_line("Enter", "Peer routes"));
            lines.push(key_line("m", "MTU probe"));
            lines.push(key_line("n", "New neighbor"));
            lines.push(key_line("e", "Edit neighbor"));
            lines.push(key_line("x", "Delete neighbor"));
            lines.push(key_line("s", "Shutdown/no-shutdown"));
            lines.push(key_line("/", "Filter"));
            lines.push(key_line("i", "Received routes"));
            lines.push(key_line("o", "Advertised routes"));
        }
        ActiveTab::Routes => {
            lines.push(key_line("/", "Filter"));
        }
        ActiveTab::Config => {
            lines.push(key_line("e", "Edit RM/PL/CL on cursor"));
            lines.push(key_line("P", "New prefix-list"));
            lines.push(key_line("C", "New community-list"));
            lines.push(key_line("h", "History"));
            lines.push(key_line("/", "Filter"));
        }
        ActiveTab::Logs => {
            lines.push(key_line("/", "Filter"));
        }
        ActiveTab::Routers => {
            lines.push(key_line("Enter", "Edit router"));
            lines.push(key_line("a", "Add router"));
            lines.push(key_line("d", "Delete router"));
        }
        ActiveTab::ConnLog => {
            lines.push(key_line("/", "Filter"));
        }
    }

    let height = (lines.len() as u16 + 3).min(f.area().height.saturating_sub(4));
    let width = 50u16.min(f.area().width.saturating_sub(4));
    let area = centered_popup(width, height, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_SELECTED))
        .title(Span::styled(
            " Keyboard Shortcuts (press any key to close) ",
            Style::default()
                .fg(C_SELECTED)
                .add_modifier(Modifier::BOLD),
        ));

    let para = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

fn key_line<'a>(key: &'a str, desc: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("  {key:<20}"),
            Style::default()
                .fg(C_SELECTED)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(desc, Style::default().fg(C_DIM)),
    ])
}

fn centered_popup(width: u16, height: u16, r: Rect) -> Rect {
    let v_pad = r.height.saturating_sub(height) / 2;
    let h_pad = r.width.saturating_sub(width) / 2;
    Rect {
        x: r.x + h_pad,
        y: r.y + v_pad,
        width: width.min(r.width),
        height: height.min(r.height),
    }
}
