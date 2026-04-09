use crate::router::{RouterConfig, RouterVendor};

/// Extract route-map name from a config line like "  neighbor X route-map NAME in".
pub fn extract_routemap_name_from_line(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let pos = parts.iter().position(|&p| p == "route-map")?;
    parts.get(pos + 1).map(|s| s.to_string())
}

pub fn extract_prefixlist_name_from_line(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let pos = parts.iter().position(|&p| p == "prefix-list")?;
    parts
        .get(pos + 1)
        .map(|s| s.trim_end_matches(':').to_string())
}

pub fn editor_field_value(r: &RouterConfig, field: usize) -> String {
    match field {
        0 => r.name.clone(),
        1 => r.hostname.clone(),
        2 => r.ssh_port.to_string(),
        3 => r.username.clone(),
        4 => r.password.clone().unwrap_or_default(),
        5 => r.vendor.to_string(),
        6 => r.vdom.clone().unwrap_or_default(),
        _ => String::new(),
    }
}

pub fn apply_buf_to_draft(draft: &mut RouterConfig, field: usize, buf: &str) {
    match field {
        0 => draft.name = buf.to_string(),
        1 => draft.hostname = buf.to_string(),
        2 => draft.ssh_port = buf.parse().unwrap_or(22),
        3 => draft.username = buf.to_string(),
        4 => {
            draft.password = if buf.is_empty() {
                None
            } else {
                Some(buf.to_string())
            }
        }
        5 => {
            draft.vendor = match buf.to_lowercase().as_str() {
                "vyos" => RouterVendor::VyOs,
                "citrixvpx" | "citrix" => RouterVendor::CitrixVpx,
                "pfsense" => RouterVendor::PfSense,
                "fortigate" => RouterVendor::FortiGate,
                "a10" => RouterVendor::A10,
                _ => RouterVendor::Cisco,
            }
        }
        6 => {
            draft.vdom = if buf.is_empty() {
                None
            } else {
                Some(buf.to_string())
            }
        }
        _ => {}
    }
}

pub(crate) fn truncate_error(s: &str, max: usize) -> String {
    let line = s.lines().next().unwrap_or(s);
    if line.len() <= max {
        line.to_string()
    } else {
        format!("{}…", &line[..max])
    }
}
