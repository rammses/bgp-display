use std::collections::HashMap;

// ─── Route-map detail ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct RouteMapEntry {
    pub sequence: u32,
    pub action: String, // "permit" | "deny"
    pub match_clauses: Vec<String>,
    pub set_clauses: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PrefixListEntry {
    #[allow(dead_code)]
    pub seq: u32,
    pub action: String,
    pub prefix: String,
}

#[derive(Debug, Clone, Default)]
pub struct CommunityListEntry {
    pub seq: u32,
    pub action: String,
    pub community: String,
}

impl CommunityListEntry {
    pub fn validate(&self) -> Result<(), String> {
        if self.action != "permit" && self.action != "deny" {
            return Err(format!(
                "Action must be 'permit' or 'deny', got '{}'",
                self.action
            ));
        }
        if self.community.trim().is_empty() {
            return Err("Community value is required".into());
        }
        Ok(())
    }
}

impl PrefixListEntry {
    /// Validate a prefix-list entry. Returns Ok(()) or a human-readable error.
    pub fn validate(&self) -> Result<(), String> {
        if self.action != "permit" && self.action != "deny" {
            return Err(format!(
                "Action must be 'permit' or 'deny', got '{}'",
                self.action
            ));
        }

        let parts: Vec<&str> = self.prefix.split_whitespace().collect();
        if parts.is_empty() {
            return Err("Prefix is required".into());
        }

        let cidr = parts[0];
        let (net, bits) = match cidr.split_once('/') {
            Some((n, b)) => (n, b),
            None => return Err(format!("Invalid CIDR: '{cidr}' (expected x.x.x.x/N)")),
        };

        if net.parse::<std::net::Ipv4Addr>().is_err() && net.parse::<std::net::Ipv6Addr>().is_err()
        {
            return Err(format!("Invalid network address: '{net}'"));
        }

        let prefix_len: u8 = bits
            .parse()
            .map_err(|_| format!("Invalid prefix length: '{bits}'"))?;

        let is_v6 = net.contains(':');
        let max_len = if is_v6 { 128 } else { 32 };
        if prefix_len > max_len {
            return Err(format!(
                "Prefix length {prefix_len} exceeds maximum {max_len}"
            ));
        }

        let mut ge: Option<u8> = None;
        let mut le: Option<u8> = None;
        let mut i = 1;
        while i + 1 < parts.len() {
            match parts[i] {
                "ge" => {
                    ge = Some(
                        parts[i + 1]
                            .parse()
                            .map_err(|_| format!("Invalid ge value: '{}'", parts[i + 1]))?,
                    );
                }
                "le" => {
                    le = Some(
                        parts[i + 1]
                            .parse()
                            .map_err(|_| format!("Invalid le value: '{}'", parts[i + 1]))?,
                    );
                }
                _ => {}
            }
            i += 2;
        }

        if let Some(g) = ge {
            if g < prefix_len {
                return Err(format!("ge ({g}) must be >= prefix length ({prefix_len})"));
            }
            if g > max_len {
                return Err(format!("ge ({g}) exceeds maximum {max_len}"));
            }
        }
        if let Some(l) = le {
            if l > max_len {
                return Err(format!("le ({l}) exceeds maximum {max_len}"));
            }
            if l < prefix_len {
                return Err(format!("le ({l}) must be >= prefix length ({prefix_len})"));
            }
        }
        if let (Some(g), Some(l)) = (ge, le) {
            if g > l {
                return Err(format!("ge ({g}) must be <= le ({l})"));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct RouteMapDetail {
    pub name: String,
    pub entries: Vec<RouteMapEntry>,
    /// prefix-list name → entries
    pub prefix_lists: HashMap<String, Vec<PrefixListEntry>>,
    /// community-list name → raw permit/deny lines
    pub community_lists: HashMap<String, Vec<String>>,
}
