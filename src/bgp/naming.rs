/// Policy object names derived from a BGP neighbor's description field.
///
/// Convention: uppercase, non-alphanumeric characters replaced with dashes,
/// consecutive dashes collapsed, leading/trailing dashes trimmed.
#[derive(Debug, Clone)]
pub struct PolicyNames {
    pub rm_in: String,
    pub rm_out: String,
    pub pl_in: String,
    pub pl_out: String,
}

pub fn sanitize_description(desc: &str) -> String {
    let upper = desc.trim().to_uppercase();
    let mut result = String::with_capacity(upper.len());
    let mut prev_dash = true; // avoid leading dash
    for c in upper.chars() {
        if c.is_ascii_alphanumeric() {
            result.push(c);
            prev_dash = false;
        } else if !prev_dash {
            result.push('-');
            prev_dash = true;
        }
    }
    result.trim_end_matches('-').to_string()
}

pub fn generate_policy_names(description: &str) -> PolicyNames {
    let tag = sanitize_description(description);
    PolicyNames {
        rm_in: format!("RM-{tag}-IN"),
        rm_out: format!("RM-{tag}-OUT"),
        pl_in: format!("PL-{tag}-IN"),
        pl_out: format!("PL-{tag}-OUT"),
    }
}

/// Cumulus policies are scoped to the exact neighbor identifier so two peers
/// with the same description cannot inherit each other's permit rules.
pub fn generate_cumulus_policy_names(description: &str, neighbor_id: &str) -> PolicyNames {
    let tag = sanitize_description(description);
    let short_tag: String = tag.chars().take(24).collect();
    let id_hex: String = neighbor_id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    generate_policy_names(&format!("{short_tag}-{id_hex}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_naming() {
        let names = generate_policy_names("Transit ISP1");
        assert_eq!(names.rm_in, "RM-TRANSIT-ISP1-IN");
        assert_eq!(names.rm_out, "RM-TRANSIT-ISP1-OUT");
        assert_eq!(names.pl_in, "PL-TRANSIT-ISP1-IN");
        assert_eq!(names.pl_out, "PL-TRANSIT-ISP1-OUT");
    }

    #[test]
    fn special_chars() {
        let names = generate_policy_names("  peer--core_01.lab  ");
        assert_eq!(names.rm_in, "RM-PEER-CORE-01-LAB-IN");
    }

    #[test]
    fn already_upper() {
        let names = generate_policy_names("UPSTREAM-PROVIDER");
        assert_eq!(names.rm_in, "RM-UPSTREAM-PROVIDER-IN");
    }

    #[test]
    fn cumulus_policy_names_are_neighbor_specific() {
        let first = generate_cumulus_policy_names("Spine", "swp51");
        let second = generate_cumulus_policy_names("Spine", "swp52");
        assert_ne!(first.rm_in, second.rm_in);
        assert_eq!(
            first.rm_in,
            generate_cumulus_policy_names("Spine", "swp51").rm_in
        );
    }
}
