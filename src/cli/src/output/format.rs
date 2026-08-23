use anyhow::Result;
use serde_json::Value;

pub fn print_json(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub fn print_yaml(value: &Value) -> Result<()> {
    print!("{}", serde_yaml::to_string(value)?);
    Ok(())
}

pub fn human_readable_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "Ki", "Mi", "Gi", "Ti"];
    let mut size = bytes as f64;
    for unit in UNITS {
        if size < 1024.0 {
            return if *unit == "B" {
                format!("{}{}", size as u64, unit)
            } else {
                format!("{:.1}{}", size, unit)
            };
        }
        size /= 1024.0;
    }
    format!("{:.1}Pi", size)
}

/// Compact form of an immutable Principal ID for table columns. A full OIDC
/// principal (`oidc:<64 hex chars>`) is unreadable and overflows narrow columns,
/// so keep the prefix plus the first 12 hex chars; short principals such as
/// `system:appmesh` are shown as-is. The full ID stays visible in `view -a`.
pub fn short_principal(principal: &str) -> String {
    const HEX_DIGITS: usize = 12;
    match principal.strip_prefix("oidc:") {
        Some(hex) if hex.len() > HEX_DIGITS => match hex.get(..HEX_DIGITS) {
            Some(prefix) => format!("oidc:{}", prefix),
            None => principal.to_string(),
        },
        _ => principal.to_string(),
    }
}

pub fn human_readable_duration(seconds: u64) -> String {
    if seconds < 60 {
        return format!("{}s", seconds);
    }
    if seconds < 3600 {
        return format!("{}m", seconds / 60);
    }
    if seconds < 86400 {
        let h = seconds / 3600;
        let m = (seconds % 3600) / 60;
        if m > 0 {
            return format!("{}h{}m", h, m);
        }
        return format!("{}h", h);
    }
    let d = seconds / 86400;
    let h = (seconds % 86400) / 3600;
    if h > 0 {
        return format!("{}d{}h", d, h);
    }
    format!("{}d", d)
}

#[cfg(test)]
mod tests {
    use super::short_principal;

    #[test]
    fn short_principal_truncates_oidc_hash() {
        // Owner columns must stay narrow: a full 64-hex OIDC principal collapses
        // to its prefix plus 12 hex chars while remaining unambiguous next to
        // other owners in the same table.
        let full = format!("oidc:3f9a2b71c0d4{}", "0".repeat(52));
        assert_eq!(short_principal(&full), "oidc:3f9a2b71c0d4");
    }

    #[test]
    fn short_principal_keeps_short_ids_as_is() {
        assert_eq!(short_principal("system:appmesh"), "system:appmesh");
        // An oidc: principal whose hash is already short is not mangled.
        assert_eq!(short_principal("oidc:abc"), "oidc:abc");
    }
}
