use anyhow::Result;
use serde_json::Value;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

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

/// Terminal columns a string occupies: CJK and other wide characters count 2.
pub fn display_width(text: &str) -> usize {
    text.width()
}

/// Pad with spaces to a display width (CJK-aware). Strings already wider than
/// `width` are returned unchanged, like `{:<width$}` on ASCII text.
pub fn pad_display(text: &str, width: usize) -> String {
    let current = display_width(text);
    if current >= width {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len() + (width - current));
    out.push_str(text);
    for _ in 0..(width - current) {
        out.push(' ');
    }
    out
}

/// Truncate to a display width, marking the cut with `*`. Never splits a
/// character: a wide character that does not fit is dropped whole.
pub fn truncate_with_marker(value: &str, max_width: usize) -> String {
    if display_width(value) <= max_width {
        return value.to_string();
    }
    if max_width == 0 {
        return String::new();
    }
    // Reserve one column for the marker.
    let budget = max_width - 1;
    let mut result = String::new();
    let mut width = 0;
    for ch in value.chars() {
        let ch_width = ch.width().unwrap_or(0);
        if width + ch_width > budget {
            break;
        }
        result.push(ch);
        width += ch_width;
    }
    result.push('*');
    result
}

/// User-facing label for an immutable Principal ID. Display names are mutable
/// presentation data only; callers must keep using the full ID for authorization.
pub fn principal_display(principal: &str, display_name: Option<&str>) -> String {
    const MAX_DISPLAY_CHARS: usize = 24;
    if principal == "system:appmesh" {
        return "system".to_string();
    }
    if let Some(name) = display_name {
        let single_line = name
            .split_whitespace()
            .map(|part| part.chars().filter(|c| !c.is_control()).collect::<String>())
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if !single_line.is_empty() {
            return truncate_with_marker(&single_line, MAX_DISPLAY_CHARS);
        }
    }
    short_principal(principal)
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
    use super::{display_width, principal_display, short_principal, truncate_with_marker};

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

    #[test]
    fn principal_display_prefers_human_labels() {
        assert_eq!(principal_display("system:appmesh", Some("ignored")), "system");
        assert_eq!(principal_display("oidc:abc", Some(" admin\n user ")), "admin user");
        assert_eq!(principal_display("oidc:abc", Some("admin\u{1b}[31m")), "admin[31m");
        assert_eq!(principal_display("oidc:abc", Some("  ")), "oidc:abc");
    }

    #[test]
    fn display_width_counts_cjk_as_two_columns() {
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("所有者"), 6);
        assert_eq!(display_width("a所b"), 4);
    }

    #[test]
    fn truncate_never_splits_a_character_and_fits_the_width() {
        // Each CJK char occupies 2 columns, so a 4-column limit holds one char
        // plus the marker — never half a wide character.
        let truncated = truncate_with_marker("所有者名称", 4);
        assert_eq!(truncated, "所*");
        assert!(display_width(&truncated) <= 4);
    }

    #[test]
    fn truncate_mixed_script_respects_display_width() {
        assert_eq!(truncate_with_marker("ab所有者名称", 5), "ab所*");
        let truncated = truncate_with_marker("ab所有者名称", 3);
        assert_eq!(truncated, "ab*");
        // Short values pass through unchanged.
        assert_eq!(truncate_with_marker("abc", 5), "abc");
        assert_eq!(truncate_with_marker("", 5), "");
    }
}
