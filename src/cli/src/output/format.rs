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
