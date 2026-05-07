use anyhow::{bail, Context, Result};

pub fn parse_metadata(meta: &str) -> Result<serde_json::Value> {
    if let Some(file_path) = meta.strip_prefix('@') {
        if !std::path::Path::new(file_path).exists() {
            bail!("Input file '{}' does not exist", file_path);
        }
        let content =
            std::fs::read_to_string(file_path).context("Failed to read metadata file")?;
        return Ok(
            serde_json::from_str(&content).unwrap_or(serde_json::Value::String(content)),
        );
    }
    Ok(serde_json::from_str(meta).unwrap_or(serde_json::Value::String(meta.to_string())))
}

pub fn normalize_exit_code(code: Option<i32>) -> i32 {
    match code {
        Some(c) if c >= 0 => c,
        Some(_) => 1,
        None => 124,
    }
}
