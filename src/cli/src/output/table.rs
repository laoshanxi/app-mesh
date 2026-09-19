use appmesh::Application;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use super::format::{
    display_width, human_readable_duration, human_readable_size, principal_display, truncate_with_marker,
};

const COLUMN_PADDING: usize = 2;

/// `{:<width$}` pads by character count; pad by display width instead so CJK
/// cells (2 columns per character) line up with ASCII columns.
fn write_cell(out: &mut impl Write, cell: &str, width: usize) {
    write!(out, "{}{}", cell, " ".repeat(width.saturating_sub(display_width(cell)))).ok();
}

struct Column {
    title: &'static str,
    width: usize,
}

fn format_enabled(app: &Application) -> String {
    match app.enabled {
        Some(true) => "Yes".to_string(),
        _ => "-".to_string(),
    }
}

fn format_health(app: &Application) -> String {
    // A gated app that is not running: show why. A running app stays OK/-
    // even when a dependency is down (the gate only holds the next start).
    if app.pid.is_none() && app.waiting_for.as_ref().is_some_and(|w| !w.is_empty()) {
        return "waiting".to_string();
    }
    match app.health {
        Some(0) => "OK".to_string(),
        _ => "-".to_string(),
    }
}

fn format_age(register_time: Option<u64>) -> String {
    let Some(reg) = register_time else {
        return "-".to_string();
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now > reg {
        human_readable_duration(now - reg)
    } else {
        "-".to_string()
    }
}

fn format_duration(app: &Application) -> String {
    let Some(start) = app.last_start_time else {
        return "-".to_string();
    };
    // Only show duration if process is running (has pid)
    if app.pid.is_none() && app.last_exit_time.is_none() {
        return "-".to_string();
    }
    let end = app.last_exit_time.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });
    if end >= start {
        human_readable_duration(end - start)
    } else {
        "-".to_string()
    }
}

fn format_row(i: usize, app: &Application) -> Vec<String> {
    vec![
        i.to_string(),
        app.name.clone().unwrap_or_default(),
        app.owner_principal_id
            .as_deref()
            .map(|principal| principal_display(principal, app.owner_display_name.as_deref()))
            .unwrap_or_else(|| "-".to_string()),
        format_enabled(app),
        format_health(app),
        app.pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string()),
        app.user.clone().unwrap_or_else(|| "-".to_string()),
        app.memory
            .map(human_readable_size)
            .unwrap_or_else(|| "-".to_string()),
        app.cpu
            .map(|c| format!("{:.0}", c))
            .unwrap_or_else(|| "-".to_string()),
        app.return_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".to_string()),
        format_age(app.register_time),
        format_duration(app),
        app.starts
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".to_string()),
        app.command.clone().unwrap_or_default(),
    ]
}

const TITLES: [&str; 14] = [
    "ID", "NAME", "OWNER", "ENABLED", "HEALTH", "PID", "USER", "MEMORY", "%CPU", "RETURN", "AGE",
    "DURATION", "STARTS", "COMMAND",
];

/// Terminal width budget for the table. One column stays free: conhost (the
/// classic Windows console) wraps as soon as the last column is written — no
/// deferred wrap — so a full-width row plus its newline double-spaces. Other
/// terminals only lose one COMMAND column.
fn table_width(detected: Option<u16>) -> usize {
    let columns = detected.unwrap_or(80) as usize;
    columns.saturating_sub(1)
}

pub fn print_apps(apps: &[Application], long_mode: bool) {
    if apps.is_empty() {
        eprintln!("No applications found.");
        return;
    }

    // Build row data
    let rows: Vec<Vec<String>> = apps
        .iter()
        .enumerate()
        .map(|(i, app)| format_row(i, app))
        .collect();

    // Calculate column widths (excluding COMMAND which is last)
    let col_count = TITLES.len();
    let mut columns: Vec<Column> = TITLES
        .iter()
        .map(|t| Column {
            title: t,
            width: t.len() + COLUMN_PADDING,
        })
        .collect();
    // COMMAND column: no initial padding
    columns[col_count - 1].width = TITLES[col_count - 1].len();

    // Widen columns based on actual data (excluding COMMAND)
    for row in &rows {
        for (col, cell) in columns.iter_mut().zip(row.iter()).take(col_count - 1) {
            let needed = display_width(cell) + COLUMN_PADDING;
            if needed > col.width {
                col.width = needed;
            }
        }
    }

    // Determine terminal width
    let term_width = if long_mode {
        usize::MAX
    } else {
        table_width(terminal_size::terminal_size().map(|(w, _)| w.0))
    };

    // Determine how many columns (excluding COMMAND) fit
    let mut total_width = 0usize;
    let mut visible_cols = 0usize;
    for col in columns.iter().take(col_count - 1) {
        if total_width + col.width <= term_width {
            total_width += col.width;
            visible_cols += 1;
        } else {
            break;
        }
    }

    // COMMAND column gets remaining space
    let cmd_width = if total_width + columns[col_count - 1].width < term_width {
        term_width.saturating_sub(total_width)
    } else {
        0
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    // Print header
    for col in columns.iter().take(visible_cols) {
        write!(out, "{:<width$}", col.title, width = col.width).ok();
    }
    if cmd_width > 0 {
        write!(out, "{}", columns[col_count - 1].title).ok();
    }
    writeln!(out).ok();

    // Print rows
    for row in &rows {
        for (col, cell) in columns.iter().zip(row.iter()).take(visible_cols) {
            let max_len = col.width.saturating_sub(COLUMN_PADDING);
            if display_width(cell) > max_len {
                write_cell(&mut out, &truncate_with_marker(cell, max_len), col.width);
            } else {
                write_cell(&mut out, cell, col.width);
            }
        }
        if cmd_width > 0 {
            let cmd = &row[col_count - 1];
            if display_width(cmd) > cmd_width && !long_mode {
                // Truncate command with * suffix
                let truncated = truncate_with_marker(cmd, cmd_width);
                write!(out, "{}", truncated).ok();
            } else {
                write!(out, "{}", cmd).ok();
            }
        }
        writeln!(out).ok();
    }

    out.flush().ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_padding_uses_display_width() {
        // "所有" occupies 4 columns, so a 6-column cell needs 2 padding spaces —
        // char-count padding would print 4 and misalign the next column.
        let mut buf: Vec<u8> = Vec::new();
        write_cell(&mut buf, "所有", 6);
        write_cell(&mut buf, "abc", 6);
        assert_eq!(String::from_utf8(buf).unwrap(), "所有  abc   ");
    }

    #[test]
    fn table_width_keeps_one_column_free() {
        // conhost wraps a line that fills the last column (no deferred wrap),
        // so the table must never budget the full reported width.
        assert_eq!(table_width(Some(120)), 119);
        assert_eq!(table_width(None), 79);
        assert_eq!(table_width(Some(1)), 0);
    }
}
