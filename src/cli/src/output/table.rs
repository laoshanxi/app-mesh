use appmesh::Application;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use super::format::{human_readable_duration, human_readable_size};

const COLUMN_PADDING: usize = 2;

struct Column {
    title: &'static str,
    width: usize,
}

fn format_status(app: &Application) -> String {
    match app.status {
        Some(1) => "enabled".to_string(),
        Some(0) => "disabled".to_string(),
        _ => "-".to_string(),
    }
}

fn format_health(app: &Application) -> String {
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
        app.owner.clone().unwrap_or_else(|| "-".to_string()),
        format_status(app),
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
    "ID", "NAME", "OWNER", "STATUS", "HEALTH", "PID", "USER", "MEMORY", "%CPU", "RETURN", "AGE",
    "DURATION", "STARTS", "COMMAND",
];

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
            let needed = cell.len() + COLUMN_PADDING;
            if needed > col.width {
                col.width = needed;
            }
        }
    }

    // Determine terminal width
    let term_width = if long_mode {
        usize::MAX
    } else {
        terminal_size::terminal_size()
            .map(|(w, _)| w.0 as usize)
            .unwrap_or(80)
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
            if cell.len() > max_len {
                let truncated = format!("{}*", &cell[..max_len.saturating_sub(1)]);
                write!(out, "{:<width$}", truncated, width = col.width).ok();
            } else {
                write!(out, "{:<width$}", cell, width = col.width).ok();
            }
        }
        if cmd_width > 0 {
            let cmd = &row[col_count - 1];
            if cmd.len() > cmd_width && !long_mode {
                // Truncate command with * suffix
                let truncated = format!("{}*", &cmd[..cmd_width.saturating_sub(1)]);
                write!(out, "{}", truncated).ok();
            } else {
                write!(out, "{}", cmd).ok();
            }
        }
        writeln!(out).ok();
    }

    out.flush().ok();
}
