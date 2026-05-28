use anyhow::{bail, Context, Result};
use appmesh::{AppEvent, Application, AppMeshClient, ExitAction};
use std::io::{self, Read, Write};
use std::sync::Arc;

use crate::app::{AddArgs, Cli, DisableArgs, EnableArgs, RestartArgs, RmArgs, ViewArgs};
use crate::client::build_client_with_auth;
use crate::output::{format, table};
use crate::util::{confirm, parse};

pub async fn add(cli: &Cli, args: &AddArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    let app = if let Some(ref stdin_src) = args.stdin {
        read_app_from_stdin(stdin_src)?
    } else {
        if args.app.is_none()
            && args.docker_image.is_none()
            && args.cmd.is_none()
        {
            bail!("Application name (-a) and command (-c) or docker image (-I) are required.");
        }
        build_app_from_args(args)?
    };

    let app_name = app.name.as_deref().unwrap_or("unknown");

    // Only prompt when app already exists (matching C++ behavior)
    let app_exists = client.get_app(app_name).await.is_ok();
    if app_exists
        && !args.force
        && (args.stdin.as_deref() != Some("std"))
        && !confirm::confirm(&format!(
            "Application already exists, are you sure you want to update the application <{}>?",
            app_name
        ))
    {
        return Ok(0);
    }

    // Validate interval > stop_timeout
    if args.interval.is_some() && args.stop_timeout.is_some() {
        let interval = AppMeshClient::parse_duration(args.interval.as_deref().unwrap())
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let stop_timeout = AppMeshClient::parse_duration(args.stop_timeout.as_deref().unwrap())
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        if interval <= stop_timeout {
            bail!("The stop-timeout must be less than the interval.");
        }
    }

    let result = client.add_app(&app, None).await.context("Failed to add application")?;
    let json = serde_json::to_value(&result)?;
    format::print_yaml(&json)?;
    Ok(0)
}

fn read_app_from_stdin(source: &str) -> Result<Application> {
    let content = if source == "std" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        let path = source.strip_prefix('@').unwrap_or(source);
        std::fs::read_to_string(path).context("Failed to read input file")?
    };

    let yaml: serde_json::Value = serde_yaml::from_str(&content).context("Invalid YAML input")?;
    let app: Application = serde_json::from_value(yaml).context("Invalid application definition")?;
    Ok(app)
}

fn build_app_from_args(args: &AddArgs) -> Result<Application> {
    let name = args
        .app
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Application name is required"))?;
    let mut builder = Application::builder(name);

    if let Some(ref cmd) = args.cmd {
        builder = builder.command(cmd);
    }
    if let Some(ref desc) = args.description {
        builder = builder.description(desc);
    }
    if let Some(ref dir) = args.working_dir {
        builder = builder.working_dir(dir);
    }
    // Always set shell and session_login (C++ always sends false/true)
    builder = builder.shell(args.shell);
    builder = builder.session_login(args.session_login);
    if let Some(ref hc) = args.health_check {
        builder = builder.health_check_cmd(hc);
    }
    if let Some(ref img) = args.docker_image {
        builder = builder.docker_image(img);
    }
    if let Some(num) = args.log_cache_size {
        builder = builder.stdout_cache_num(num);
    }

    // Schedule: interval — store raw string for cron, parsed seconds for duration
    if let Some(ref interval) = args.interval {
        if args.cron {
            builder = builder.cron(true);
        } else {
            AppMeshClient::parse_duration(interval)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
        }
        builder = builder.start_interval_seconds(interval);
    }

    if let Some(ref retention) = args.stop_timeout {
        builder = builder.retention(retention);
    }

    // Exit behavior
    if let Some(ref exit_behavior) = args.exit {
        let action = parse_exit_action(exit_behavior)?;
        builder = builder.exit_behavior(action);
    }
    for ctrl in &args.control {
        let (code, action) = parse_control(ctrl)?;
        builder = builder.control_behavior(code, action);
    }

    // Metadata
    if let Some(ref meta) = args.metadata {
        let val = parse::parse_metadata(meta)?;
        builder = builder.metadata(val);
    }

    // Environment variables
    for env_str in &args.env {
        if let Some((k, v)) = env_str.split_once('=') {
            builder = builder.env(k, v);
        } else {
            bail!("Invalid environment variable format: {}", env_str);
        }
    }
    for env_str in &args.security_env {
        if let Some((k, v)) = env_str.split_once('=') {
            builder = builder.sec_env(k, v);
        } else {
            bail!("Invalid environment variable format: {}", env_str);
        }
    }

    // Resource limits
    if args.memory_limit.is_some() || args.virtual_memory.is_some() || args.cpu_shares.is_some() {
        builder = builder.resource_limit(args.cpu_shares, args.memory_limit, args.virtual_memory);
    }

    // Daily limitation (both required together)
    if args.daily_begin.is_some() && args.daily_end.is_some() {
        let start = parse_daily_time(args.daily_begin.as_deref().unwrap())?;
        let end = parse_daily_time(args.daily_end.as_deref().unwrap())?;
        builder = builder.daily_range(start, end);
    }

    let mut app = builder.build();

    // Fields that need direct assignment on the struct
    if let Some(status) = args.status {
        app.status = Some(u32::from(status));
    }
    if let Some(pid) = args.pid {
        app.pid = Some(pid);
    }
    if let Some(perm) = args.permission {
        app.permission = Some(perm);
    }

    // Begin/end time as epoch seconds
    if let Some(ref begin) = args.begin_time {
        app.start_time = Some(parse_iso8601_datetime(begin)?);
    }
    if let Some(ref end) = args.end_time {
        app.end_time = Some(parse_iso8601_datetime(end)?);
    }

    Ok(app)
}

fn parse_exit_action(s: &str) -> Result<ExitAction> {
    match s.to_lowercase().as_str() {
        "restart" => Ok(ExitAction::Restart),
        "standby" => Ok(ExitAction::Standby),
        "keepalive" => Ok(ExitAction::Keepalive),
        "remove" => Ok(ExitAction::Remove),
        _ => bail!(
            "Invalid behavior '{}' for exit event. Use: restart|standby|keepalive|remove",
            s
        ),
    }
}

fn parse_control(ctrl: &str) -> Result<(i32, ExitAction)> {
    let (code_str, action_str) = ctrl
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("Invalid control format: '{}'. Use CODE:ACTION", ctrl))?;
    let code: i32 = code_str.trim().parse().context("Invalid exit code")?;
    let action = parse_exit_action(action_str.trim())?;
    Ok((code, action))
}

/// Parse an ISO 8601 datetime to epoch seconds. Accepts an explicit offset or
/// `Z` (an absolute instant), a zoneless datetime (interpreted in the system
/// local timezone, matching the C++ CLI), or a bare integer (epoch seconds).
fn parse_iso8601_datetime(s: &str) -> Result<u64> {
    let s = s.trim();
    if let Ok(epoch) = parse_datetime_to_epoch(s) {
        return Ok(epoch.max(0) as u64);
    }
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(secs);
    }
    bail!("Cannot parse datetime '{}'. Use ISO 8601 format: '2020-10-11T09:22:05'", s)
}

/// Convert an ISO 8601 datetime string to a UTC epoch second using `jiff`.
fn parse_datetime_to_epoch(s: &str) -> Result<i64> {
    use std::str::FromStr;
    // An explicit offset (e.g. "+08:00", "+08") or trailing "Z" is an absolute instant.
    if let Ok(ts) = jiff::Timestamp::from_str(s) {
        return Ok(ts.as_second());
    }
    // Otherwise it is zoneless: interpret it in the system local timezone.
    let dt = jiff::civil::DateTime::from_str(s)
        .map_err(|e| anyhow::anyhow!("invalid datetime '{}': {}", s, e))?;
    let zoned = dt
        .to_zoned(jiff::tz::TimeZone::system())
        .map_err(|e| anyhow::anyhow!("invalid datetime '{}': {}", s, e))?;
    Ok(zoned.timestamp().as_second())
}

/// Parse a daily time like "09:00:00+08" or "20:00:00" into seconds-of-day in
/// UTC. An explicit offset is honored; without one the time is interpreted in
/// the system local timezone (matching the C++ CLI's `parseDayTimeUtcDuration`).
fn parse_daily_time(s: &str) -> Result<u64> {
    let s = s.trim();
    // Reuse the datetime parser on a fixed reference date, then take the UTC time-of-day.
    let epoch = parse_datetime_to_epoch(&format!("2000-01-01T{}", s))
        .with_context(|| format!("Invalid daily time format: '{}'", s))?;
    Ok(epoch.rem_euclid(86400) as u64)
}

pub async fn rm(cli: &Cli, args: &RmArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    if !args.force {
        let names = args.app.join(", ");
        if !confirm::confirm(&format!("Remove application(s) '{}'?", names)) {
            return Ok(0);
        }
    }

    for name in &args.app {
        client
            .delete_app(name)
            .await
            .context(format!("Failed to remove '{}'", name))?;
    }
    Ok(0)
}

pub async fn view(cli: &Cli, args: &ViewArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    if let Some(ref app_name) = args.app {
        if args.show_output || args.follow {
            return view_output(&client, app_name, args).await;
        }

        let app = client
            .get_app(app_name)
            .await
            .context("Failed to get application")?;

        if args.pstree {
            if let Some(ref tree) = app.pstree {
                println!("{}", tree);
            }
            return Ok(0);
        }

        let json = serde_json::to_value(&app)?;
        if args.json {
            format::print_json(&json)?;
        } else {
            format::print_yaml(&json)?;
        }
        return Ok(0);
    }

    // List all apps
    let apps = client
        .list_apps()
        .await
        .context("Failed to list applications")?;

    if args.json {
        let json = serde_json::to_value(&apps)?;
        format::print_json(&json)?;
    } else {
        table::print_apps(&apps, args.long);
    }
    Ok(0)
}

async fn view_output(
    client: &Arc<appmesh::AppMeshClientWSS>,
    app_name: &str,
    args: &ViewArgs,
) -> Result<i32> {
    let log_index = args.log_index.unwrap_or(0);

    if !args.follow {
        // One-shot: fetch current output via get_app_output
        let output = client
            .get_app_output(app_name, 0, log_index, 0, None, None)
            .await
            .context("Failed to get output")?;
        if !output.output.is_empty() {
            print!("{}", output.output);
            io::stdout().flush().ok();
        }
        return Ok(0);
    }

    // Follow mode: use subscribe for real-time STDOUT events via WSS
    let (done_tx, done_rx) = tokio::sync::watch::channel(false);
    let done_tx = Arc::new(std::sync::Mutex::new(Some(done_tx)));
    let done_tx_cb = Arc::clone(&done_tx);

    let on_event: appmesh::EventCallback = Arc::new(move |event: AppEvent| {
        match event.event_type.as_str() {
            "STDOUT" => {
                let output = event
                    .data
                    .get("output")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !output.is_empty() {
                    print!("{}", output);
                    io::stdout().flush().ok();
                }
            }
            "EXIT" | "REMOVED" | "__disconnected__" => {
                if let Some(tx) = done_tx_cb.lock().ok().and_then(|mut g| g.take()) {
                    let _ = tx.send(true);
                }
            }
            _ => {}
        }
    });

    let sub = client
        .subscribe(app_name, Some(&["STDOUT", "EXIT", "REMOVED"]), Some(on_event))
        .await
        .context("Failed to subscribe")?;

    // Backfill output emitted before subscribe
    let backfill = client
        .get_app_output(app_name, 0, log_index, 0, None, Some(0))
        .await;
    if let Ok(bf) = backfill {
        if !bf.output.is_empty() {
            print!("{}", bf.output);
            io::stdout().flush().ok();
        }
    }

    let mut done_rx = done_rx;
    let _ = done_rx.wait_for(|v| *v).await;

    let _ = client.unsubscribe(&sub.subscription_id).await;
    Ok(0)
}

pub async fn enable(cli: &Cli, args: &EnableArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    let names = get_app_names(&client, &args.app, args.all).await?;
    if names.is_empty() {
        eprintln!("No applications processed.");
        return Ok(0);
    }
    for name in &names {
        client
            .enable_app(name)
            .await
            .context(format!("Failed to enable '{}'", name))?;
    }
    Ok(0)
}

pub async fn disable(cli: &Cli, args: &DisableArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    let names = get_app_names(&client, &args.app, args.all).await?;
    if names.is_empty() {
        eprintln!("No applications processed.");
        return Ok(0);
    }
    for name in &names {
        client
            .disable_app(name)
            .await
            .context(format!("Failed to disable '{}'", name))?;
    }
    Ok(0)
}

pub async fn restart(cli: &Cli, args: &RestartArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    let names = get_app_names(&client, &args.app, args.all).await?;
    if names.is_empty() {
        eprintln!("No applications processed.");
        return Ok(0);
    }
    for name in &names {
        client
            .disable_app(name)
            .await
            .context(format!("Failed to disable '{}'", name))?;
        client
            .enable_app(name)
            .await
            .context(format!("Failed to enable '{}'", name))?;
    }
    Ok(0)
}

async fn get_app_names(
    client: &appmesh::AppMeshClientWSS,
    explicit: &[String],
    all: bool,
) -> Result<Vec<String>> {
    if all {
        let apps = client.list_apps().await.context("Failed to list apps")?;
        Ok(apps.iter().filter_map(|a| a.name.clone()).collect())
    } else if explicit.is_empty() {
        bail!("No application name specified. Use -a <name> or -A for all.");
    } else {
        Ok(explicit.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datetime_offset_is_absolute() {
        // Explicit offsets / "Z" are absolute instants regardless of the system timezone.
        let utc = parse_iso8601_datetime("2020-10-11T09:22:05Z").unwrap();
        let plus8 = parse_iso8601_datetime("2020-10-11T09:22:05+08:00").unwrap();
        let short = parse_iso8601_datetime("2020-10-11T09:22:05+08").unwrap();
        assert_eq!(utc - plus8, 8 * 3600);
        assert_eq!(plus8, short); // "+08" and "+08:00" are equivalent
    }

    #[test]
    fn datetime_accepts_epoch_seconds() {
        assert_eq!(parse_iso8601_datetime("1602379325").unwrap(), 1602379325);
    }

    #[test]
    fn daily_time_applies_offset_to_utc() {
        // 09:00:00 at +08 == 01:00:00 UTC == 3600s, matching C++ parseDayTimeUtcDuration.
        assert_eq!(parse_daily_time("09:00:00+08").unwrap(), 3600);
        assert_eq!(parse_daily_time("09:00:00+08:00").unwrap(), 3600);
        // Wrap-around: 04:00:00 at +08 == 20:00:00 UTC the previous day.
        assert_eq!(parse_daily_time("04:00:00+08").unwrap(), 20 * 3600);
    }

    #[test]
    fn offsetless_inputs_parse_in_local_zone() {
        // Value depends on the system timezone, but parsing must succeed (civil fallback).
        assert!(parse_iso8601_datetime("2020-10-11T09:22:05").is_ok());
        let d = parse_daily_time("09:00:00").unwrap();
        assert!(d < 86400);
    }
}
