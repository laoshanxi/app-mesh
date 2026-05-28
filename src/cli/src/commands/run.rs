use anyhow::{bail, Context, Result};
use appmesh::{Application, AppMeshClient, ExitAction};
use std::sync::Arc;

use crate::app::{Cli, ExecArgs, RunArgs, ShellArgs};
use crate::client::build_client_with_auth;
use crate::util::{config, parse, signal};

pub async fn run(cli: &Cli, args: &RunArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    if args.app.is_none() && args.cmd.is_none() {
        bail!("The 'run' command requires either '--app' or '--cmd'.");
    }

    // Build Application — only set name if user specified -a (C++ behavior)
    let mut app = Application::default();
    app.behavior = Some(appmesh::Behavior {
        exit: Some(ExitAction::Remove),
        control: None,
    });

    if let Some(ref name) = args.app {
        app.name = Some(name.clone());
    }
    if let Some(ref cmd) = args.cmd {
        app.command = Some(cmd.clone());
    }
    if let Some(ref desc) = args.description {
        app.description = Some(desc.clone());
    }
    if let Some(ref dir) = args.working_dir {
        app.working_dir = Some(dir.clone());
    }
    app.shell = Some(args.shell);
    app.session_login = Some(args.session_login);

    if let Some(ref meta) = args.metadata {
        app.metadata = Some(parse::parse_metadata(meta)?);
    }

    if !args.env.is_empty() {
        let mut envs = std::collections::HashMap::new();
        for env_str in &args.env {
            if let Some((k, v)) = env_str.split_once('=') {
                envs.insert(k.to_string(), v.to_string());
            } else {
                bail!("Invalid environment variable format: {}", env_str);
            }
        }
        app.env = Some(envs);
    }

    let timeout = AppMeshClient::parse_duration(&args.timeout)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let lifecycle = AppMeshClient::parse_duration(&args.lifetime)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // When the user named the run, clean up the transient app on Ctrl+C (matches C++).
    if let Some(ref name) = args.app {
        signal::register_cleanup(client.clone(), name.clone());
    }

    if timeout < 0 {
        let (exit_code, output) = client
            .run_app_sync(&app, timeout.abs(), lifecycle)
            .await
            .context("Sync run failed")?;
        if !output.is_empty() {
            print!("{}", output);
        }
        signal::clear_cleanup();
        return Ok(parse::normalize_exit_code(exit_code));
    }

    // Async mode: subscribe + run + wait
    let (app_run, exit_code) = client
        .run_and_wait(&app, timeout, lifecycle, appmesh::print_output_handler(), timeout)
        .await
        .context("Run failed")?;

    // Best-effort delete if run_and_wait didn't already clean up
    if exit_code.is_none() || exit_code == Some(-2) {
        let _ = client.delete_app(&app_run.app_name).await;
    }

    signal::clear_cleanup();
    Ok(parse::normalize_exit_code(exit_code))
}

pub async fn exec(cli: &Cli, args: &ExecArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    let command = args.command.join(" ");
    if command.is_empty() {
        bail!("The 'exec' command requires a command to execute.");
    }

    let app_name = derive_exec_app_name(&client).await;

    // Clean up any existing session
    let _ = client.delete_app(&app_name).await;

    let timeout = AppMeshClient::parse_duration(&args.timeout)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let lifecycle = AppMeshClient::parse_duration(&args.lifetime)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    signal::register_cleanup(client.clone(), app_name.clone());

    loop {
        let app = build_exec_app(&app_name, &command, args.session_login, &args.env);

        let (_app_run, exit_code) = client
            .run_and_wait(&app, timeout, lifecycle, appmesh::print_output_handler(), timeout)
            .await
            .context("Exec failed")?;

        let return_code = parse::normalize_exit_code(exit_code);
        if !args.retry || return_code == 0 {
            signal::clear_cleanup();
            return Ok(return_code);
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

pub async fn shell(cli: &Cli, args: &ShellArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    let app_name = derive_exec_app_name(&client).await;

    let _ = client.delete_app(&app_name).await;

    let timeout = AppMeshClient::parse_duration(&args.timeout)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let lifecycle = AppMeshClient::parse_duration(&args.lifetime)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Show connection info (matching C++ format, stdout)
    let user_info = client.get_current_user().await.ok();
    let exec_user = user_info
        .as_ref()
        .and_then(|v| v["exec_user"].as_str())
        .unwrap_or("unknown");
    let appmesh_user = user_info
        .as_ref()
        .and_then(|v| v["name"].as_str())
        .unwrap_or("unknown");
    let url = crate::client::get_current_url(cli);
    println!(
        "Connected to <{}@{}> as exec user <{}>",
        appmesh_user, url, exec_user
    );

    let history_path = config::shell_history_path();
    let mut rl = rustyline::DefaultEditor::new().context("Failed to initialize readline")?;
    let _ = rl.load_history(&history_path);

    let mut return_code = 0i32;

    // Execute initial command if provided
    if !args.command.is_empty() {
        let initial_cmd = args.command.join(" ");
        return_code =
            execute_shell_command(&client, &app_name, &initial_cmd, args, timeout, lifecycle)
                .await
                .unwrap_or(1);
    }

    loop {
        match rl.readline("appmesh> ") {
            Ok(line) => {
                let cmd = line.trim();
                if cmd.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(cmd);

                match cmd {
                    "exit" | "q" => break,
                    "clear" | "cls" => {
                        print!("\x1B[2J\x1B[1;1H");
                        std::io::Write::flush(&mut std::io::stdout()).ok();
                        continue;
                    }
                    _ => {}
                }

                return_code =
                    execute_shell_command(&client, &app_name, cmd, args, timeout, lifecycle)
                        .await
                        .unwrap_or(1);
            }
            Err(rustyline::error::ReadlineError::Interrupted) => continue,
            Err(rustyline::error::ReadlineError::Eof) => {
                eprintln!("End of input (Ctrl+D pressed)");
                break;
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                break;
            }
        }
    }

    let _ = rl.save_history(&history_path);
    let _ = client.delete_app(&app_name).await;
    Ok(return_code)
}

async fn execute_shell_command(
    client: &Arc<appmesh::AppMeshClientWSS>,
    app_name: &str,
    command: &str,
    args: &ShellArgs,
    timeout: i32,
    lifecycle: i32,
) -> Result<i32> {
    let app = build_exec_app(app_name, command, args.session_login, &args.env);

    // On Ctrl+C, delete the app so the in-flight run observes REMOVED and returns
    // cleanly (unsubscribing itself); the shell then drops back to the prompt instead
    // of exiting the whole session. A background watcher does the delete so run_and_wait
    // is never cancelled mid-flight (which would leak its subscription). The delete is
    // bounded so a stuck connection can't wedge the prompt.
    let watcher = {
        let client = Arc::clone(client);
        let app_name = app_name.to_string();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    client.delete_app(&app_name),
                )
                .await;
            }
        })
    };

    let result = client
        .run_and_wait(&app, timeout, lifecycle, appmesh::print_output_handler(), timeout)
        .await;
    watcher.abort();

    let (_app_run, exit_code) = result.context("Shell command failed")?;
    Ok(parse::normalize_exit_code(exit_code))
}

fn build_exec_app(
    app_name: &str,
    command: &str,
    session_login: bool,
    extra_env: &[String],
) -> Application {
    let mut builder = Application::builder(app_name)
        .command(command)
        .shell(true)
        .description("App Mesh exec environment")
        .exit_behavior(ExitAction::Remove);

    if session_login {
        builder = builder.session_login(true);
    }

    // Forward current working directory
    if let Ok(cwd) = std::env::current_dir() {
        builder = builder.working_dir(&cwd.to_string_lossy());
    }

    // Forward ALL current environment variables (matching C++ behavior)
    for (key, value) in std::env::vars() {
        builder = builder.env(&key, &value);
    }

    // Override with user-specified env vars
    for env_str in extra_env {
        if let Some((k, v)) = env_str.split_once('=') {
            builder = builder.env(k, v);
        }
    }

    builder.build()
}

async fn derive_exec_app_name(client: &appmesh::AppMeshClientWSS) -> String {
    let appmesh_user = client
        .get_current_user()
        .await
        .ok()
        .and_then(|v| v["name"].as_str().map(String::from))
        .unwrap_or_else(|| "unknown".to_string());

    let os_user = get_os_username();
    let bash_pid = get_shell_pid();

    format!("{}_{}_{}", appmesh_user, os_user, bash_pid)
}

fn get_os_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".to_string())
}

/// Walk up the process tree to find the nearest shell (bash, sh, etc.)
/// Falls back to current PID if no shell found.
fn get_shell_pid() -> u32 {
    // VSCode integrated terminal reuses the same bash process
    if std::env::var("VSCODE_PID").is_ok() {
        return std::process::id();
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(pid) = find_shell_pid_linux() {
            return pid;
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(pid) = find_shell_pid_macos() {
            return pid;
        }
    }

    std::process::id()
}

#[cfg(target_os = "linux")]
fn find_shell_pid_linux() -> Option<u32> {
    let mut ppid = get_ppid()?;
    while ppid > 1 {
        let comm = std::fs::read_to_string(format!("/proc/{}/comm", ppid)).ok()?;
        if is_shell_process(comm.trim()) {
            return Some(ppid);
        }
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", ppid)).ok()?;
        let after_paren = stat.find(')')?.checked_add(2)?;
        let fields: Vec<&str> = stat[after_paren..].split_whitespace().collect();
        ppid = fields.get(1)?.parse().ok()?;
    }
    Some(ppid)
}

#[cfg(target_os = "macos")]
fn find_shell_pid_macos() -> Option<u32> {
    let mut ppid = get_ppid()?;
    while ppid > 1 {
        let output = std::process::Command::new("ps")
            .args(["-p", &ppid.to_string(), "-o", "comm="])
            .output()
            .ok()?;
        let comm = String::from_utf8_lossy(&output.stdout);
        let name = comm.trim().rsplit('/').next().unwrap_or("");
        if is_shell_process(name) {
            return Some(ppid);
        }
        let output = std::process::Command::new("ps")
            .args(["-p", &ppid.to_string(), "-o", "ppid="])
            .output()
            .ok()?;
        ppid = String::from_utf8_lossy(&output.stdout).trim().parse().ok()?;
    }
    Some(ppid)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn get_ppid() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", std::process::id())).ok()?;
        let after_paren = stat.find(')')?.checked_add(2)?;
        let fields: Vec<&str> = stat[after_paren..].split_whitespace().collect();
        fields.get(1)?.parse().ok()
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ps")
            .args(["-p", &std::process::id().to_string(), "-o", "ppid="])
            .output()
            .ok()?;
        String::from_utf8_lossy(&output.stdout).trim().parse().ok()
    }
}

#[cfg(unix)]
fn is_shell_process(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "bash" | "sh" | "dash" | "zsh" | "fish" | "cmd.exe" | "powershell.exe" | "pwsh.exe"
    )
}

