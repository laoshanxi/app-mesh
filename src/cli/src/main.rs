mod app;
mod client;
mod commands;
mod output;
mod util;

use anyhow::Result;
use app::{Cli, Commands, WorkflowCommand};
use appmesh::AppMeshError;
use clap::Parser;
use std::process;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider().install_default().ok();
    env_logger::init();

    let cli = Cli::parse();

    if cli.verbose {
        log::set_max_level(log::LevelFilter::Debug);
    }

    let code = match run_with_session_recovery(&cli).await {
        Ok(code) => code,
        Err(e) => {
            let msg = extract_error_message(&e);
            eprintln!("{}", msg);

            if is_error_tolerant_mode(&cli) {
                0
            } else {
                1
            }
        }
    };
    process::exit(code);
}

/// Only output-follow (`view -a <app> -f`) tolerates errors and exits 0 — like
/// `tail -f`, the stream ending is not a CLI failure; `ls -f` watch must not.
/// `--force` (add/rm) only skips the interactive confirmation and must never
/// mask a failed request: scripts rely on the nonzero exit code.
fn is_error_tolerant_mode(cli: &Cli) -> bool {
    match &cli.command {
        Commands::View(args) => args.follow && args.app.is_some(),
        _ => false,
    }
}

/// Run a command once; when a read-only command is rejected with a 401, attempt
/// one token refresh and, if that renewed the session, retry once. A command
/// that changes state is never replayed. A dead refresh grant tears the stored
/// session down and reports the logon hint instead of the bare "401" the
/// command produced.
async fn run_with_session_recovery(cli: &Cli) -> Result<i32> {
    match run(cli).await {
        Err(error) if session_recovery_applies(&cli.command, &error) => {
            match client::recover_session_after_unauthorized(cli).await {
                Ok(true) => run(cli).await,
                Err(session_error) => Err(session_error),
                Ok(false) => Err(error),
            }
        }
        outcome => outcome,
    }
}

/// Whole-command recovery replays the command from the start, so only commands
/// that observe Engine state may use it: replaying a mutation repeats its side
/// effects (a run script executes twice, a task is delivered twice, an upload is
/// written again). Session-lifecycle commands and interactive shell are also
/// excluded — logon must not restart its prompts, and a shell must not start
/// over. When in doubt the command is not replayed.
fn is_read_only_command(command: &Commands) -> bool {
    match command {
        Commands::Loginfo(_)
        | Commands::View(_)
        | Commands::Get(_)
        | Commands::Config(_)
        | Commands::Resource(_)
        | Commands::Metric(_) => true,
        // Workflow queries are task round-trips; only the read actions replay.
        Commands::Workflow(args) => matches!(
            args.command,
            WorkflowCommand::Get(_)
                | WorkflowCommand::List(_)
                | WorkflowCommand::Runs(_)
                | WorkflowCommand::Logs(_)
                | WorkflowCommand::Output(_)
                | WorkflowCommand::Detail(_)
                | WorkflowCommand::Inputs(_)
        ),
        // A bare `label --view` lists; add/delete mutate and must not replay.
        Commands::Label(args) => !args.add && !args.delete,
        // Every other command changes state (logon/logoff, app lifecycle,
        // run/exec/shell/task, file writes, log level, workflow mutations).
        _ => false,
    }
}

fn session_recovery_applies(command: &Commands, error: &anyhow::Error) -> bool {
    is_read_only_command(command) && is_unauthorized(error)
}

/// Only a typed 401 status counts: error text mentioning "401" (server messages,
/// connection errors) must not trigger a token refresh.
fn is_unauthorized(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<AppMeshError>(),
            Some(AppMeshError::RequestFailed { status, .. }) if status.as_u16() == 401
        )
    })
}

async fn run(cli: &Cli) -> Result<i32> {
    match &cli.command {
        Commands::Logon(args) => commands::auth::logon(cli, args).await,
        Commands::Logoff(args) => commands::auth::logoff(cli, args).await,
        Commands::Loginfo(args) => commands::auth::loginfo(cli, args).await,
        Commands::Add(args) => commands::apps::add(cli, args.as_ref()).await,
        Commands::Rm(args) => commands::apps::rm(cli, args).await,
        Commands::View(args) => commands::apps::view(cli, args).await,
        Commands::Enable(args) => commands::apps::enable(cli, args).await,
        Commands::Disable(args) => commands::apps::disable(cli, args).await,
        Commands::Restart(args) => commands::apps::restart(cli, args).await,
        Commands::Run(args) => commands::run::run(cli, args).await,
        Commands::Task(args) => commands::task::task(cli, args).await,
        Commands::Exec(args) => commands::run::exec(cli, args).await,
        Commands::Shell(args) => commands::run::shell(cli, args).await,
        Commands::Get(args) => commands::file::get(cli, args).await,
        Commands::Put(args) => commands::file::put(cli, args).await,
        Commands::Rmfile(args) => commands::file::rmfile(cli, args).await,
        Commands::Label(args) => commands::system::label(cli, args).await,
        Commands::Log(args) => commands::system::log_level(cli, args).await,
        Commands::Config(_) => commands::system::config(cli).await,
        Commands::Resource(_) => commands::system::resource(cli).await,
        Commands::Metric(_) => commands::system::metric(cli).await,
        Commands::Workflow(args) => commands::workflow::workflow(cli, args).await,
    }
}

fn extract_error_message(err: &anyhow::Error) -> String {
    let mut parts = Vec::new();
    for cause in err.chain() {
        let msg = cause.to_string();
        parts.push(extract_json_message(&msg));
    }
    parts.dedup();
    parts.join(": ")
}

/// Extract "message" field from JSON embedded anywhere in the string.
fn extract_json_message(s: &str) -> String {
    // Try the whole string as JSON first
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(s) {
        if let Some(m) = json.get("message").and_then(|v| v.as_str()) {
            return m.to_string();
        }
    }
    // Try to find JSON object embedded in the string (e.g. "prefix: {\"message\":\"...\"}")
    if let Some(start) = s.find('{') {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&s[start..]) {
            if let Some(m) = json.get("message").and_then(|v| v.as_str()) {
                let prefix = s[..start].trim().trim_end_matches(':').trim();
                if prefix.is_empty() {
                    return m.to_string();
                }
                return format!("{}: {}", prefix, m);
            }
        }
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn cli(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("appm").chain(args.iter().copied()))
    }

    #[test]
    fn force_never_suppresses_error_exit_code() {
        // `--force` on add/rm (and their aliases) only skips the interactive
        // confirmation. A failed request must still exit 1 — scripts do
        // `appm add ... -f || die` and rely on the nonzero code.
        for args in [
            vec!["add", "-a", "x", "-c", "y", "--force"],
            vec!["reg", "-a", "x", "-c", "y", "-f"],
            vec!["rm", "-a", "x", "--force"],
            vec!["remove", "-a", "x", "-f"],
            vec!["unreg", "-a", "x", "-f"],
        ] {
            assert!(!is_error_tolerant_mode(&cli(&args)), "{:?} must propagate errors", args);
        }
    }

    #[test]
    fn only_output_follow_tolerates_errors() {
        // `view -a <app> -f` (tail -f-like output follow) tolerates errors;
        // `ls -f` watch mode and non-follow views must not.
        assert!(is_error_tolerant_mode(&cli(&["view", "-a", "x", "-f"])));
        assert!(!is_error_tolerant_mode(&cli(&["ls", "-f"])));
        assert!(!is_error_tolerant_mode(&cli(&["view", "-a", "x"])));
        assert!(!is_error_tolerant_mode(&cli(&["config"])));
    }

    fn unauthorized_status(status: u16) -> AppMeshError {
        AppMeshError::RequestFailed {
            status: http::StatusCode::from_u16(status).expect("valid status"),
            message: "WebSocket connect failed".into(),
        }
    }

    #[test]
    fn only_a_typed_401_status_triggers_recovery() {
        // The 401 may sit anywhere in the context chain.
        let chained = anyhow::Error::new(unauthorized_status(401)).context("Failed to list applications");
        assert!(is_unauthorized(&chained));

        // Another status, or plain text mentioning 401, must not refresh.
        assert!(!is_unauthorized(&anyhow::Error::new(unauthorized_status(403))));
        assert!(!is_unauthorized(&anyhow::Error::new(AppMeshError::ConnectionError(
            "WebSocket connect failed: 401 Unauthorized".into()
        ))));
        assert!(!is_unauthorized(&anyhow::anyhow!("Engine rejected the access token: 401 Unauthorized")));
    }

    #[test]
    fn read_only_commands_may_recover() {
        let err = anyhow::Error::new(unauthorized_status(401));
        // `view`/`view -f` only observe: a replay may reprint output but mutates
        // nothing, so output follow and list watch may recover too.
        for args in [
            vec!["view"],
            vec!["view", "-a", "x", "-f"],
            vec!["view", "-f"],
            vec!["loginfo"],
            vec!["resource"],
            vec!["metric"],
            vec!["config"],
            vec!["get", "-r", "/remote", "-l", "local"],
            vec!["label", "--view"],
            vec!["workflow", "list"],
            vec!["workflow", "get", "wf"],
            vec!["workflow", "runs", "wf"],
            vec!["workflow", "logs", "-w", "wf", "RUN"],
            vec!["workflow", "output", "-w", "wf", "RUN", "-j", "job", "-s", "step"],
            vec!["workflow", "detail", "-w", "wf", "RUN"],
            vec!["workflow", "inputs", "wf"],
        ] {
            assert!(session_recovery_applies(&cli(&args).command, &err), "{:?} may recover", args);
        }
    }

    #[test]
    fn state_changing_commands_never_replay() {
        // A whole-command retry after a 401 would repeat the side effects:
        // `run`/`exec` would execute the script twice, `task` would deliver the
        // payload twice, and the app/file/workflow mutations would apply again.
        let err = anyhow::Error::new(unauthorized_status(401));
        for args in [
            vec!["logon"],
            vec!["logoff"],
            vec!["shell"],
            vec!["exec", "true"],
            vec!["run", "-a", "x", "-c", "true"],
            vec!["task", "app", "payload"],
            vec!["add", "-a", "x", "-c", "y"],
            vec!["rm", "-a", "x"],
            vec!["enable", "-a", "x"],
            vec!["disable", "-a", "x"],
            vec!["restart", "-a", "x"],
            vec!["put", "-r", "/remote", "-l", "local"],
            vec!["rmfile", "-r", "/remote"],
            vec!["log", "-L", "INFO"],
            vec!["label", "-a", "-l", "k=v"],
            vec!["label", "-d", "-l", "k"],
            vec!["workflow", "add", "-f", "wf.yaml"],
            vec!["workflow", "rm", "wf"],
            vec!["workflow", "run", "wf"],
            vec!["workflow", "cancel", "-w", "wf", "RUN"],
            vec!["workflow", "rerun", "-w", "wf", "RUN"],
        ] {
            assert!(!session_recovery_applies(&cli(&args).command, &err), "{:?} must not replay", args);
        }
    }

    #[test]
    fn error_text_mentioning_401_never_recovers() {
        // Even a read-only command must not replay on plain text that happens to
        // contain "401"; only a typed 401 status proves the session was rejected.
        let text = anyhow::anyhow!("Engine rejected the access token: 401 Unauthorized");
        assert!(!session_recovery_applies(&cli(&["view"]).command, &text));
        assert!(!session_recovery_applies(&cli(&["loginfo"]).command, &text));
    }
}
