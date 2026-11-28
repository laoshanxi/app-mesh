use anyhow::{bail, Context, Result};
use appmesh::{AppMeshClient, AppMeshClientWSS, AppMeshError, AppRun, Application, ExitAction};
use http::Method;
use std::io::Write;
use std::sync::Arc;
use uuid::Uuid;

use crate::app::{Cli, ExecArgs, RunArgs, ShellArgs};
use crate::client::build_client_with_auth;
use crate::util::{config, parse, signal};

/// Join trailing arguments into the shell string the daemon runs. A lone argument is
/// already a shell string (`appm exec "ls | wc -l"`) so it passes through; separate argv
/// entries are re-quoted, else `exec -- sh -c 'exit 7'` flattens to `sh -c exit 7`.
fn join_command(parts: &[String]) -> String {
    if parts.len() <= 1 {
        return parts.first().cloned().unwrap_or_default();
    }
    parts.iter().map(|p| shell_quote(p)).collect::<Vec<_>>().join(" ")
}

/// Single-quote for POSIX shells; arguments of only safe characters are left bare.
fn shell_quote(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '=' | '@' | ','));
    if safe {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', r"'\''"))
}

pub async fn run(cli: &Cli, args: &RunArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    if args.app.is_none() && args.cmd.is_none() {
        bail!("The 'run' command requires either '--app' or '--cmd'.");
    }

    // Build Application — only set name if user specified -a (C++ behavior)
    let mut app = Application::default();
    app.behavior = Some(appmesh::Behavior { exit: Some(ExitAction::Remove), exit_code_actions: None });

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
    if let Some(ref image) = args.docker_image {
        app.docker_image = Some(image.clone());
        if !args.docker_port.is_empty() {
            app.docker_ports = Some(args.docker_port.clone());
        }
        if !args.docker_volume.is_empty() {
            app.docker_volumes = Some(args.docker_volume.clone());
        }
        if let Some(ref network) = args.docker_network {
            app.docker_network = Some(network.clone());
        }
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

    let timeout = AppMeshClient::parse_duration(&args.timeout).map_err(|e| anyhow::anyhow!("{}", e))?;
    let lifecycle = AppMeshClient::parse_duration(&args.lifetime).map_err(|e| anyhow::anyhow!("{}", e))?;

    if let Some(ref name) = args.app {
        // `run` copies an existing app; a keepalive task app silently does nothing,
        // and a restart app's run copy restarts forever — only its timeout ends it.
        if let Ok(existing) = client.get_app(name).await {
            let exit = existing.behavior.as_ref().and_then(|behavior| behavior.exit.as_ref());
            if exit.is_some_and(|exit| *exit == ExitAction::Keepalive) {
                bail!(
                    "'{}' is a keepalive task application; nothing was run. Send it a task instead: appm task {} '<payload>'",
                    name,
                    name
                );
            }
            if exit.is_some_and(|exit| *exit == ExitAction::Restart) {
                bail!(
                    "'{}' restarts whenever it exits, so an on-demand run of it never completes — only its timeout ends it. \
                     Enable the application, or send it a task if it serves one: appm task {} '<payload>'",
                    name,
                    name
                );
            }
        }
    }

    // When the user named the run, clean up the transient app on Ctrl+C (matches C++).
    if let Some(ref name) = args.app {
        signal::register_cleanup(client.clone(), name.clone());
    }

    if timeout < 0 {
        // "<0: wait until exit" — the daemon treats timeout 0 as no forced termination;
        // abs() would instead kill the run after |timeout| seconds.
        let reply = sync_run(client.client(), &app, lifecycle).await.context("Sync run failed")?;
        let stdout = std::io::stdout();
        let mut writer = LossyUtf8Writer::new(stdout.lock());
        match &reply.truncated {
            // One page held everything: the daemon already removed the run.
            None => {
                writer.write_all(&reply.body);
                writer.finish().context("Writing the run output to stdout failed")?;
            }
            Some((run_name, position)) => {
                let fetch = |position| fetch_run_output(client.client(), run_name, position);
                if let Err(error) = write_run_output(&reply.body, *position, fetch, &mut writer).await {
                    writer.finish().ok();
                    eprintln!(
                        "Warning: could not read the rest of the output of run '{}' ({}). The remaining output \
                         stays readable on application '{}' for {} seconds (for example `appm view -a {} -o`).",
                        run_name, error, run_name, SYNC_RUN_RETENTION_SECONDS, run_name
                    );
                    signal::clear_cleanup();
                    return Ok(parse::normalize_exit_code(reply.exit_code));
                }
                writer.finish().context("Writing the run output to stdout failed")?;
                // Best effort: the daemon drops the run itself once the retention ends.
                let _ = client.delete_app(run_name).await;
            }
        }
        signal::clear_cleanup();
        return Ok(parse::normalize_exit_code(reply.exit_code));
    }

    // Async mode: subscribe + run + wait
    let (app_run, exit_code) = wait_for_run(&client, &app, timeout, lifecycle).await.context("Run failed")?;

    // Best-effort delete if run_and_wait didn't already clean up; terminal failures
    // (transport disconnect) surface as typed errors and propagate above.
    if let (None, Some(app_run)) = (&exit_code, app_run) {
        let _ = client.delete_app(&app_run.app_name).await;
    }

    signal::clear_cleanup();
    Ok(parse::normalize_exit_code(exit_code))
}

/// One page of a synchronous run's output; a longer output is paged from the output endpoint.
const SYNC_RUN_PAGE_BYTES: usize = 5 * 1024 * 1024;
/// How long the daemon keeps a run whose output filled a page.
const SYNC_RUN_RETENTION_SECONDS: u64 = 600;

/// Reply to a synchronous run: the exit code and the first page of the output.
/// `truncated` is `Some((run instance name, byte offset of the remaining output))` when the
/// daemon kept the run because its output filled the page.
struct SyncRunReply {
    exit_code: Option<i32>,
    body: Vec<u8>,
    truncated: Option<(String, i64)>,
}

/// Send a synchronous run (`/appmesh/app/syncrun`) and wait for the exit. Sent raw
/// because `run_app_sync` hands back only the text, not the truncation headers.
async fn sync_run(client: &AppMeshClient, app: &Application, lifecycle: i32) -> Result<SyncRunReply, AppMeshError> {
    let resp = client
        .raw_request(
            Method::POST,
            "/appmesh/app/syncrun",
            Some(&serde_json::to_vec(app)?),
            Some([("Content-Type".to_string(), "application/json".to_string())].into()),
            Some([("timeout".to_string(), "0".to_string()), ("lifecycle".to_string(), lifecycle.to_string())].into()),
            false,
        )
        .await?;

    let exit_code = match resp.headers().get("X-Exit-Code") {
        _ if resp.status() != http::StatusCode::OK => None,
        Some(value) => match value.to_str().ok().and_then(|value| value.parse::<i32>().ok()) {
            Some(code) => Some(code),
            None => {
                return Err(AppMeshError::SerializationError(format!("Malformed X-Exit-Code response header: {value:?}")));
            }
        },
        None => None,
    };
    // An older daemon sends neither header and always removes the run with the reply.
    let truncated = match (
        resp.headers().get("X-App-Name").and_then(|value| value.to_str().ok()),
        resp.headers().get("X-Output-Truncated").and_then(|value| value.to_str().ok()),
    ) {
        (Some(run_name), Some("1")) => Some(run_name.to_string()),
        _ => None,
    };
    let position = resp
        .headers()
        .get("X-Output-Position")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| resp.body().len() as i64);
    let body = resp.into_body().to_vec();
    Ok(SyncRunReply { exit_code, body, truncated: truncated.map(|run_name| (run_name, position)) })
}

/// One page of a run's output starting at `position`.
async fn fetch_run_output(client: &AppMeshClient, run_name: &str, position: i64) -> Result<Vec<u8>, AppMeshError> {
    client
        .raw_request(
            Method::GET,
            &format!("/appmesh/app/{}/output", encode_path_segment(run_name)),
            None,
            None,
            Some([("stdout_position".to_string(), position.to_string())].into()),
            true,
        )
        .await
        .map(|resp| resp.into_body().to_vec())
}

/// Percent-encode a URL path segment (`%20` for a space, `%2B` for a plus).
fn encode_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    if value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')) {
        return value.to_string();
    }
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => encoded.push(byte as char),
            _ => {
                encoded.push('%');
                encoded.push(HEX[(byte >> 4) as usize] as char);
                encoded.push(HEX[(byte & 0x0F) as usize] as char);
            }
        }
    }
    encoded
}

/// Write the output of a run whose reply filled a page, fetching the pages that follow.
///
/// `position` is the byte offset after `first`; it advances by each page's byte length.
/// A page shorter than a full one ends the output. A page that cannot be fetched is
/// `Err`, and the run is left on the daemon so its output stays readable.
async fn write_run_output<F, Fut, E>(
    first: &[u8],
    mut position: i64,
    mut fetch_page: F,
    out: &mut LossyUtf8Writer<impl Write>,
) -> Result<(), E>
where
    F: FnMut(i64) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, E>>,
{
    out.write_all(first);
    loop {
        let page = fetch_page(position).await?;
        position += page.len() as i64;
        let complete = page.len() < SYNC_RUN_PAGE_BYTES;
        out.write_all(&page);
        if complete {
            return Ok(());
        }
    }
}

/// Writes UTF-8 text to a sink as it arrives, replacing invalid bytes with U+FFFD exactly
/// as `String::from_utf8_lossy` would over the whole output. An incomplete multi-byte
/// character split across pages is held back until its remainder arrives. A failed write
/// is kept back and reported once by `finish`, so page loop and sink error stay apart.
struct LossyUtf8Writer<W: Write> {
    out: W,
    pending: Vec<u8>,
    error: Option<std::io::Error>,
}

impl<W: Write> LossyUtf8Writer<W> {
    fn new(out: W) -> Self {
        Self { out, pending: Vec::new(), error: None }
    }

    fn write_all(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
        let mut buffer = std::mem::take(&mut self.pending);
        loop {
            match std::str::from_utf8(&buffer).map_err(|error| (error.valid_up_to(), error.error_len())) {
                Ok(_) => {
                    self.emit(&buffer);
                    return;
                }
                Err((valid, error_len)) => {
                    self.emit(&buffer[..valid]);
                    match error_len {
                        // A malformed sequence: one replacement character, then read on.
                        Some(len) => {
                            self.emit("\u{FFFD}".as_bytes());
                            buffer.drain(..valid + len);
                        }
                        // Cut off mid-character: hold it back for the next page.
                        None => {
                            buffer.drain(..valid);
                            self.pending = buffer;
                            return;
                        }
                    };
                }
            }
        }
    }

    /// Report the first failed write. A character still cut off at the very end of the
    /// output becomes one replacement character, as in `String::from_utf8_lossy`.
    fn finish(&mut self) -> std::io::Result<()> {
        if !self.pending.is_empty() {
            self.pending.clear();
            self.emit("\u{FFFD}".as_bytes());
        }
        match self.error.take() {
            Some(error) => Err(error),
            None => self.out.flush(),
        }
    }

    fn emit(&mut self, bytes: &[u8]) {
        if self.error.is_none() && !bytes.is_empty() {
            self.error = self.out.write_all(bytes).err();
        }
    }
}

pub async fn exec(cli: &Cli, args: &ExecArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    let command = join_command(&args.command);
    if command.is_empty() {
        bail!("The 'exec' command requires a command to execute.");
    }

    let app_name = derive_exec_app_name().await;

    // Clean up any existing session
    let _ = client.delete_app(&app_name).await;

    let timeout = AppMeshClient::parse_duration(&args.timeout).map_err(|e| anyhow::anyhow!("{}", e))?;
    let lifecycle = AppMeshClient::parse_duration(&args.lifetime).map_err(|e| anyhow::anyhow!("{}", e))?;

    signal::register_cleanup(client.clone(), app_name.clone());

    loop {
        let app = build_exec_app(&app_name, &command, args.session_login, &args.env, cli.forward_to.is_some());

        let (_app_run, exit_code) = wait_for_run(&client, &app, timeout, lifecycle).await.context("Exec failed")?;

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

    let app_name = derive_exec_app_name().await;

    let _ = client.delete_app(&app_name).await;

    let timeout = AppMeshClient::parse_duration(&args.timeout).map_err(|e| anyhow::anyhow!("{}", e))?;
    let lifecycle = AppMeshClient::parse_duration(&args.lifetime).map_err(|e| anyhow::anyhow!("{}", e))?;

    // The daemon resolves the immutable principal and its execution mapping.
    let url = crate::client::get_current_url(cli);
    println!("Connected to <{}>", url);

    let history_path = config::shell_history_path();
    let mut rl = rustyline::DefaultEditor::new().context("Failed to initialize readline")?;
    let _ = rl.load_history(&history_path);

    let mut return_code = 0i32;

    // Execute initial command if provided
    if !args.command.is_empty() {
        let initial_cmd = join_command(&args.command);
        return_code =
            execute_shell_command(&client, &app_name, &initial_cmd, args, timeout, lifecycle, cli.forward_to.is_some())
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
                    execute_shell_command(&client, &app_name, cmd, args, timeout, lifecycle, cli.forward_to.is_some())
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

/// Run and wait for the exit, within `timeout` seconds.
async fn wait_for_run(client: &AppMeshClientWSS, app: &Application, timeout: i32, lifecycle: i32) -> Result<(Option<AppRun>, Option<i32>), AppMeshError> {
    // The daemon drops a `lifecycle` shorter than the runtime bound `timeout`, so the
    // shorter of the two is the runtime bound sent; the wait keeps the caller's timeout.
    let result = client
        .run_and_wait(app, timeout.min(lifecycle), lifecycle, appmesh::print_output_handler(), timeout)
        .await;
    // A run app removed before its exit is seen (its lifecycle end, or a delete by
    // another client) is reported as a timeout, as the synchronous run is.
    match result {
        Err(AppMeshError::AppRemoved) => Ok((None, Some(124))),
        result => result.map(|(app_run, exit_code)| (Some(app_run), exit_code)),
    }
}

async fn execute_shell_command(
    client: &Arc<appmesh::AppMeshClientWSS>,
    app_name: &str,
    command: &str,
    args: &ShellArgs,
    timeout: i32,
    lifecycle: i32,
    forwarded: bool,
) -> Result<i32> {
    let app = build_exec_app(app_name, command, args.session_login, &args.env, forwarded);

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
                let _ = tokio::time::timeout(std::time::Duration::from_secs(3), client.delete_app(&app_name)).await;
            }
        })
    };

    let result = wait_for_run(&client, &app, timeout, lifecycle).await;
    watcher.abort();

    let (_app_run, exit_code) = result.context("Shell command failed")?;
    Ok(parse::normalize_exit_code(exit_code))
}

fn build_exec_app(
    app_name: &str,
    command: &str,
    session_login: bool,
    extra_env: &[String],
    forwarded: bool,
) -> Application {
    let mut builder = Application::builder(app_name)
        .command(command)
        .shell(true)
        .description("App Mesh exec environment")
        .exit_behavior(ExitAction::Remove);

    if session_login {
        builder = builder.session_login(true);
    }

    // Forward current working directory. A forwarded exec runs on another host
    // where the local cwd does not exist, so keep the server default instead.
    if !forwarded {
        if let Ok(cwd) = std::env::current_dir() {
            builder = builder.working_dir(&cwd.to_string_lossy());
        }
    }

    // Ambient process variables are never copied to the remote application. Name-
    // based secret deny-lists miss standard credentials such as AWS_SECRET_ACCESS_KEY;
    // every forwarded value must therefore be an explicit --env decision.
    for env_str in extra_env {
        if let Some((k, v)) = env_str.split_once('=') {
            builder = builder.env(k, v);
        }
    }

    builder.build()
}

async fn derive_exec_app_name() -> String {
    let os_user: String = get_os_username()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        .take(32)
        .collect();
    let os_user = if os_user.is_empty() { "user" } else { &os_user };
    format!("shell_{}_{}", os_user, Uuid::new_v4().simple())
}

fn get_os_username() -> String {
    std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "user".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Ready;
    use std::sync::{Arc, Mutex};

    /// Record of the byte positions each page was requested at.
    type Requests = Arc<Mutex<Vec<i64>>>;

    /// The answer to one page request: its bytes, or the transport failure.
    type Page = Ready<Result<Vec<u8>, String>>;

    /// A full page ending with `tail`.
    fn full_page(tail: &[u8]) -> Vec<u8> {
        vec![b'.'; SYNC_RUN_PAGE_BYTES - tail.len()].into_iter().chain(tail.iter().copied()).collect()
    }

    /// A run whose output continues with `pages` after the reply page; `fail_at` makes
    /// that page request (0-based) fail instead of answering.
    fn run_pages(pages: Vec<Vec<u8>>, fail_at: Option<usize>) -> (Requests, impl FnMut(i64) -> Page) {
        let requests = Requests::default();
        let seen = Arc::clone(&requests);
        let mut pages = pages.into_iter();
        let fetch = move |position: i64| {
            let index = {
                let mut seen = seen.lock().unwrap();
                seen.push(position);
                seen.len() - 1
            };
            let result = if Some(index) == fail_at {
                Err("connection closed".to_string())
            } else {
                Ok(pages.next().unwrap_or_default())
            };
            std::future::ready(result)
        };
        (requests, fetch)
    }

    /// Page the output into a buffer; the result is `(output, outcome)`.
    async fn collect(first: &[u8], position: i64, fetch: impl FnMut(i64) -> Page) -> (Vec<u8>, Result<(), String>) {
        let mut writer = LossyUtf8Writer::new(Vec::new());
        let result = write_run_output(first, position, fetch, &mut writer).await;
        writer.finish().expect("writing to a Vec cannot fail");
        (writer.out, result)
    }

    #[test]
    fn untruncated_page_is_decoded_like_from_utf8_lossy() {
        for body in [
            b"".to_vec(),
            b"hello\n".to_vec(),
            "caf\u{e9} \u{4e16}\u{754c}".as_bytes().to_vec(),
            vec![0xFF, b'a', 0xC3],
            "s".repeat(SYNC_RUN_PAGE_BYTES).into_bytes(),
        ] {
            let mut writer = LossyUtf8Writer::new(Vec::new());
            writer.write_all(&body);
            writer.finish().unwrap();
            assert_eq!(String::from_utf8(writer.out).unwrap(), String::from_utf8_lossy(&body));
        }
    }

    #[tokio::test]
    async fn multi_page_output_is_joined_in_order() {
        // Only a full page is followed by another; the tail of each page tells them apart.
        let (requests, fetch) = run_pages(vec![full_page(b"45"), b"6".to_vec()], None);
        let (out, result) = collect(b"123", 3, fetch).await;
        result.unwrap();
        assert_eq!(out.len(), 3 + SYNC_RUN_PAGE_BYTES + 1);
        assert!(out.starts_with(b"123."));
        assert!(out.ends_with(b"456"));
        // The offset starts after the reply page and advances by each page's byte length.
        assert_eq!(*requests.lock().unwrap(), vec![3, 3 + SYNC_RUN_PAGE_BYTES as i64]);
    }

    #[tokio::test]
    async fn offset_starts_at_the_reply_header_and_advances_by_page_bytes() {
        let pages = vec![vec![b'x'; SYNC_RUN_PAGE_BYTES], vec![b'y'; SYNC_RUN_PAGE_BYTES], vec![b'z'; 10]];
        let (requests, fetch) = run_pages(pages, None);
        let (out, result) = collect(b"head", 4096, fetch).await;
        result.unwrap();
        assert_eq!(out.len(), 4 + 2 * SYNC_RUN_PAGE_BYTES + 10);
        let step = SYNC_RUN_PAGE_BYTES as i64;
        assert_eq!(*requests.lock().unwrap(), vec![4096, 4096 + step, 4096 + 2 * step]);
    }

    #[tokio::test]
    async fn exactly_one_page_reads_an_empty_second_page() {
        let (requests, fetch) = run_pages(vec![Vec::new()], None);
        let (out, result) = collect(&full_page(b"a"), SYNC_RUN_PAGE_BYTES as i64, fetch).await;
        result.unwrap();
        assert_eq!(out.len(), SYNC_RUN_PAGE_BYTES);
        assert_eq!(*requests.lock().unwrap(), vec![SYNC_RUN_PAGE_BYTES as i64]);
    }

    #[tokio::test]
    async fn failed_page_is_an_error_after_the_pages_read_so_far() {
        let (requests, fetch) = run_pages(vec![vec![b'x'; SYNC_RUN_PAGE_BYTES]], Some(1));
        let (out, result) = collect(b"123", 3, fetch).await;
        assert_eq!(result.unwrap_err(), "connection closed");
        assert_eq!(out.len(), 3 + SYNC_RUN_PAGE_BYTES);
        assert_eq!(requests.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn character_split_across_pages_stays_whole() {
        // Page 1 ends inside a 3-byte character, page 2 completes it and ends inside a
        // 4-byte one, page 3 completes that.
        let filler = |count: usize| vec![b'.'; count];
        let page2 = [&[0xB8, 0x96, b'\n'][..], &filler(SYNC_RUN_PAGE_BYTES - 5), &[0xF0, 0x9F]].concat();
        let pages = vec![full_page(&[0xE4]), page2, vec![0x98, 0x80]];
        let (_, fetch) = run_pages(pages, None);
        let (out, result) = collect(b"pre", 3, fetch).await;
        result.unwrap();
        let dots = SYNC_RUN_PAGE_BYTES - 1;
        let expected = format!("pre{}{}\n{}{}", ".".repeat(dots), '\u{4e16}', ".".repeat(dots - 4), '\u{1f600}');
        assert_eq!(String::from_utf8(out).unwrap(), expected);
    }

    #[tokio::test]
    async fn decode_matches_from_utf8_lossy_at_every_page_split() {
        let text: Vec<u8> =
            "ab\u{4e16}cd\u{1f600}e\u{e9}".as_bytes().iter().chain(&[0xFF, b'z', 0xC3, 0x28]).copied().collect();
        let expected = String::from_utf8_lossy(&text).into_owned();
        for split in 0..=text.len() {
            // The reply page is full, so exactly one more (short) page follows.
            let (_, fetch) = run_pages(vec![text[split..].to_vec()], None);
            let (out, result) = collect(&full_page(&text[..split]), SYNC_RUN_PAGE_BYTES as i64, fetch).await;
            result.unwrap();
            let dots = SYNC_RUN_PAGE_BYTES - split;
            assert_eq!(String::from_utf8(out).unwrap()[dots..], expected, "split at {split}");
        }
    }

    #[test]
    fn path_segment_is_percent_encoded_like_the_sdk() {
        assert_eq!(encode_path_segment("run-1.2_3~"), "run-1.2_3~");
        assert_eq!(encode_path_segment("a b+c/d\u{e9}"), "a%20b%2Bc%2Fd%C3%A9");
    }
}
