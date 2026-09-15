use anyhow::{bail, Context, Result};
use std::io::{IsTerminal, Write};

/// Read a non-secret login name from the interactive console. Non-interactive
/// callers must pass --username explicitly.
pub fn prompt_username(prompt: &str) -> Result<String> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        bail!("username prompt requires an interactive console; pass --username");
    }
    eprint!("{}", prompt);
    std::io::stderr().flush().context("write username prompt")?;
    let mut input = String::new();
    stdin.read_line(&mut input).context("read username from console")?;
    Ok(input.trim().to_string())
}

/// Read a password from the platform TTY/console with `*` feedback. rpassword
/// opens the console directly, so redirected stdin, argv, shell history, and
/// process listings never carry the password.
pub fn prompt_password(prompt: &str) -> Result<String> {
    let config = rpassword::ConfigBuilder::new()
        .password_feedback_mask('*')
        .build();
    rpassword::prompt_password_with_config(prompt, config)
        .context("read password from interactive console")
}

/// Read a single password line from standard input for an explicitly
/// non-interactive caller (`appm logon --password-stdin`). Unlike argv or an
/// environment variable, a pipe never appears in process listings; a terminal
/// is refused so the password is not echoed back to the screen.
pub fn read_password_stdin() -> Result<String> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        bail!("--password-stdin requires a piped or redirected standard input");
    }
    let mut line = String::new();
    stdin
        .read_line(&mut line)
        .context("read password from standard input")?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}
