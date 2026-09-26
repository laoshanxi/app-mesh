use anyhow::{bail, Context, Result};
use std::io::{IsTerminal, Read, Write};

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

/// Read a password from the platform TTY/console without echo feedback (the
/// sudo/ssh convention). rpassword opens the console directly, so redirected
/// stdin, argv, shell history, and process listings never carry the password.
pub fn prompt_password(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("read password from interactive console")
}

/// Read a single password line from standard input for an explicitly
/// non-interactive caller (`appm logon --password-stdin`). Unlike argv or an
/// environment variable, a pipe never appears in process listings; a terminal
/// is refused so the password is not echoed back to the screen.
pub fn read_password_stdin() -> Result<String> {
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        bail!("--password-stdin requires a piped or redirected standard input");
    }
    let mut input = String::new();
    stdin
        .read_to_string(&mut input)
        .context("read password from standard input")?;
    single_line_password(&input)
}

// The full input must be exactly one line: truncating at the first newline
// would silently accept a password that never matches the server-side one.
fn single_line_password(input: &str) -> Result<String> {
    let (line, rest) = input.split_once('\n').unwrap_or((input, ""));
    if !rest.is_empty() {
        bail!("The password must be a single line");
    }
    Ok(line.trim_end_matches('\r').to_string())
}

#[cfg(test)]
mod tests {
    use super::single_line_password;

    #[test]
    fn accepts_a_single_line_with_or_without_terminator() {
        assert_eq!(single_line_password("secret\n").unwrap(), "secret");
        assert_eq!(single_line_password("secret").unwrap(), "secret");
        assert_eq!(single_line_password("secret\r\n").unwrap(), "secret");
    }

    #[test]
    fn rejects_anything_after_the_first_line() {
        assert!(single_line_password("secret\nextra").is_err());
        assert!(single_line_password("secret\nextra\n").is_err());
        assert!(single_line_password("secret\n\n").is_err());
    }

    #[test]
    fn keeps_spaces_inside_the_line() {
        assert_eq!(single_line_password("two words \n").unwrap(), "two words ");
    }
}
