use std::io::{self, IsTerminal, Write};

pub fn confirm(message: &str) -> bool {
    if !io::stdin().is_terminal() {
        eprintln!("Confirmation required but stdin is not a terminal. Use --force to skip.");
        return false;
    }
    eprint!("{} (y/n): ", message);
    io::stderr().flush().ok();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}
