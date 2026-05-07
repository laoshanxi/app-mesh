use anyhow::Result;
use std::io::{self, Write};

pub fn prompt_password(prompt: &str) -> Result<String> {
    eprint!("{}", prompt);
    io::stderr().flush()?;
    let pass = rpassword::read_password()?;
    Ok(pass)
}

pub fn prompt_username(prompt: &str) -> Result<String> {
    eprint!("{}", prompt);
    io::stderr().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

pub fn prompt_totp() -> Result<String> {
    eprint!("Enter TOTP code: ");
    io::stderr().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}
