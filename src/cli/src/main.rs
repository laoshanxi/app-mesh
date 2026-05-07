use anyhow::Result;
use clap::Parser;
use std::process;

mod app;
mod client;
mod commands;
mod output;
mod util;

use app::{Cli, Commands};

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    env_logger::init();

    let cli = Cli::parse();

    if cli.verbose {
        log::set_max_level(log::LevelFilter::Debug);
    }

    let code = match run(&cli).await {
        Ok(code) => code,
        Err(e) => {
            let msg = extract_error_message(&e);
            eprintln!("{}", msg);

            if is_follow_or_force_mode(&cli) {
                0
            } else {
                1
            }
        }
    };
    process::exit(code);
}

fn is_follow_or_force_mode(cli: &Cli) -> bool {
    match &cli.command {
        Commands::View(args) => args.follow,
        Commands::Rm(args) => args.force,
        Commands::Add(args) => args.force,
        Commands::User(args) => args.force,
        _ => false,
    }
}

async fn run(cli: &Cli) -> Result<i32> {
    match &cli.command {
        Commands::Logon(args) => commands::auth::logon(cli, args).await,
        Commands::Logoff(_) => commands::auth::logoff(cli).await,
        Commands::Loginfo(args) => commands::auth::loginfo(cli, args).await,
        Commands::Add(args) => commands::apps::add(cli, args.as_ref()).await,
        Commands::Rm(args) => commands::apps::rm(cli, args).await,
        Commands::View(args) => commands::apps::view(cli, args).await,
        Commands::Enable(args) => commands::apps::enable(cli, args).await,
        Commands::Disable(args) => commands::apps::disable(cli, args).await,
        Commands::Restart(args) => commands::apps::restart(cli, args).await,
        Commands::Run(args) => commands::run::run(cli, args).await,
        Commands::Exec(args) => commands::run::exec(cli, args).await,
        Commands::Shell(args) => commands::run::shell(cli, args).await,
        Commands::Get(args) => commands::file::get(cli, args).await,
        Commands::Put(args) => commands::file::put(cli, args).await,
        Commands::Label(args) => commands::system::label(cli, args).await,
        Commands::Log(args) => commands::system::log_level(cli, args).await,
        Commands::Config(_) => commands::system::config(cli).await,
        Commands::Resource(_) => commands::system::resource(cli).await,
        Commands::Passwd(args) => commands::user::passwd(cli, args).await,
        Commands::Lock(args) => commands::user::lock(cli, args).await,
        Commands::User(args) => commands::user::user(cli, args).await,
        Commands::Mfa(args) => commands::user::mfa(cli, args).await,
        Commands::Appmgpwd(args) => commands::admin::appmgpwd(args),
        Commands::Appmginit(_) => commands::admin::appmginit(),
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
