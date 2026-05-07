use anyhow::{Context, Result};
use appmesh::AppMeshClient;

use crate::app::{Cli, LoginfoArgs, LogonArgs};
use crate::client::{build_client, build_client_with_auth, get_current_host, get_current_url, persist_token};
use crate::util::{config, password};

pub async fn logon(cli: &Cli, args: &LogonArgs) -> Result<i32> {
    let client = build_client(cli).await?;

    let username = match &cli.user {
        Some(u) => u.clone(),
        None => password::prompt_username("User: ")?,
    };

    let passwd = match &cli.password {
        Some(p) => p.clone(),
        None => password::prompt_password("Password: ")?,
    };

    let expire = args
        .timeout
        .as_deref()
        .map(AppMeshClient::parse_duration)
        .transpose()
        .context("Invalid timeout duration")?;

    let challenge = client
        .login(&username, &passwd, None, expire, args.audience.as_deref())
        .await
        .context("Login failed")?;

    if !challenge.is_empty() {
        let totp_code = password::prompt_totp()?;
        let expire_secs = expire.unwrap_or(604_800);
        client
            .validate_totp(&username, &challenge, &totp_code, expire_secs)
            .await
            .context("TOTP validation failed")?;
    }

    // Persist token for subsequent commands
    let url = get_current_url(cli);
    let host = get_current_host(cli);
    persist_token(&client, &host);

    if args.show_token {
        if let Some(token) = client.get_access_token() {
            println!("{}", token);
        }
    }

    eprintln!(
        "User <{}> logged on to <{}> successfully.",
        username, url
    );
    Ok(0)
}

pub async fn logoff(cli: &Cli) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    let username = client
        .get_current_user()
        .await
        .ok()
        .and_then(|v| v["name"].as_str().map(String::from))
        .unwrap_or_else(|| "unknown".to_string());

    client.logout().await.context("Logout failed")?;

    // Clear persisted token
    let url = get_current_url(cli);
    let host = get_current_host(cli);
    config::clear_token(&host);

    eprintln!(
        "User <{}> logged off from <{}> successfully.",
        username, url
    );
    Ok(0)
}

pub async fn loginfo(cli: &Cli, args: &LoginfoArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    if args.show_token {
        let user_info = client.get_current_user().await.ok();
        if let Some(ref info) = user_info {
            if let Some(name) = info["name"].as_str() {
                println!("User: {}", name);
            }
        }
        if let Some(token) = client.get_access_token() {
            println!("Token: {}", token);
        }
        return Ok(0);
    }

    let user_info = client
        .get_current_user()
        .await
        .context("Failed to get user info")?;

    if let Some(name) = user_info["name"].as_str() {
        println!("User: {}", name);
    }
    Ok(0)
}
