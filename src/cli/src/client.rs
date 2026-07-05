use anyhow::{bail, Context, Result};
use appmesh::{AppMeshClientWSS, ClientBuilderWSS};
use std::sync::Arc;

use crate::app::Cli;
use crate::util::config;

pub fn get_current_url(cli: &Cli) -> String {
    if let Some(ref url) = cli.host_url {
        return url.clone();
    }
    if let Some((host, port)) = config::load_last_host() {
        return format!("{}:{}", host, port);
    }
    format!("127.0.0.1:{}", config::DEFAULT_WSS_PORT)
}

pub fn get_current_host(cli: &Cli) -> String {
    let url = get_current_url(cli);
    extract_host(&url)
}

fn extract_host(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(&format!("https://{}", url)) {
        if let Some(h) = parsed.host_str() {
            return h.to_string();
        }
    }
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(h) = parsed.host_str() {
            return h.to_string();
        }
    }
    url.split(':').next().unwrap_or("127.0.0.1").to_string()
}

/// Build a WSS client and authenticate with inline -U/-X if provided.
pub async fn build_client(cli: &Cli) -> Result<Arc<AppMeshClientWSS>> {
    let (host, wss_port, tls) = resolve_address_and_tls(cli)?;
    let client = build_wss(host.clone(), wss_port, &tls)?;

    // Restore persisted token from file
    if let Some(token) = config::load_token(&host) {
        client.client().set_token(&token);
    }

    // Set forward-to if specified
    if let Some(ref fwd) = cli.forward_to {
        client.client().set_forward_to(Some(fwd.clone()));
    }

    // Authenticate if credentials provided inline
    if let (Some(user), Some(pass)) = (&cli.user, &cli.password) {
        client
            .login(user, pass, None, None, None)
            .await
            .context("Login failed")?;
        persist_token(&client, &host);
    } else if let Some(user) = &cli.user {
        let pass = crate::util::password::prompt_password(&format!("Password({}): ", user))?;
        if pass.is_empty() {
            bail!("password cannot be empty");
        }
        client
            .login(user, &pass, None, None, None)
            .await
            .context("Login failed")?;
        persist_token(&client, &host);
    }

    config::save_last_host(&host, wss_port);
    Ok(client)
}

pub async fn build_client_with_auth(cli: &Cli) -> Result<Arc<AppMeshClientWSS>> {
    let client = build_client(cli).await?;

    if cli.user.is_none() && client.get_access_token().is_none() {
        // Try default credentials; if that also fails, give a clear message
        if client.login("mesh", "mesh123", None, None, None).await.is_err() {
            anyhow::bail!(
                "Not logged in. Run 'appm logon -U <user> -X <password>' first, \
                 or pass -U/-X on the command line."
            );
        }
    }

    Ok(client)
}

/// Save the current token to disk for next session.
pub fn persist_token(client: &AppMeshClientWSS, host: &str) {
    if let Some(token) = client.get_access_token() {
        config::save_token(host, &token);
    }
}

fn build_wss(
    host: String,
    port: u16,
    tls: &config::DaemonTlsConfig,
) -> Result<Arc<AppMeshClientWSS>> {
    // Only skip verification when the daemon config explicitly disables it. With
    // no CA configured, leave ssl_ca_cert unset so the SDK's auto default applies
    // (App Mesh CA bundle if installed, else system CAs) — never silently disable.
    let skip_verify = !tls.verify_server;

    let mut builder = ClientBuilderWSS::new()
        .address(&host, port)
        .danger_accept_invalid_certs(skip_verify);

    if let Some(ref ca) = tls.ca_cert {
        builder = builder.ssl_ca_cert(ca.to_string_lossy().to_string());
    }
    if let (Some(ref cert), Some(ref key)) = (&tls.client_cert, &tls.client_key) {
        builder = builder.ssl_client_auth(cert.clone(), key.clone());
    }

    builder.build().context("Failed to build WSS client")
}

fn resolve_address_and_tls(
    cli: &Cli,
) -> Result<(String, u16, config::DaemonTlsConfig)> {
    let (daemon_addr, daemon_tls) = config::load_daemon_config();

    if let Some(ref url) = cli.host_url {
        let (host, port) = parse_url(url)?;
        return Ok((host, port, daemon_tls));
    }

    if let Some((host, port)) = config::load_last_host() {
        return Ok((host, port, daemon_tls));
    }

    if let Some((host, port)) = daemon_addr {
        return Ok((host, port, daemon_tls));
    }

    Ok(("127.0.0.1".to_string(), config::DEFAULT_WSS_PORT, daemon_tls))
}

fn parse_url(url: &str) -> Result<(String, u16)> {
    if !url.contains("://") {
        if let Some((host, port_str)) = url.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Ok((host.to_string(), port));
            }
        }
        return Ok((url.to_string(), config::DEFAULT_WSS_PORT));
    }

    let parsed = url::Url::parse(url).context("Invalid URL")?;
    let host = parsed.host_str().unwrap_or("127.0.0.1").to_string();
    let port = parsed.port().unwrap_or(config::DEFAULT_WSS_PORT);
    Ok((host, port))
}
