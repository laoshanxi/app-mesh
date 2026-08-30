use anyhow::{Context, Result};
use appmesh::{AppMeshClientWSS, ClientBuilderWSS, DexOAuthClient};
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

pub fn get_current_endpoint(cli: &Cli) -> Result<String> {
    let (host, port, _) = resolve_address_and_tls(cli)?;
    Ok(canonical_endpoint(&host, port))
}

/// Build an Engine client without performing authentication. This is used for the
/// public `/appmesh/auth/config` discovery call during login.
pub async fn build_client(cli: &Cli) -> Result<Arc<AppMeshClientWSS>> {
    let (host, wss_port, tls) = resolve_address_and_tls(cli)?;
    let client = build_wss(host.clone(), wss_port, &tls)?;

    // Set forward-to if specified
    if let Some(ref fwd) = cli.forward_to {
        client.client().set_forward_to(Some(fwd.clone()));
    }

    config::save_last_host(&host, wss_port);
    Ok(client)
}

pub async fn build_client_with_auth(cli: &Cli) -> Result<Arc<AppMeshClientWSS>> {
    let client = build_client(cli).await?;

    // Unattended automation (CI, containers) supplies an already-acquired Dex
    // access token through the same APPMESH_BEARER_TOKEN convention used by the
    // packaged Python tools. The token is used as-is until it expires: there is
    // no refresh token and no local Dex session, so `appm logon` remains the
    // path for interactive use.
    if let Ok(token) = std::env::var("APPMESH_BEARER_TOKEN") {
        if !token.trim().is_empty() {
            client.client().set_token(token.trim());
            return Ok(client);
        }
    }

    let endpoint = get_current_endpoint(cli)?;
    let session = config::load_session(&endpoint)?.ok_or_else(|| {
        anyhow::anyhow!("No Dex session is configured for {}. Run 'appm logon'.", endpoint)
    })?;
    // Discovery must use the HTTPS side channel, never the WSS transport: the
    // daemon authenticates the WebSocket only at upgrade time, and a transport
    // connected here without a token would stay anonymous for every later call.
    let advertised = client
        .get_auth_config_https(cli.forward_to.as_deref())
        .await
        .context("Engine OAuth discovery failed")?;
    let advertised_issuer = advertised.get("issuer").and_then(serde_json::Value::as_str);
    let advertised_client = advertised.get("public_client_id").and_then(serde_json::Value::as_str);
    let advertised_audience = advertised.get("audience").and_then(serde_json::Value::as_str);
    if advertised_issuer != Some(session.oauth.issuer.as_str())
        || advertised_client != Some(session.oauth.client_id.as_str())
        || advertised_audience != session.oauth.audience.as_deref()
    {
        anyhow::bail!(
            "Stored Dex session does not match the issuer/client/audience advertised by {}. Run 'appm logon' again.",
            endpoint
        );
    }

    // The SDK provider owns expiry/401 refresh for the full client lifetime. The CLI
    // owns persistence and durably records every rotated Dex token set. Refresh tokens
    // remain inside this provider/session callback and are never sent to the Engine.
    let oauth = Arc::new(
        DexOAuthClient::discover(session.oauth.clone())
            .await
            .context("Dex discovery for token lifecycle failed")?,
    );
    oauth.restore(session.tokens.clone())?;
    let engine_endpoint = session.engine_endpoint.clone();
    let oauth_config = session.oauth.clone();
    oauth.set_token_update_callback(move |tokens| {
        config::save_session(&config::StoredSession::new(
            engine_endpoint.clone(),
            oauth_config.clone(),
            tokens.clone(),
        ))
        .map_err(|error| appmesh::AppMeshError::IoError(error.to_string()))
    });
    oauth
        .install_on(client.client())
        .await
        .context("Dex token preparation failed")?;
    client.client().set_token_provider(Some(oauth));

    Ok(client)
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

    let transport_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host)
    } else {
        host
    };
    let mut builder = ClientBuilderWSS::new()
        .address(&transport_host, port)
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
        let tls = if daemon_addr.as_ref().is_some_and(|address| address == &(host.clone(), port)) {
            daemon_tls
        } else {
            // An explicit remote endpoint never inherits the local daemon's insecure
            // VerifyServer setting or private client key material.
            config::DaemonTlsConfig::default()
        };
        return Ok((host, port, tls));
    }

    if let Some((host, port)) = config::load_last_host() {
        let tls = if daemon_addr.as_ref().is_some_and(|address| address == &(host.clone(), port)) {
            daemon_tls
        } else {
            config::DaemonTlsConfig::default()
        };
        return Ok((host, port, tls));
    }

    if let Some((host, port)) = daemon_addr {
        return Ok((host, port, daemon_tls));
    }

    Ok(("127.0.0.1".to_string(), config::DEFAULT_WSS_PORT, daemon_tls))
}

fn parse_url(url: &str) -> Result<(String, u16)> {
    if !url.contains("://") {
        if let Ok(address) = url.parse::<std::net::IpAddr>() {
            return Ok((address.to_string(), config::DEFAULT_WSS_PORT));
        }
        let parsed = url::Url::parse(&format!("wss://{}", url)).context("Invalid Engine address")?;
        return validated_host_port(parsed, config::DEFAULT_WSS_PORT);
    }

    let parsed = url::Url::parse(url).context("Invalid URL")?;
    let default_port = parsed.port_or_known_default().unwrap_or(config::DEFAULT_WSS_PORT);
    validated_host_port(parsed, default_port)
}

fn validated_host_port(parsed: url::Url, default_port: u16) -> Result<(String, u16)> {
    if !matches!(parsed.scheme(), "wss" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || (parsed.path() != "" && parsed.path() != "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!(
            "Engine URL must be a WSS/HTTPS origin without credentials, path, query, or fragment"
        );
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Engine URL is missing a host"))?
        .to_string();
    let port = parsed.port().unwrap_or(default_port);
    Ok((host, port))
}

fn canonical_endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("wss://[{}]:{}", host, port)
    } else {
        format!("wss://{}:{}", host, port)
    }
}
