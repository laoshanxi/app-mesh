use anyhow::{Context, Result};
use appmesh::{AppMeshClientWSS, ClientBuilderWSS, OAuthClient, RequestSigner, TokenProvider, TokenSet};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::app::Cli;
use crate::util::config;
use crate::util::config::{ENV_API_KEY, ENV_API_SECRET, ENV_BEARER_TOKEN};

pub fn get_current_url(cli: &Cli) -> String {
    if let Some(ref url) = cli.host_url {
        return url.clone();
    }
    if let Some(endpoint) = config::load_last_endpoint() {
        return format!("{}://{}:{}", if endpoint.plain { "ws" } else { "wss" }, endpoint.host, endpoint.port);
    }
    format!("127.0.0.1:{}", config::DEFAULT_WSS_PORT)
}

pub fn get_current_endpoint(cli: &Cli) -> Result<String> {
    let (host, port, tls) = resolve_address_and_tls(cli)?;
    Ok(canonical_endpoint(&host, port, tls.plain))
}

/// Attach the HMAC request signer when an API key pair is configured via
/// --api-key/--api-secret or APPMESH_API_KEY/APPMESH_API_SECRET. The secret is
/// used in memory only and never persisted or logged; `--api-secret -` reads
/// one line from stdin so the value never crosses argv.
fn apply_request_signer(client: &Arc<AppMeshClientWSS>, cli: &Cli) {
    let flag_or_env = |flag: &Option<String>, env: &str| {
        flag.clone()
            .or_else(|| std::env::var(env).ok())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    let secret = match flag_or_env(&cli.api_secret, ENV_API_SECRET) {
        // argv is visible to every process through `ps`; `-` keeps the secret out of it.
        Some(secret) if secret == "-" => read_secret_from_stdin(),
        secret => secret,
    };
    match (flag_or_env(&cli.api_key, ENV_API_KEY), secret) {
        (Some(key_id), Some(secret)) => match RequestSigner::new(key_id, secret) {
            Ok(signer) => client.set_request_signer(Some(signer)),
            // Unreachable in practice: the values above are non-empty; stay loud anyway.
            Err(err) => eprintln!("Warning: request signing is unavailable ({err}); requests are sent unsigned."),
        },
        (None, None) => {}
        _ => eprintln!(
            "Warning: request signing needs both an API key id and secret (--api-key/--api-secret or \
             APPMESH_API_KEY/APPMESH_API_SECRET); requests are sent unsigned."
        ),
    }
}

/// One trimmed line from stdin; `None` when nothing readable arrived.
fn read_secret_from_stdin() -> Option<String> {
    let mut secret = String::new();
    match std::io::stdin().read_line(&mut secret) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(secret.trim_end_matches(['\r', '\n']).to_string()).filter(|value| !value.is_empty()),
    }
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

    apply_request_signer(&client, cli);

    // An explicit -H is remembered only at logon, so a one-off -H cannot hijack the default.
    if cli.host_url.is_none() {
        remember_resolved(cli, &host, wss_port, &tls);
    }
    Ok(client)
}

/// Persist the resolved endpoint and its transport settings. The local Engine
/// re-reads its own CA, so only a named or previously recorded CA is kept.
fn remember_resolved(cli: &Cli, host: &str, port: u16, tls: &config::DaemonTlsConfig) {
    // A CA has no effect without verification or on a plaintext endpoint.
    let ca_cert = if !tls.verify_server || tls.plain {
        None
    } else {
        match cli.ca_cert {
            Some(ref ca) => Some(ca.clone()),
            None => config::load_last_endpoint()
                .filter(|endpoint| endpoint.host == host && endpoint.port == port && endpoint.plain == tls.plain)
                .and_then(|endpoint| endpoint.ca_cert),
        }
    };
    config::save_last_endpoint(&config::RememberedEndpoint {
        host: host.to_string(),
        port,
        plain: tls.plain,
        verify_server: tls.verify_server,
        ca_cert,
    });
}

/// Persist the resolved endpoint as the CLI default after a successful logon.
pub fn remember_engine_endpoint(cli: &Cli) -> Result<()> {
    let (host, port, tls) = resolve_address_and_tls(cli)?;
    remember_resolved(cli, &host, port, &tls);
    Ok(())
}

pub async fn build_client_with_auth(cli: &Cli) -> Result<Arc<AppMeshClientWSS>> {
    let client = build_client(cli).await?;

    // Unattended automation (CI, containers) supplies an already-acquired
    // access token through the same APPMESH_BEARER_TOKEN convention used by the
    // packaged Python tools. The token is used as-is until it expires: there is
    // no refresh token and no local sign-in session, so `appm logon` remains the
    // path for interactive use.
    if let Ok(token) = std::env::var(ENV_BEARER_TOKEN) {
        if !token.trim().is_empty() {
            client.client().set_token(token.trim());
            return Ok(client);
        }
    }

    let endpoint = get_current_endpoint(cli)?;
    let session = config::load_session(&endpoint)?
        .ok_or_else(|| anyhow::anyhow!("No sign-in session is configured for {}. Run 'appm logon'.", endpoint))?;
    // Forwarded requests require a bearer token on every route, so the anonymous
    // discovery GET below would always answer 401 — noise on every -F invocation.
    // Skip it: use the stored token as-is, exactly what the degraded fallback did.
    if cli.forward_to.is_some() {
        if !stored_token_usable(&session) {
            anyhow::bail!(
                "The stored access token for {} is expired and forwarded requests accept only \
                 bearer authentication. Run 'appm logon' again.",
                endpoint
            );
        }
        client.client().set_token(&session.tokens.access_token);
        return Ok(client);
    }
    // Discovery must use the HTTPS side channel, never the WSS transport: the
    // daemon authenticates the WebSocket only at upgrade time, and a transport
    // connected here without a token would stay anonymous for every later call.
    let advertised = match client.get_auth_config_https(cli.forward_to.as_deref()).await {
        Ok(advertised) => advertised,
        Err(error) => {
            // A brief authentication-service outage must not take the CLI down
            // while the stored access token is still valid. Degraded mode uses
            // the token as-is: the issuer check and token refresh need the
            // discovery document, so both wait until discovery recovers.
            if !stored_token_usable(&session) {
                return Err(error).context("Engine OAuth discovery failed");
            }
            eprintln!("Warning: Engine OAuth discovery failed ({}). Using the stored access token until it expires.", error);
            client.client().set_token(&session.tokens.access_token);
            return Ok(client);
        }
    };
    let advertised_issuer = advertised.get("issuer").and_then(serde_json::Value::as_str);
    let advertised_client = advertised.get("public_client_id").and_then(serde_json::Value::as_str);
    let advertised_audience = advertised.get("audience").and_then(serde_json::Value::as_str);
    if advertised_issuer != Some(session.oauth.issuer.as_str())
        || advertised_client != Some(session.oauth.client_id.as_str())
        || advertised_audience != session.oauth.audience.as_deref()
    {
        // Hold the lock so a parallel refresh cannot re-write the file between
        // this mismatch verdict and the removal.
        config::with_session_lock(&session, |_| config::delete_session(&session))?;
        anyhow::bail!(
            "The stored sign-in session does not match the authentication configuration for {}. The incompatible \
	 session was removed. Run 'appm logon' again.",
            endpoint
        );
    }

    // A session without a usable refresh grant (the Engine disabled refresh
    // tokens at logon, or now advertises refresh_token=false) cannot renew: a
    // still-valid access token is used as-is, an expired one ends the session.
    if !refresh_grant_usable(&advertised, &session) {
        if session.tokens.is_expired() {
            anyhow::bail!("The sign-in session for {} expired and cannot be renewed. Run 'appm logon' again.", endpoint);
        }
        client.client().set_token(&session.tokens.access_token);
        return Ok(client);
    }

    // The OAuth client owns expiry/401 refresh for the full client lifetime. The CLI
    // owns persistence and durably records every rotated token set. Refresh tokens
    // remain inside this OAuth/session callback and are never sent to the Engine.
    let oauth =
        Arc::new(OAuthClient::discover(session.oauth.clone()).await.context("Authentication service discovery failed")?);
    // Serialize the initial token preparation across processes and adopt whatever
    // a parallel CLI already rotated into the session file. The guard covers only
    // the read: `install_on` below may refresh, and that refresh's persistence
    // callback re-acquires the same lock.
    let latest_tokens = config::with_session_lock(&session, |latest| {
        Ok(latest.map(|latest| latest.tokens).unwrap_or_else(|| session.tokens.clone()))
    })?;
    oauth.restore(latest_tokens.clone())?;
    // Mirror of the token set the SDK holds, advanced by every persisted or
    // adopted update below; its refresh token is the grant the next refresh
    // consumes and the yardstick for every lock+recheck decision.
    let known_tokens = Arc::new(Mutex::new(latest_tokens));
    let binding = session.clone();
    let oauth_weak = Arc::downgrade(&oauth);
    let known = Arc::clone(&known_tokens);
    oauth.set_token_update_callback(move |new_tokens| {
        let used_refresh = lock_known(&known).refresh_token.clone();
        config::with_session_lock(&binding, |latest| {
            match config::decide_session_update(used_refresh.as_deref(), latest.as_ref(), &binding) {
                config::SessionUpdate::Write => {
                    config::save_session(&config::StoredSession::new(
                        binding.engine_endpoint.clone(),
                        binding.oauth.clone(),
                        new_tokens.clone(),
                    ))?;
                    *lock_known(&known) = new_tokens.clone();
                }
                config::SessionUpdate::Adopt(tokens) => {
                    // A parallel CLI won the rotation; `restore()` swaps the SDK's
                    // in-memory set for the on-disk one. It touches only the SDK's
                    // short-lived token mutex, never the refresh mutex this
                    // callback already runs under, so it cannot deadlock or
                    // re-enter the refresh in progress.
                    if let Some(oauth) = oauth_weak.upgrade() {
                        oauth.restore(tokens.clone())?;
                    }
                    *lock_known(&known) = tokens;
                }
                config::SessionUpdate::Skip => {}
            }
            Ok(())
        })
        .map_err(|error| appmesh::AppMeshError::IoError(error.to_string()))
    });
    if let Err(error) = oauth.install_on(client.client()).await {
        // The provider drops its grant on invalid_grant — the refresh token was
        // revoked, expired, or claimed by another login with the same account (for
        // example the web UI). That session can never renew: remove it and say so.
        if !oauth.can_refresh() {
            let used_refresh = lock_known(&known_tokens).refresh_token.clone();
            // Decide against the latest on-disk session under the lock: only a
            // file that still holds the grant that just died is ours to remove.
            enum ColdStart {
                Removed,
                Adopted(appmesh::TokenSet),
                Foreign,
            }
            let outcome = config::with_session_lock(&session, |latest| {
                Ok(match config::decide_session_update(used_refresh.as_deref(), latest.as_ref(), &session) {
                    config::SessionUpdate::Write => {
                        config::delete_session(&session)?;
                        ColdStart::Removed
                    }
                    // A parallel CLI won the rotation: its on-disk set is live, so
                    // adopt it instead of reporting a dead session.
                    config::SessionUpdate::Adopt(tokens) => ColdStart::Adopted(tokens),
                    config::SessionUpdate::Skip => ColdStart::Foreign,
                })
            })?;
            match outcome {
                ColdStart::Removed | ColdStart::Foreign => {
                    return Err(error).context(format!(
                        "The sign-in session for {} was invalidated{}; another login with the same account \
                     may have replaced it. Run 'appm logon' again.",
                        endpoint,
                        if matches!(outcome, ColdStart::Removed) { " and removed" } else { "" }
                    ));
                }
                ColdStart::Adopted(tokens) => {
                    oauth.restore(tokens.clone())?;
                    *lock_known(&known_tokens) = tokens;
                    // One retry with the adopted grant; a further failure is real.
                    oauth.install_on(client.client()).await.context("Access token preparation failed")?;
                }
            }
        } else {
            return Err(error).context("Access token preparation failed");
        }
    }
    client.client().set_token_provider(Some(oauth));

    Ok(client)
}

/// Lock the mirrored token set without propagating a poisoned lock.
fn lock_known(known: &Mutex<TokenSet>) -> MutexGuard<'_, TokenSet> {
    known.lock().unwrap_or_else(|error| error.into_inner())
}

fn build_wss(host: String, port: u16, tls: &config::DaemonTlsConfig) -> Result<Arc<AppMeshClientWSS>> {
    // Plain endpoint: no CA or client certificate applies.
    if tls.plain {
        let transport_host =
            if host.contains(':') && !host.starts_with('[') { format!("[{}]", host) } else { host };
        return ClientBuilderWSS::new().address(&transport_host, port).plain_transport(true).build().context("Failed to build WSS client");
    }
    // Only skip verification when the daemon config explicitly disables it. With
    // no CA configured, leave ssl_ca_cert unset so the SDK's auto default applies
    // (App Mesh CA bundle if installed, else system CAs) — never silently disable.
    let skip_verify = !tls.verify_server;

    let transport_host = if host.contains(':') && !host.starts_with('[') { format!("[{}]", host) } else { host };
    let mut builder = ClientBuilderWSS::new().address(&transport_host, port).danger_accept_invalid_certs(skip_verify);

    if let Some(ref ca) = tls.ca_cert {
        builder = builder.ssl_ca_cert(ca.to_string_lossy().to_string());
    }
    if let (Some(ref cert), Some(ref key)) = (&tls.client_cert, &tls.client_key) {
        builder = builder.ssl_client_auth(cert.clone(), key.clone());
    }

    builder.build().context("Failed to build WSS client")
}

fn resolve_address_and_tls(cli: &Cli) -> Result<(String, u16, config::DaemonTlsConfig)> {
    let (daemon_addr, daemon_tls) = config::load_daemon_config();
    let remembered = config::load_last_endpoint();
    let explicit = cli.host_url.is_some();

    // Endpoint: explicit -H, else the remembered default, else local Engine config, else loopback.
    let (host, port, plain) = if let Some(ref url) = cli.host_url {
        let (host, port) = parse_url(url)?;
        (host, port, url_scheme_is_plain(url)?)
    } else if let Some(ref endpoint) = remembered {
        (endpoint.host.clone(), endpoint.port, endpoint.plain)
    } else if let Some((host, port)) = daemon_addr.clone() {
        (host, port, daemon_tls.plain)
    } else {
        ("127.0.0.1".to_string(), config::DEFAULT_WSS_PORT, false)
    };

    let local_engine = daemon_addr.as_ref().is_some_and(|address| address == &(host.clone(), port));
    let mut tls = if local_engine && (!explicit || plain == daemon_tls.plain) {
        // The local Engine is authoritative for its own listener and certificates.
        daemon_tls
    } else {
        // A remote endpoint uses its recorded settings; never local key material.
        let mut tls = config::DaemonTlsConfig { plain, ..config::DaemonTlsConfig::default() };
        if let Some(endpoint) = remembered.filter(|e| e.host == host && e.port == port && e.plain == plain) {
            tls.verify_server = endpoint.verify_server;
            tls.ca_cert = endpoint.ca_cert;
        }
        tls
    };
    // Explicit flags describe this invocation and are remembered at logon.
    if let Some(ref ca) = cli.ca_cert {
        tls.ca_cert = Some(ca.clone());
        tls.verify_server = true;
    }
    if cli.no_verify {
        tls.ca_cert = None;
        tls.verify_server = false;
    }
    Ok((host, port, tls))
}

/// True for the plaintext schemes (the TLS-at-gateway deployment shape).
fn url_scheme_is_plain(url: &str) -> Result<bool> {
    let parsed = if url.contains("://") {
        url::Url::parse(url).context("Invalid URL")?
    } else {
        url::Url::parse(&format!("wss://{}", url)).context("Invalid Engine address")?
    };
    Ok(matches!(parsed.scheme(), "ws" | "http"))
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
    if !matches!(parsed.scheme(), "wss" | "https" | "ws" | "http")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || (parsed.path() != "" && parsed.path() != "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!("Engine URL must be a WSS/HTTPS (or WS/HTTP for plain transport) origin without credentials, path, query, or fragment");
    }
    let host = parsed.host_str().ok_or_else(|| anyhow::anyhow!("Engine URL is missing a host"))?.to_string();
    let port = parsed.port().unwrap_or(default_port);
    Ok((host, port))
}

/// The scheme-aware canonical endpoint used as the sign-in session key.
fn canonical_endpoint(host: &str, port: u16, plain: bool) -> String {
    let scheme = if plain { "ws" } else { "wss" };
    if host.contains(':') && !host.starts_with('[') {
        format!("{}://[{}]:{}", scheme, host, port)
    } else {
        format!("{}://{}:{}", scheme, host, port)
    }
}

/// A stored token may ride out a discovery outage only while it is still valid.
fn stored_token_usable(session: &config::StoredSession) -> bool {
    !session.tokens.is_expired()
}

/// The refresh grant is usable only when the session holds a refresh token and
/// the Engine still advertises refresh-token support (older daemons omit the
/// field, which means supported).
fn refresh_grant_usable(advertised: &serde_json::Value, session: &config::StoredSession) -> bool {
    advertised.get("refresh_token").and_then(serde_json::Value::as_bool).unwrap_or(true)
        && session.tokens.refresh_token.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use appmesh::{OAuthConfig, TokenSet};

    fn session_with_expiry(expires_at: Option<u64>) -> config::StoredSession {
        config::StoredSession::new(
            "wss://engine:6063".to_string(),
            OAuthConfig::new("https://auth.example", "https://auth.example", "appmesh-cli"),
            TokenSet {
                access_token: "access-token".into(),
                refresh_token: Some("refresh-token".into()),
                expires_at,
                refresh_at: None,
                token_type: "Bearer".into(),
                scope: None,
            },
        )
    }

    #[test]
    fn stored_token_rides_out_discovery_outage_until_expiry() {
        // 4102444800 is 2100-01-01; the far-future token survives an outage.
        assert!(stored_token_usable(&session_with_expiry(Some(4_102_444_800))));
        assert!(!stored_token_usable(&session_with_expiry(Some(1_000_000_000))));
    }

    #[test]
    fn stored_token_without_expiry_is_usable() {
        assert!(stored_token_usable(&session_with_expiry(None)));
    }

    #[test]
    fn refresh_grant_requires_stored_token_and_engine_support() {
        // Older daemons omit refresh_token entirely; a stored grant keeps working.
        let advertised = serde_json::json!({"issuer" : "https://auth.example"});
        let session = session_with_expiry(Some(4_102_444_800));
        assert!(refresh_grant_usable(&advertised, &session));

        // A session that never received a refresh token has nothing to renew with.
        let mut without_grant = session_with_expiry(Some(4_102_444_800));
        without_grant.tokens.refresh_token = None;
        assert!(!refresh_grant_usable(&advertised, &without_grant));

        // An Engine that disabled refresh tokens must not be sent a refresh grant.
        let disabled = serde_json::json!({"refresh_token" : false});
        assert!(!refresh_grant_usable(&disabled, &session));
    }
}
