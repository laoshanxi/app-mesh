use anyhow::{bail, Context, Result};
use appmesh::{AppMeshError, OAuthClient, OAuthConfig, TokenProvider};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

use crate::app::{Cli, LoginfoArgs, LogoffArgs, LogonArgs};
use crate::client::{build_client, build_client_with_auth, get_current_endpoint};
use crate::output::format::short_principal;
use crate::util::config::{self, StoredSession};
use crate::util::password::{prompt_password, prompt_username};

#[derive(Debug, Deserialize)]
struct EngineAuthConfig {
    issuer: String,
    audience: String,
    public_client_id: String,
    #[serde(default)]
    browser_entry: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    flows: Vec<String>,
    #[serde(default)]
    first_admin_enrollment: FirstAdminEnrollment,
}

#[derive(Debug, Default, Deserialize)]
struct FirstAdminEnrollment {
    #[serde(default)]
    available: bool,
    subject: Option<String>,
}

// The built-in password source matches packaged identities by email. Expand
// the packaged short names (admin and guest) to their email form.
const BUILTIN_EMAIL_DOMAIN: &str = "appmesh.local";

fn builtin_email(username: &str) -> Option<String> {
    (!username.contains('@')).then(|| format!("{username}@{BUILTIN_EMAIL_DOMAIN}"))
}

// Cluster issuers are plain HTTP on a protected network; the opt-in keeps the
// default fail-closed for every other deployment.
fn env_allows_plain_http() -> bool {
    std::env::var("APPMESH_AUTH_ALLOW_HTTP")
        .map(|value| !matches!(value.trim().to_ascii_lowercase().as_str(), "" | "0" | "false" | "no"))
        .unwrap_or(false)
}

pub async fn logon(cli: &Cli, args: &LogonArgs) -> Result<i32> {
    let engine = build_client(cli).await?;
    let engine_endpoint = get_current_endpoint(cli)?;
    // Discovery goes over the HTTPS side channel: the WSS transport presents its
    // bearer only at upgrade time, so it must stay unconnected until a token exists.
    let advertised: EngineAuthConfig = serde_json::from_value(
        engine
            .get_auth_config_https(cli.forward_to.as_deref())
            .await
            .context("Engine OAuth discovery failed")?,
    )
    .context("Engine returned invalid OAuth configuration")?;
    let password_login = advertised.flows.iter().any(|flow| flow == "password");
    let first_admin_enrollment = advertised.first_admin_enrollment;
    let issuer = advertised.issuer;
    let access_url = args
        .auth_access_url
        .clone()
        .or_else(|| std::env::var("APPMESH_AUTH_ACCESS_URL").ok())
        // The advertised browser_entry is a redirect origin for browsers, not a
        // client discovery route: it carries no issuer path and may use TLS the
        // CLI does not trust. Discovery defaults to the issuer itself.
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| issuer.clone());

    let oauth_config = OAuthConfig::new(issuer, access_url, advertised.public_client_id)
        .audience(advertised.audience)
        .scopes(advertised.scopes)
        .allow_plain_http(args.auth_allow_http || env_allows_plain_http());
    // The advertised browser entry is a front-channel origin only: the SDK maps
    // login and device verification URLs onto it so the browser gets the entry
    // that serves the login assets and the callback relay. Discovery and token
    // requests keep using the access URL.
    let oauth_config = match advertised.browser_entry.trim().is_empty() {
        true => oauth_config,
        false => oauth_config.browser_entry(advertised.browser_entry.trim()),
    };
    let oauth = OAuthClient::discover(oauth_config.clone())
        .await
        .context("Authentication service discovery failed")?;

    let tokens = if args.browser {
        browser_login(&oauth, args.login_timeout).await?
    } else if args.device {
        device_login(&oauth).await?
    } else {
        if !password_login {
            bail!("The selected Engine does not enable built-in password login. Use --device or --browser.");
        }
        let username = match args.username.as_deref() {
            Some(value) if !value.trim().is_empty() => value.trim().to_string(),
            Some(_) => bail!("Username cannot be empty"),
            None => prompt_username("Username: ")?,
        };
        if username.is_empty() {
            bail!("Username cannot be empty");
        }
        let password = Zeroizing::new(prompt_password("Password: ")?);
        if password.is_empty() {
            bail!("Password cannot be empty");
        }
        match oauth.password_login(&username, password.as_str()).await {
            Ok(tokens) => tokens,
            Err(error) => {
                // Retry a rejected short name once as <name>@<domain>; a full
                // email or a non-auth failure surfaces the original error.
                let retry = builtin_email(&username).filter(|_| {
                    matches!(&error, AppMeshError::RequestFailed { status, .. } if status.as_u16() == 401)
                });
                match retry {
                    Some(email) => oauth
                        .password_login(&email, password.as_str())
                        .await
                        .context("Built-in password login failed")?,
                    None => return Err(error).context("Built-in password login failed"),
                }
            }
        }
    };

    // Validate the access token at the resource server before reporting success. The
    // refresh token remains only in the OAuth/CLI session and is never installed.
    engine.client().set_token(&tokens.access_token);
    let mut principal = engine
        .client()
        .get_current_principal()
        .await
        .context("Engine rejected the access token")?;
    if should_enroll_first_admin(&first_admin_enrollment, &principal) {
        if cli.forward_to.is_some() {
            bail!(
                "First administrator setup cannot use --forward-to. Run 'appm logon' once on the authentication owner host."
            );
        }
        principal = engine
            .client()
            .enroll_first_admin()
            .await
            .context(
                "First administrator setup failed. Run 'appm logon' once on the authentication owner host",
            )?;
        eprintln!("Assigned the first App Mesh administrator.");
    }
    let session = StoredSession::new(engine_endpoint.clone(), oauth_config, tokens);
    config::save_session(&session)?;
    // The endpoint proved reachable and authenticated, so it may become the
    // remembered default even when it was passed explicitly with -H.
    crate::client::remember_engine_endpoint(cli)?;

    let principal_name = principal
        .get("display_name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        // No usable display name: fall back to the shortened principal ID so the
        // success line never claims an empty identity.
        .or_else(|| {
            principal
                .get("principal_id")
                .and_then(serde_json::Value::as_str)
                .filter(|id| !id.is_empty())
                .map(short_principal)
        })
        .unwrap_or_else(|| "authenticated principal".to_string());
    eprintln!("Logged on to <{}> as {}.", engine_endpoint, principal_name);
    Ok(0)
}

fn should_enroll_first_admin(
    enrollment: &FirstAdminEnrollment,
    principal: &serde_json::Value,
) -> bool {
    enrollment.available
        && enrollment.subject.as_deref().is_some_and(|expected| {
            principal.get("subject").and_then(serde_json::Value::as_str) == Some(expected)
        })
}

pub async fn logoff(cli: &Cli, args: &LogoffArgs) -> Result<i32> {
    let engine_endpoint = get_current_endpoint(cli)?;
    let Some(session) = config::load_session(&engine_endpoint)? else {
        eprintln!("No local sign-in session exists for <{}>.", engine_endpoint);
        return Ok(0);
    };

    let mut revocation_message = "Token revocation was skipped by request.".to_string();
    if !args.local_only {
        match OAuthClient::discover(session.oauth.clone()).await {
            Ok(oauth) => {
                oauth.restore(session.tokens.clone())?;
                match oauth.revoke().await {
                    Ok(true) => revocation_message = "Tokens were revoked.".into(),
                    Ok(false) => {
                        revocation_message =
                            "The authentication service does not support revocation. The access token remains valid until expiry."
                                .into()
                    }
                    Err(error) => {
                        revocation_message = format!(
                            "Token revocation failed ({}). The access token may remain valid until expiry.",
                            error
                        )
                    }
                }
            }
            Err(error) => {
                revocation_message = format!(
                    "The authentication service was unavailable for revocation ({}). The access token may remain valid until expiry.",
                    error
                )
            }
        }
    }

    config::delete_session(&session)?;
    eprintln!("Local sign-in session cleared for <{}>. {}", engine_endpoint, revocation_message);
    Ok(0)
}

pub async fn loginfo(cli: &Cli, _args: &LoginfoArgs) -> Result<i32> {
    let engine_endpoint = get_current_endpoint(cli)?;
    let client = build_client_with_auth(cli).await?;
    let principal = client
        .client()
        .get_current_principal()
        .await
        .context("The stored sign-in session is not valid at the Engine")?;
    let session = config::load_session(&engine_endpoint)?.ok_or_else(|| {
        anyhow::anyhow!("No sign-in session is configured for {}", engine_endpoint)
    })?;

    println!("Engine: {}", engine_endpoint);
    if let Some(principal_id) = principal.get("principal_id").and_then(serde_json::Value::as_str) {
        println!("Principal: {}", principal_id);
    }
    if let Some(display_name) = principal
        .get("display_name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.is_empty())
    {
        println!("Display name: {}", display_name);
    }
    if let Some(expires_at) = session.tokens.expires_at {
        println!("Access token expires at: {}", format_token_expiry(expires_at));
    }
    Ok(0)
}

/// Render an epoch-second token expiry in the system timezone. The raw integer
/// is kept as the fallback so an unformattable value is never hidden.
fn format_token_expiry(epoch: u64) -> String {
    let Ok(seconds) = i64::try_from(epoch) else {
        return epoch.to_string();
    };
    let Ok(timestamp) = jiff::Timestamp::from_second(seconds) else {
        return epoch.to_string();
    };
    timestamp
        .to_zoned(jiff::tz::TimeZone::system())
        .strftime("%Y-%m-%d %H:%M:%S %Z")
        .to_string()
}

async fn device_login(oauth: &OAuthClient) -> Result<appmesh::TokenSet> {
    let device = oauth.request_device_authorization().await?;
    let verification_uri = device
        .verification_uri_complete
        .as_deref()
        .or(device.verification_uri.as_deref())
        .unwrap_or("the verification URL supplied by the authentication service");
    eprintln!("Open {}", verification_uri);
    eprintln!("Enter code: {}", device.user_code);
    oauth
        .wait_for_device_authorization(&device)
        .await
        .context("Device authorization failed")
}

async fn browser_login(oauth: &OAuthClient, timeout_seconds: u64) -> Result<appmesh::TokenSet> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .context("bind OAuth loopback callback")?;
    let port = listener.local_addr()?.port();
    let request = oauth.authorization_request(&format!("http://127.0.0.1:{}/callback", port))?;

    if let Err(error) = open_system_browser(&request.authorization_url) {
        eprintln!("Could not open the system browser: {}", error);
        eprintln!("Open this URL manually: {}", request.authorization_url);
    } else {
        eprintln!("Opened the system browser for sign-in.");
    }

    let code = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_seconds.max(1)),
        wait_for_callback(&listener, &request.state),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Timed out while waiting for the browser callback"))??;
    oauth
        .exchange_authorization_code(&code, &request)
        .await
        .context("Authorization code exchange failed")
}

/// Upper bound for a callback request head, matching the previous single-read buffer.
const CALLBACK_HEAD_LIMIT: usize = 16 * 1024;

enum HeadProgress {
    /// More TCP segments are needed before the head can be parsed.
    Incomplete,
    /// The CRLFCRLF terminator arrived; the head is complete.
    Complete,
    /// The peer exceeded the size limit without ever completing the head.
    Overflow,
}

/// Accumulates the raw bytes of a callback request head across TCP segments.
/// Browsers can split the head across segment boundaries, so one read must not
/// be trusted to deliver the request line and headers in full.
struct CallbackHead {
    bytes: Vec<u8>,
}

impl CallbackHead {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn push(&mut self, chunk: &[u8]) -> HeadProgress {
        self.bytes.extend_from_slice(chunk);
        if find_head_end(&self.bytes).is_some() {
            HeadProgress::Complete
        } else if self.bytes.len() > CALLBACK_HEAD_LIMIT {
            HeadProgress::Overflow
        } else {
            HeadProgress::Incomplete
        }
    }

    /// The complete head, without the terminator or any bytes that follow it.
    fn into_head(self) -> Result<String> {
        let end = find_head_end(&self.bytes).context("OAuth callback head was incomplete")?;
        std::str::from_utf8(&self.bytes[..end])
            .context("OAuth callback was not UTF-8")
            .map(str::to_string)
    }
}

fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Read the callback request head incrementally until the CRLFCRLF terminator,
/// EOF, or the size cap. Peers that never deliver a complete head yield None so
/// they get a 400 and the caller keeps waiting for the real callback; overall
/// time is bounded by the login timeout around `wait_for_callback`.
async fn read_callback_head(stream: &mut TcpStream) -> Result<Option<String>> {
    let mut head = CallbackHead::new();
    let mut chunk = vec![0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await.context("read OAuth callback")?;
        if read == 0 {
            return Ok(None);
        }
        match head.push(&chunk[..read]) {
            HeadProgress::Complete => return head.into_head().map(Some),
            HeadProgress::Overflow => return Ok(None),
            HeadProgress::Incomplete => {}
        }
    }
}

async fn wait_for_callback(listener: &TcpListener, expected_state: &str) -> Result<String> {
    loop {
        let (mut stream, peer) = listener.accept().await.context("accept OAuth callback")?;
        if !peer.ip().is_loopback() {
            respond(&mut stream, "403 Forbidden", "Loopback clients only.").await?;
            continue;
        }
        let Some(request) = read_callback_head(&mut stream).await? else {
            respond(&mut stream, "400 Bad Request", "Invalid OAuth callback.").await?;
            continue;
        };
        let mut request_parts = request.lines().next().into_iter().flat_map(str::split_whitespace);
        let (Some(method), Some(target), Some(version)) =
            (request_parts.next(), request_parts.next(), request_parts.next())
        else {
            respond(&mut stream, "400 Bad Request", "Invalid OAuth callback.").await?;
            continue;
        };
        if method != "GET" || !version.starts_with("HTTP/1.") || request_parts.next().is_some() {
            respond(&mut stream, "400 Bad Request", "Invalid OAuth callback.").await?;
            continue;
        }
        let callback = url::Url::parse(&format!("http://127.0.0.1{}", target))
            .context("parse OAuth callback")?;
        if callback.path() != "/callback" {
            respond(&mut stream, "404 Not Found", "Not found.").await?;
            continue;
        }
        let params: Vec<(String, String)> = callback.query_pairs().into_owned().collect();
        let states: Vec<&str> = params
            .iter()
            .filter(|(key, _)| key == "state")
            .map(|(_, value)| value.as_str())
            .collect();
        if states.len() != 1 || states[0] != expected_state {
            respond(&mut stream, "400 Bad Request", "OAuth state did not match; retrying.").await?;
            continue;
        }
        if let Some(error) = single_callback_value(&params, "error")? {
            respond(&mut stream, "400 Bad Request", "Sign-in was not completed.").await?;
            bail!("Authorization failed: {}", sanitize_callback_value(error));
        }
        let code = single_callback_value(&params, "code")?
            .filter(|code| !code.is_empty())
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("The callback did not include an authorization code"))?;
        respond(
            &mut stream,
            "200 OK",
            "App Mesh login completed. You can close this window.",
        )
        .await?;
        return Ok(code);
    }
}

fn single_callback_value<'a>(params: &'a [(String, String)], name: &str) -> Result<Option<&'a str>> {
    let mut values = params
        .iter()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.as_str());
    let first = values.next();
    if values.next().is_some() {
        bail!("The callback included duplicate {} parameters", name);
    }
    Ok(first)
}

fn sanitize_callback_value(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(128)
        .collect()
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",
        status,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await.context("write OAuth callback response")?;
    stream.shutdown().await.context("close OAuth callback response")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        builtin_email, format_token_expiry, should_enroll_first_admin, CallbackHead,
        FirstAdminEnrollment, HeadProgress, CALLBACK_HEAD_LIMIT,
    };

    #[test]
    fn builtin_email_maps_short_names() {
        // The built-in password source rejects bare "admin" and matches by email.
        assert_eq!(builtin_email("admin").as_deref(), Some("admin@appmesh.local"));
        assert_eq!(builtin_email("guest").as_deref(), Some("guest@appmesh.local"));
    }

    #[test]
    fn builtin_email_never_rewrites_addresses() {
        // Appending a second domain would retry a doomed request and mask the
        // original failure.
        assert_eq!(builtin_email("admin@appmesh.local"), None);
    }

    #[test]
    fn token_expiry_is_human_readable() {
        // 1783000000 is 2026-07-02T04:26:40Z; any local offset (max ±14h) keeps
        // the rendered date in July 2026, so the assertion holds in every tz.
        let formatted = format_token_expiry(1_783_000_000);
        assert_ne!(formatted, "1783000000", "raw epoch must not be shown as-is");
        assert!(formatted.contains(':'), "expected HH:MM:SS in {}", formatted);
        assert!(formatted.contains("2026-07"), "unexpected date in {}", formatted);
    }

    #[test]
    fn token_expiry_out_of_range_falls_back_to_epoch() {
        assert_eq!(format_token_expiry(u64::MAX), u64::MAX.to_string());
    }

    #[test]
    fn first_admin_enrollment_requires_open_window_and_exact_subject() {
        let enrollment = FirstAdminEnrollment {
            available: true,
            subject: Some("packaged-subject".into()),
        };
        let packaged = serde_json::json!({"subject": "packaged-subject"});
        let other = serde_json::json!({"subject": "other-subject"});
        assert!(should_enroll_first_admin(&enrollment, &packaged));
        assert!(!should_enroll_first_admin(&enrollment, &other));

        let closed = FirstAdminEnrollment {
            available: false,
            subject: Some("packaged-subject".into()),
        };
        assert!(!should_enroll_first_admin(&closed, &packaged));
    }

    #[test]
    fn callback_head_assembles_across_reads() {
        // The terminator and request line arrive in separate reads: the head must
        // only be parsed once the final blank line has been received.
        let request =
            b"GET /callback?code=xyz&state=s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        let (first, second) = request.split_at(request.len() - 3);

        let mut head = CallbackHead::new();
        assert!(matches!(head.push(first), HeadProgress::Incomplete));
        assert!(matches!(head.push(second), HeadProgress::Complete));
        let assembled = head.into_head().expect("complete head must parse");
        assert!(
            assembled.starts_with("GET /callback?code=xyz&state=s HTTP/1.1"),
            "request line must survive reassembly: {}",
            assembled
        );
        assert!(!assembled.contains("\r\n\r\n"), "terminator must not leak into the head");
    }

    #[test]
    fn callback_head_assembles_one_byte_at_a_time() {
        let request = b"HEAD /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        let mut head = CallbackHead::new();
        for byte in request.iter().take(request.len() - 1) {
            assert!(
                matches!(head.push(&[*byte]), HeadProgress::Incomplete),
                "head must stay incomplete before the final blank line"
            );
        }
        assert!(matches!(head.push(b"\r\n\r\n"), HeadProgress::Complete));
        let assembled = head.into_head().expect("complete head must parse");
        assert!(assembled.starts_with("HEAD /favicon.ico HTTP/1.1"));
    }

    #[test]
    fn callback_head_rejects_unbounded_streams() {
        let mut head = CallbackHead::new();
        let flood = vec![b'X'; CALLBACK_HEAD_LIMIT + 1];
        assert!(matches!(head.push(&flood), HeadProgress::Overflow));
    }
}

fn open_system_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = std::process::Command::new("open");
        command.arg(url);
        command
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = std::process::Command::new("explorer.exe");
        command.arg(url);
        command
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut command = std::process::Command::new("xdg-open");
        command.arg(url);
        command
    };
    #[cfg(not(any(unix, target_os = "windows")))]
    bail!("automatic browser opening is not supported on this platform");

    let status = command.status().context("start system browser")?;
    // explorer.exe routinely exits with a non-zero status (typically 1) even
    // after successfully handing the URL to the default browser, so on Windows
    // only the inability to spawn the launcher counts as failure.
    if !status.success() && !cfg!(windows) {
        bail!("system browser launcher exited with {}", status);
    }
    Ok(())
}
