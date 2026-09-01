//! Optional live coverage for the standards-based Dex provider.
//!
//! These tests are skipped unless DEX_ISSUER and DEX_ACCESS_URL are set. They never
//! use a username/password grant and never send refresh tokens to App Mesh.

use appmesh::{OAuthClient, OAuthConfig, DevicePoll};

fn live_config() -> Option<OAuthConfig> {
    let issuer = std::env::var("DEX_ISSUER").ok()?;
    let access_url = std::env::var("DEX_ACCESS_URL").ok()?;
    Some(
        OAuthConfig::new(
            issuer,
            access_url,
            std::env::var("DEX_CLIENT_ID").unwrap_or_else(|_| "appmesh-cli".into()),
        )
        .audience(std::env::var("DEX_AUDIENCE").unwrap_or_else(|_| "appmesh-api".into())),
    )
}

#[tokio::test]
async fn live_device_flow_authorization_pending() {
    let Some(config) = live_config() else {
        eprintln!("SKIP live_device_flow_authorization_pending: Dex environment is not set");
        return;
    };
    let oauth = OAuthClient::discover(config).await.expect("discover oauth");
    let device = oauth.request_device_authorization().await.expect("request device authorization");
    assert!(!device.device_code.is_empty());
    assert!(!device.user_code.is_empty());
    assert!(device.verification_uri.as_deref().is_some_and(|uri| !uri.is_empty()));
    assert!(matches!(
        oauth.poll_device_token(&device).await.expect("poll device token"),
        DevicePoll::Pending | DevicePoll::SlowDown
    ));
}

// Plain-HTTP issuers stay fail-closed unless the caller opts in; the opt-in is
// the supported route for cluster issuers on a protected network.
#[tokio::test]
async fn plain_http_issuer_requires_opt_in() {
    const UNROUTABLE_HTTP_ISSUER: &str = "http://issuer.invalid:6062/auth";

    let error = OAuthClient::discover(OAuthConfig::new(
        UNROUTABLE_HTTP_ISSUER,
        UNROUTABLE_HTTP_ISSUER,
        "appmesh-cli",
    ))
    .await
    .expect_err("plain-HTTP issuer must be rejected by default");
    assert!(error.to_string().contains("must use HTTPS"), "got: {error}");

    let relaxed = OAuthClient::discover(
        OAuthConfig::new(UNROUTABLE_HTTP_ISSUER, UNROUTABLE_HTTP_ISSUER, "appmesh-cli")
            .allow_plain_http(true),
    )
    .await
    .expect_err("the .invalid host never resolves");
    assert!(!relaxed.to_string().contains("must use HTTPS"), "got: {relaxed}");
}
