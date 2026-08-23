//! Optional live coverage for the standards-based Dex provider.
//!
//! These tests are skipped unless DEX_ISSUER and DEX_ACCESS_URL are set. They never
//! use a username/password grant and never send refresh tokens to App Mesh.

use appmesh::{DexOAuthClient, DexOAuthConfig, DevicePoll};

fn live_config() -> Option<DexOAuthConfig> {
    let issuer = std::env::var("DEX_ISSUER").ok()?;
    let access_url = std::env::var("DEX_ACCESS_URL").ok()?;
    Some(
        DexOAuthConfig::new(
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
    let oauth = DexOAuthClient::discover(config).await.expect("discover Dex");
    let device = oauth.request_device_authorization().await.expect("request device authorization");
    assert!(!device.device_code.is_empty());
    assert!(!device.user_code.is_empty());
    assert!(device.verification_uri.as_deref().is_some_and(|uri| !uri.is_empty()));
    assert!(matches!(
        oauth.poll_device_token(&device).await.expect("poll device token"),
        DevicePoll::Pending | DevicePoll::SlowDown
    ));
}
