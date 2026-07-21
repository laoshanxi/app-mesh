// oauth_test.rs
//! Live integration tests for the direct-Keycloak OAuth2 client.
//!
//! These tests require a running Keycloak and are gated by environment variables
//! (they skip when `KEYCLOAK_URL` is unset, following the SDK convention for
//! environment-dependent tests):
//!
//! ```bash
//! export KEYCLOAK_URL=http://localhost:8080       # Keycloak base URL
//! export KEYCLOAK_REALM=appmesh-realm             # optional, default shown
//! export KEYCLOAK_CLIENT_ID=appmesh-client        # optional, default shown
//! export KEYCLOAK_USER=mesh                       # optional, default shown
//! export KEYCLOAK_PASSWORD=...                    # required (never committed)
//! export APPMESH_Keycloak_client_secret=...       # confidential client only
//! cargo test --test oauth_test -- --nocapture
//! ```

use appmesh::{AppMeshClientOAuth, ClientBuilder, DevicePoll, KeycloakClient, OAuth2Config};

/// Build the Keycloak config from env, or `None` (skip) when KEYCLOAK_URL is unset.
fn live_config() -> Option<OAuth2Config> {
    let auth_server_url = std::env::var("KEYCLOAK_URL").ok()?;
    Some(OAuth2Config {
        auth_server_url,
        realm: std::env::var("KEYCLOAK_REALM").unwrap_or_else(|_| "appmesh-realm".to_string()),
        client_id: std::env::var("KEYCLOAK_CLIENT_ID").unwrap_or_else(|_| "appmesh-client".to_string()),
        // Secret comes from the environment only; it is never logged or printed.
        client_secret: std::env::var("APPMESH_Keycloak_client_secret").ok(),
    })
}

/// Username/password from env. Password is required for the login tests.
fn live_credentials() -> Option<(String, String)> {
    let username = std::env::var("KEYCLOAK_USER").unwrap_or_else(|_| "mesh".to_string());
    let password = std::env::var("KEYCLOAK_PASSWORD").ok()?;
    Some((username, password))
}

/// Live: password login -> Bearer wiring -> userinfo -> renew (rotation) -> logout.
#[tokio::test]
async fn live_password_login_userinfo_renew_logout() {
    let Some(config) = live_config() else {
        eprintln!("SKIP live_password_login_userinfo_renew_logout: KEYCLOAK_URL not set");
        return;
    };
    let Some((username, password)) = live_credentials() else {
        eprintln!("SKIP live_password_login_userinfo_renew_logout: KEYCLOAK_PASSWORD not set");
        return;
    };

    // Wrap a (daemon-less) App Mesh client to verify the Bearer token wiring;
    // set_token is local, so no daemon needs to run.
    let appmesh = ClientBuilder::new().build().expect("build AppMeshClient");
    let client = AppMeshClientOAuth::new(config, appmesh).expect("build AppMeshClientOAuth");

    // 1. Password login (Direct Access Grant).
    client.login(&username, &password, None).await.expect("Keycloak password login failed");
    let access_token_1 = client.keycloak().access_token().expect("no access_token after login");
    let refresh_token_1 = client.keycloak().refresh_token().expect("no refresh_token after login");

    // The Keycloak access token must be installed on the App Mesh client (Bearer).
    assert_eq!(
        client.get_access_token().as_deref(),
        Some(access_token_1.as_str()),
        "Keycloak access token was not wired into the App Mesh client"
    );

    // 2. Userinfo directly from Keycloak.
    let userinfo = client.get_oauth_userinfo().await.expect("Keycloak userinfo failed");
    assert_eq!(
        userinfo.get("preferred_username").and_then(|v| v.as_str()),
        Some(username.as_str()),
        "userinfo preferred_username mismatch: {userinfo}"
    );

    // 3. Renew: Keycloak rotates the refresh token; the full new response is stored.
    client.renew_token().await.expect("Keycloak token renewal failed");
    let access_token_2 = client.keycloak().access_token().expect("no access_token after renew");
    let refresh_token_2 = client.keycloak().refresh_token().expect("no refresh_token after renew");
    assert_ne!(refresh_token_1, refresh_token_2, "refresh token was not rotated on renew");
    assert_eq!(
        client.get_access_token().as_deref(),
        Some(access_token_2.as_str()),
        "renewed access token was not wired into the App Mesh client"
    );

    // 4. Keycloak logout (daemon logout is expected to fail — no daemon in this test).
    client.keycloak().logout().await.expect("Keycloak logout failed");
}

/// Live, non-interactive: device authorization issues codes, and a single token
/// poll before user approval reports `authorization_pending`.
#[tokio::test]
async fn live_device_flow_authorization_pending() {
    let Some(config) = live_config() else {
        eprintln!("SKIP live_device_flow_authorization_pending: KEYCLOAK_URL not set");
        return;
    };

    let keycloak = KeycloakClient::new(config).expect("build KeycloakClient");

    // 1. Device authorization request (RFC 8628 §3.1/§3.2).
    let device = keycloak
        .request_device_authorization(appmesh::DEFAULT_OAUTH_SCOPE)
        .await
        .expect("device authorization request failed (is the Device Authorization Grant enabled on the client?)");
    assert!(!device.device_code.is_empty(), "missing device_code");
    assert!(!device.user_code.is_empty(), "missing user_code");
    assert!(
        device.verification_uri.as_deref().is_some_and(|u| !u.is_empty()),
        "missing verification_uri"
    );
    assert!(device.interval >= 1, "unexpected polling interval: {}", device.interval);
    assert!(device.expires_in >= 1, "unexpected expires_in: {}", device.expires_in);

    // 2. Poll once WITHOUT user approval: must parse as authorization_pending.
    let poll = keycloak.poll_device_token(&device).await.expect("device token poll errored");
    assert_eq!(poll, DevicePoll::Pending, "expected authorization_pending on first poll");
}
