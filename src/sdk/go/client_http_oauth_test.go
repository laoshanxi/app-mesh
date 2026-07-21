// client_http_oauth_test.go
//
// Live integration tests against a real Keycloak instance.
// Gated by the KEYCLOAK_URL environment variable and skipped cleanly when it is
// unset, so normal CI runs are unaffected.
//
// Configuration (environment variables; defaults are the documented open-source
// test values for the local Keycloak dev instance):
//
//	KEYCLOAK_URL                     - e.g. http://localhost:8080 (required to run)
//	KEYCLOAK_REALM                   - default "appmesh-realm"
//	KEYCLOAK_CLIENT_ID               - default "appmesh-client"
//	KEYCLOAK_USER                    - default "mesh"
//	KEYCLOAK_PASSWORD                - default "mesh123" (documented test default)
//	APPMESH_Keycloak_client_secret   - client secret (optional; never printed/logged)
package appmesh

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func liveOAuthConfig(t *testing.T) OAuth2Config {
	t.Helper()
	kcURL := os.Getenv("KEYCLOAK_URL")
	if kcURL == "" {
		t.Skip("KEYCLOAK_URL not set; skipping live Keycloak OAuth tests")
	}
	return OAuth2Config{
		AuthServerURL: kcURL,
		Realm:         envOrDefault("KEYCLOAK_REALM", "appmesh-realm"),
		ClientID:      envOrDefault("KEYCLOAK_CLIENT_ID", "appmesh-client"),
		ClientSecret:  os.Getenv("APPMESH_Keycloak_client_secret"), // never printed or logged
	}
}

func newLiveOAuthClient(t *testing.T) *AppMeshClientOAuth {
	t.Helper()
	client, err := NewHTTPClientOAuth(liveOAuthConfig(t), Option{})
	require.NoError(t, err)
	return client
}

// TestOAuthLiveKeycloakPasswordFlow exercises the Direct Access Grant end to end:
// password login -> userinfo -> renew (refresh token rotation) -> Keycloak logout.
func TestOAuthLiveKeycloakPasswordFlow(t *testing.T) {
	client := newLiveOAuthClient(t)
	defer client.AppMeshClient.Close() // base cleanup only; the Keycloak session ends below

	username := envOrDefault("KEYCLOAK_USER", "mesh")
	password := envOrDefault("KEYCLOAK_PASSWORD", "mesh123") // documented open-source test default

	// Password login (Direct Access Grant).
	require.NoError(t, client.Login(username, password, ""))
	require.NotEmpty(t, client.accessTokenValue())
	require.NotEmpty(t, client.refreshTokenValue())
	// The Keycloak access token must be applied as the Bearer token for daemon calls.
	require.Equal(t, client.accessTokenValue(), client.GetToken())

	// Userinfo directly from Keycloak (does not involve the daemon).
	claims, err := client.GetOauthUserinfo()
	require.NoError(t, err)
	require.Equal(t, username, claims["preferred_username"])

	// Renew: Keycloak rotates the refresh token, the full new response must be stored.
	oldRefresh := client.refreshTokenValue()
	ok, err := client.RenewToken()
	require.NoError(t, err)
	require.True(t, ok)
	require.NotEmpty(t, client.accessTokenValue())
	require.NotEqual(t, oldRefresh, client.refreshTokenValue(), "Keycloak must rotate the refresh token on renew")
	require.Equal(t, client.accessTokenValue(), client.GetToken())

	// Keycloak end-session: the refresh token must no longer be usable afterwards.
	// (Logout() additionally logs off the App Mesh daemon, which is not part of this
	// Keycloak-only live environment, so the Keycloak leg is exercised directly.)
	require.NoError(t, client.keycloakLogout(client.refreshTokenValue()))
	_, err = client.RenewToken()
	require.Error(t, err, "refresh token must be invalid after Keycloak logout")
}

// TestOAuthLiveKeycloakDeviceFlowNonInteractive exercises the RFC 8628 endpoints
// without human interaction: it requests a device authorization and polls the token
// endpoint exactly once, expecting the authorization_pending error. It never waits
// for user approval.
func TestOAuthLiveKeycloakDeviceFlowNonInteractive(t *testing.T) {
	client := newLiveOAuthClient(t)
	defer client.AppMeshClient.Close()

	// Device authorization request (RFC 8628 sections 3.1/3.2).
	form := client.clientForm()
	form.Set("scope", oauthDefaultScope)
	code, raw, err := client.postForm(client.oidcEndpoint("auth/device"), form)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code, "device authorization failed: %s", string(raw))

	var device DeviceAuthResponse
	require.NoError(t, json.Unmarshal(raw, &device))
	require.NotEmpty(t, device.DeviceCode)
	require.NotEmpty(t, device.UserCode)
	require.NotEmpty(t, device.VerificationURI)
	require.Greater(t, device.Interval, 0)
	require.Greater(t, device.ExpiresIn, 0)

	// Poll once without approval: RFC 8628 section 3.5 requires HTTP 400 with
	// error=authorization_pending, which the device flow keeps polling on.
	poll := client.clientForm()
	poll.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	poll.Set("device_code", device.DeviceCode)
	code, raw, err = client.postForm(client.oidcEndpoint("token"), poll)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, code)
	require.Equal(t, "authorization_pending", oauthErrorCode(raw))
}
