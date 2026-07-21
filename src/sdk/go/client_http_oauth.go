// client_http_oauth.go
package appmesh

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// oauthDefaultScope requests identity claims so userinfo returns preferred_username/email.
const oauthDefaultScope = "openid profile email"

// OAuth2Config holds the Keycloak connection settings for AppMeshClientOAuth.
type OAuth2Config struct {
	AuthServerURL string // Keycloak server URL, e.g. "https://keycloak.example.com/"
	Realm         string // Keycloak realm name
	ClientID      string // Keycloak client ID
	ClientSecret  string // Keycloak client secret (optional, confidential clients only)
}

// DeviceAuthResponse is the device authorization response (RFC 8628 section 3.2).
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// KeycloakToken is a Keycloak token endpoint response. Keycloak rotates the refresh
// token on every grant, so the complete response is stored after each token request.
type KeycloakToken struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

// AppMeshClientOAuth is an AppMeshClient that authenticates directly against Keycloak
// instead of the App Mesh daemon. The Keycloak access token is applied as the Bearer
// token for all daemon REST calls made through the embedded client.
//
// Token renewal goes directly to Keycloak via RenewToken; the base client's automatic
// refresh loop (which renews via the daemon) is therefore always disabled in this mode.
type AppMeshClientOAuth struct {
	*AppMeshClient

	oauth2    OAuth2Config
	oauthHTTP *http.Client

	tokenMu sync.Mutex
	token   KeycloakToken

	// Injection points for tests (default to time.Now / time.Sleep).
	timeNow func() time.Time
	sleep   func(time.Duration)
}

// NewHTTPClientOAuth builds an HTTP-backed App Mesh client that authenticates directly
// against Keycloak. It does not authenticate; call Login or LoginDeviceFlow afterward.
func NewHTTPClientOAuth(oauth2 OAuth2Config, options Option) (*AppMeshClientOAuth, error) {
	if oauth2.AuthServerURL == "" || oauth2.Realm == "" || oauth2.ClientID == "" {
		return nil, fmt.Errorf("oauth2 AuthServerURL, Realm and ClientID are required")
	}
	// Direct-Keycloak mode renews via RenewToken() against Keycloak; the base client's
	// auto-refresh loop would call the daemon's /appmesh/token/renew instead, so keep it off.
	options.AutoRefreshToken = false
	base, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	return newOAuthClientWithBase(oauth2, base, options.HTTPTimeout), nil
}

// newOAuthClientWithBase wires an OAuth client around an existing base client (test seam).
func newOAuthClientWithBase(oauth2 OAuth2Config, base *AppMeshClient, timeout time.Duration) *AppMeshClientOAuth {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &AppMeshClientOAuth{
		AppMeshClient: base,
		oauth2:        oauth2,
		oauthHTTP:     &http.Client{Timeout: timeout},
		timeNow:       time.Now,
		sleep:         time.Sleep,
	}
}

// Login authenticates against Keycloak using the Direct Access Grant (grant_type=password)
// and applies the issued access token as the Bearer token for daemon REST calls.
// totpCode is optional and sent verbatim as a string when non-empty: converting it to an
// integer would strip leading zeros (e.g. "012345" -> 12345).
func (r *AppMeshClientOAuth) Login(username string, password string, totpCode string) error {
	if username == "" || password == "" {
		return fmt.Errorf("username and password are required")
	}

	form := r.clientForm()
	form.Set("grant_type", "password")
	form.Set("username", username)
	form.Set("password", password)
	form.Set("scope", oauthDefaultScope)
	if totpCode != "" {
		form.Set("totp", totpCode)
	}

	code, raw, err := r.postForm(r.oidcEndpoint("token"), form)
	if err != nil {
		return fmt.Errorf("Keycloak login request failed: %w", err)
	}
	if code != http.StatusOK {
		return newAPIError("Keycloak login", code, string(raw))
	}
	return r.applyTokenResponse(raw)
}

// LoginDeviceFlow authenticates via the OAuth 2.0 Device Authorization Grant (RFC 8628).
//
// For browserless/input-constrained environments: the user opens
// VerificationURIComplete (or VerificationURI plus UserCode) on another device, and this
// call polls the token endpoint until approval, denial, or expiry. Requires "OAuth 2.0
// Device Authorization Grant" enabled on the Keycloak client.
//
// onPrompt receives the device authorization response to present the sign-in
// instructions to the user; nil defaults to printing them to stdout.
func (r *AppMeshClientOAuth) LoginDeviceFlow(onPrompt func(DeviceAuthResponse)) error {
	form := r.clientForm()
	form.Set("scope", oauthDefaultScope)
	code, raw, err := r.postForm(r.oidcEndpoint("auth/device"), form)
	if err != nil {
		return fmt.Errorf("Keycloak device authorization request failed: %w", err)
	}
	if code != http.StatusOK {
		return newAPIError("Keycloak device authorization", code, string(raw))
	}
	var device DeviceAuthResponse
	if err := json.Unmarshal(raw, &device); err != nil {
		return fmt.Errorf("failed to unmarshal device authorization response: %w", err)
	}
	if device.DeviceCode == "" {
		return fmt.Errorf("device authorization response missing device_code")
	}

	if onPrompt != nil {
		onPrompt(device)
	} else {
		uri := device.VerificationURIComplete
		if uri == "" {
			uri = device.VerificationURI
		}
		fmt.Printf("To sign in, open %s and enter code: %s\n", uri, device.UserCode)
	}

	// RFC 8628 section 3.5: poll no faster than "interval", stop once the device code expires.
	interval := device.Interval
	if interval <= 0 {
		interval = 5
	}
	expiresIn := device.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 600
	}
	deadline := r.timeNow().Add(time.Duration(expiresIn) * time.Second)

	pollForm := r.clientForm()
	pollForm.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	pollForm.Set("device_code", device.DeviceCode)

	for {
		remaining := deadline.Sub(r.timeNow())
		if remaining <= 0 {
			return fmt.Errorf("device authorization expired before the user approved the request")
		}
		wait := time.Duration(interval) * time.Second
		if wait > remaining {
			wait = remaining // the final wait must not overshoot the deadline
		}
		r.sleep(wait)

		code, raw, err := r.postForm(r.oidcEndpoint("token"), pollForm)
		if err != nil {
			return fmt.Errorf("Keycloak device token request failed: %w", err)
		}
		if code == http.StatusOK {
			return r.applyTokenResponse(raw)
		}
		switch oauthErrorCode(raw) {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 // RFC 8628 section 3.5: back off by 5 seconds
			continue
		default:
			return newAPIError("Keycloak device authorization", code, string(raw))
		}
	}
}

// RenewToken refreshes the Keycloak token using grant_type=refresh_token. Keycloak
// rotates the refresh token, so the complete new response replaces the stored one.
// It shadows AppMeshClient.RenewToken (which renews via the daemon).
func (r *AppMeshClientOAuth) RenewToken() (bool, error) {
	refresh := r.refreshTokenValue()
	if refresh == "" {
		return false, fmt.Errorf("no Keycloak refresh token available to renew")
	}

	form := r.clientForm()
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refresh)

	code, raw, err := r.postForm(r.oidcEndpoint("token"), form)
	if err != nil {
		return false, fmt.Errorf("Keycloak token renewal request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, newAPIError("Keycloak token renewal", code, string(raw))
	}
	if err := r.applyTokenResponse(raw); err != nil {
		return false, err
	}
	return true, nil
}

// Logout ends the Keycloak session (end-session with the refresh token) and logs off the
// daemon session, then clears the locally stored token. It returns true only when both
// the Keycloak and daemon logouts succeeded.
func (r *AppMeshClientOAuth) Logout() (bool, error) {
	kcResult := false
	if refresh := r.refreshTokenValue(); refresh != "" {
		if err := r.keycloakLogout(refresh); err != nil {
			log.Printf("Failed to logout from Keycloak: %v", err)
		} else {
			kcResult = true
		}
	}

	// Log off the daemon BEFORE clearing the local token so the request still carries the
	// current access token; clearing first would make the daemon logoff a no-op.
	daemonResult, err := r.AppMeshClient.Logout()

	r.tokenMu.Lock()
	r.token = KeycloakToken{}
	r.tokenMu.Unlock()

	if err != nil {
		return false, err
	}
	return kcResult && daemonResult, nil
}

// GetOauthUserinfo returns the Keycloak OIDC userinfo claims (e.g. sub,
// preferred_username, email) for the current access token, directly from Keycloak.
// Unlike GetCurrentUser (inherited), it does not involve the App Mesh daemon.
func (r *AppMeshClientOAuth) GetOauthUserinfo() (map[string]interface{}, error) {
	access := r.accessTokenValue()
	if access == "" {
		return nil, fmt.Errorf("no Keycloak access token available")
	}

	req, err := http.NewRequest(http.MethodGet, r.oidcEndpoint("userinfo"), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build Keycloak userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+access)

	resp, err := r.oauthHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Keycloak userinfo request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Keycloak userinfo response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, newAPIError("Keycloak userinfo", resp.StatusCode, string(raw))
	}
	claims := map[string]interface{}{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Keycloak userinfo: %w", err)
	}
	return claims, nil
}

// Close ends the Keycloak session on a best-effort basis and releases client resources.
func (r *AppMeshClientOAuth) Close() {
	if refresh := r.refreshTokenValue(); refresh != "" {
		if err := r.keycloakLogout(refresh); err != nil {
			log.Printf("Failed to logout from Keycloak during close: %v", err)
		}
	}
	r.tokenMu.Lock()
	r.token = KeycloakToken{}
	r.tokenMu.Unlock()

	r.AppMeshClient.Close()
}

// keycloakLogout posts the end-session request with the given refresh token.
func (r *AppMeshClientOAuth) keycloakLogout(refreshToken string) error {
	form := r.clientForm()
	form.Set("refresh_token", refreshToken)
	code, raw, err := r.postForm(r.oidcEndpoint("logout"), form)
	if err != nil {
		return err
	}
	if code != http.StatusOK && code != http.StatusNoContent {
		return newAPIError("Keycloak logout", code, string(raw))
	}
	return nil
}

// oidcEndpoint builds a Keycloak OpenID Connect endpoint URL for this realm.
func (r *AppMeshClientOAuth) oidcEndpoint(suffix string) string {
	return strings.TrimRight(r.oauth2.AuthServerURL, "/") + "/realms/" + url.PathEscape(r.oauth2.Realm) + "/protocol/openid-connect/" + suffix
}

// clientForm returns form values pre-populated with the client credentials.
func (r *AppMeshClientOAuth) clientForm() url.Values {
	form := url.Values{}
	form.Set("client_id", r.oauth2.ClientID)
	if r.oauth2.ClientSecret != "" {
		form.Set("client_secret", r.oauth2.ClientSecret)
	}
	return form
}

// postForm posts a form-encoded request to a Keycloak endpoint and buffers the response.
func (r *AppMeshClientOAuth) postForm(endpoint string, form url.Values) (int, []byte, error) {
	resp, err := r.oauthHTTP.PostForm(endpoint, form)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("failed to read Keycloak response body: %w", err)
	}
	return resp.StatusCode, raw, nil
}

// applyTokenResponse stores the full Keycloak token response and applies the access
// token as the Bearer token for daemon REST calls.
func (r *AppMeshClientOAuth) applyTokenResponse(raw []byte) error {
	var token KeycloakToken
	if err := json.Unmarshal(raw, &token); err != nil {
		return fmt.Errorf("failed to unmarshal Keycloak token response: %w", err)
	}
	if token.AccessToken == "" {
		return fmt.Errorf("Keycloak token response missing access_token")
	}
	r.tokenMu.Lock()
	r.token = token
	r.tokenMu.Unlock()
	r.SetToken(token.AccessToken)
	return nil
}

// refreshTokenValue returns the currently stored Keycloak refresh token, if any.
func (r *AppMeshClientOAuth) refreshTokenValue() string {
	r.tokenMu.Lock()
	defer r.tokenMu.Unlock()
	return r.token.RefreshToken
}

// accessTokenValue returns the currently stored Keycloak access token, if any.
func (r *AppMeshClientOAuth) accessTokenValue() string {
	r.tokenMu.Lock()
	defer r.tokenMu.Unlock()
	return r.token.AccessToken
}

// oauthErrorCode extracts the OAuth2 "error" code from a Keycloak error response body.
func oauthErrorCode(raw []byte) string {
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return ""
	}
	return body.Error
}
