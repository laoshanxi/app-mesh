// refresh_token_provider.go
package appmesh

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// defaultRefreshClientID mirrors the CLI's public OAuth client.
const defaultRefreshClientID = "appmesh-cli"

// RefreshTokenConfig carries the OAuth2 inputs for a RefreshTokenProvider.
type RefreshTokenConfig struct {
	// TokenURL is the token endpoint, e.g. https://host:6060/auth/token. It
	// must use https, or http only on a loopback host (127.0.0.1, localhost, ::1).
	TokenURL string
	// ClientID is the OAuth client; defaults to "appmesh-cli" when empty.
	ClientID string
	// AccessToken is the current access token (may be empty to force a refresh).
	AccessToken string
	// RefreshToken is the OAuth refresh token.
	RefreshToken string
	// ExpiresIn is the access token lifetime in seconds; 0/unknown means the
	// provider refreshes only when a request is rejected with 401.
	ExpiresIn int64
	// HTTPClient is optional, for TLS configuration or tests.
	HTTPClient *http.Client
}

// RefreshTokenProvider is a TokenProvider backed by an OAuth2 refresh token
// grant. It refreshes proactively near expiry and on 401 rejection, and
// follows refresh-token rotation: a new refresh token in the grant response
// replaces the stored one, while its absence keeps the old one valid.
type RefreshTokenProvider struct {
	mu           sync.Mutex
	tokenURL     string
	clientID     string
	accessToken  string
	refreshToken string
	expiresAt    time.Time // zero when the lifetime is unknown
	lifetime     time.Duration
	httpClient   *http.Client
}

// NewRefreshTokenProvider validates the config and builds the provider. No
// network call is made; the first refresh happens lazily on expiry or 401.
func NewRefreshTokenProvider(cfg RefreshTokenConfig) (*RefreshTokenProvider, error) {
	tokenURL := strings.TrimSpace(cfg.TokenURL)
	if tokenURL == "" {
		return nil, fmt.Errorf("token URL must be a non-empty string")
	}
	parsed, err := url.Parse(tokenURL)
	if err != nil {
		return nil, fmt.Errorf("invalid token URL: %w", err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("token URL must include a host, got %q", tokenURL)
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(parsed.Hostname()) {
			return nil, fmt.Errorf("token URL over http is only allowed on loopback hosts, got host %q", parsed.Hostname())
		}
	default:
		return nil, fmt.Errorf("token URL must use https (or http on a loopback host), got scheme %q", parsed.Scheme)
	}
	refreshToken := strings.TrimSpace(cfg.RefreshToken)
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token must be a non-empty string")
	}
	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		clientID = defaultRefreshClientID
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	provider := &RefreshTokenProvider{
		tokenURL:     tokenURL,
		clientID:     clientID,
		accessToken:  cfg.AccessToken,
		refreshToken: refreshToken,
		httpClient:   httpClient,
	}
	if cfg.ExpiresIn > 0 {
		provider.lifetime = time.Duration(cfg.ExpiresIn) * time.Second
		provider.expiresAt = time.Now().Add(provider.lifetime)
	}
	return provider, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// AccessToken returns the current access token, refreshing proactively when
// the token is within the safety margin of its expiry. The margin is the
// larger of 30 seconds and 10% of the token lifetime. A token with unknown
// lifetime is returned as-is and refreshed only on 401.
func (p *RefreshTokenProvider) AccessToken() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.accessToken != "" && !p.expiringLocked() {
		return p.accessToken, nil
	}
	if p.refreshToken == "" {
		if p.accessToken == "" {
			return "", fmt.Errorf("refresh token provider has no access token")
		}
		return "", fmt.Errorf("access token expired and no refresh token is available")
	}
	return p.refreshLocked()
}

// expiringLocked reports whether the token is inside the refresh margin.
// Callers re-check this under the mutex so a refresh by a racing goroutine
// is observed instead of repeated.
func (p *RefreshTokenProvider) expiringLocked() bool {
	if p.expiresAt.IsZero() {
		return false
	}
	margin := p.lifetime / 10
	if margin < 30*time.Second {
		margin = 30 * time.Second
	}
	return !time.Now().Before(p.expiresAt.Add(-margin))
}

// CanRefresh reports whether a refresh token is held.
func (p *RefreshTokenProvider) CanRefresh() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshToken != ""
}

// RefreshAccessToken runs the refresh grant. When rejectedToken names a token
// the provider no longer holds, a racing caller already refreshed and the
// current token is returned without another grant.
func (p *RefreshTokenProvider) RefreshAccessToken(rejectedToken string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if rejectedToken != "" && p.accessToken != "" && rejectedToken != p.accessToken {
		return p.accessToken, nil
	}
	return p.refreshLocked()
}

// Clear forgets both tokens.
func (p *RefreshTokenProvider) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clearLocked()
}

func (p *RefreshTokenProvider) clearLocked() {
	p.accessToken = ""
	p.refreshToken = ""
	p.expiresAt = time.Time{}
	p.lifetime = 0
}

// refreshLocked performs the refresh_token grant. On invalid_grant the
// refresh token is dead, so both tokens are cleared; any other failure keeps
// the state so a later attempt can retry.
func (p *RefreshTokenProvider) refreshLocked() (string, error) {
	if p.refreshToken == "" {
		return "", fmt.Errorf("no refresh token available")
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {p.refreshToken},
		"client_id":     {p.clientID},
	}
	req, err := http.NewRequest(http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to build token refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token refresh request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("failed to read token refresh response: %w", err)
	}
	var grant struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		ExpiresIn        int64  `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &grant) // a non-JSON body is handled via the status code
	if grant.Error == "invalid_grant" {
		p.clearLocked()
		return "", fmt.Errorf("refresh token rejected (invalid_grant): %s", grant.ErrorDescription)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token refresh failed with status %d", resp.StatusCode)
	}
	if grant.AccessToken == "" {
		return "", fmt.Errorf("token refresh response is missing access_token")
	}
	p.accessToken = grant.AccessToken
	// Rotation: only a returned refresh token replaces the stored one; its
	// absence keeps the old one valid (Dex rotation with reuseInterval).
	if grant.RefreshToken != "" {
		p.refreshToken = grant.RefreshToken
	}
	if grant.ExpiresIn > 0 {
		p.lifetime = time.Duration(grant.ExpiresIn) * time.Second
		p.expiresAt = time.Now().Add(p.lifetime)
	} else {
		p.expiresAt = time.Time{}
		p.lifetime = 0
	}
	return p.accessToken, nil
}
