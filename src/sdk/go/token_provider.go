// token_provider.go
package appmesh

import (
	"fmt"
	"strings"
	"sync"
)

// TokenProvider supplies and refreshes access tokens. Refresh credentials stay
// private to the provider; only access tokens cross into the client.
type TokenProvider interface {
	// AccessToken returns a current token, refreshing before expiry when possible.
	AccessToken() (string, error)
	// CanRefresh reports whether the provider can replace a rejected/expiring token.
	CanRefresh() bool
	// RefreshAccessToken replaces a rejected token; called at most once per 401.
	// rejectedToken lets implementations skip duplicate refreshes when requests race.
	RefreshAccessToken(rejectedToken string) (string, error)
	// Clear forgets provider-owned in-memory token state.
	Clear()
}

// StaticTokenProvider is an in-memory provider for a caller-supplied access
// token. It cannot refresh; Clear drops the token.
type StaticTokenProvider struct {
	mu    sync.RWMutex
	token string
}

// NewStaticTokenProvider builds a provider for a non-empty token.
func NewStaticTokenProvider(token string) (*StaticTokenProvider, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("bearer token must be a non-empty string")
	}
	return &StaticTokenProvider{token: token}, nil
}

// AccessToken returns the static token, or an error once Clear was called.
func (p *StaticTokenProvider) AccessToken() (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.token == "" {
		return "", fmt.Errorf("static token provider was cleared")
	}
	return p.token, nil
}

// CanRefresh reports false: a static token cannot be replaced.
func (p *StaticTokenProvider) CanRefresh() bool { return false }

// RefreshAccessToken always fails: a static token cannot be replaced.
func (p *StaticTokenProvider) RefreshAccessToken(rejectedToken string) (string, error) {
	return "", fmt.Errorf("static token provider cannot refresh")
}

// Clear forgets the in-memory token.
func (p *StaticTokenProvider) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.token = ""
}

// tokenProviderHolder guards the TokenProvider attached to a requester. An
// attached provider wins over the static in-memory token; setToken detaches it.
type tokenProviderHolder struct {
	mu       sync.RWMutex
	provider TokenProvider
}

func (h *tokenProviderHolder) setTokenProvider(provider TokenProvider) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.provider = provider
}

func (h *tokenProviderHolder) getTokenProvider() TokenProvider {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.provider
}
