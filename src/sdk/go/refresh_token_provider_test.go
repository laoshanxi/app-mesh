package appmesh

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The token endpoint must be https, or http only on a loopback host.
func TestNewRefreshTokenProviderURLPolicy(t *testing.T) {
	for _, tokenURL := range []string{
		"http://example.com/auth/token",
		"http://192.168.1.10/auth/token",
		"ftp://127.0.0.1/auth/token",
		"https:///auth/token",
		"not-a-url",
	} {
		provider, err := NewRefreshTokenProvider(RefreshTokenConfig{TokenURL: tokenURL, AccessToken: "a1", RefreshToken: "r1"})
		require.Error(t, err, "token URL %q must be rejected", tokenURL)
		assert.Nil(t, provider)
	}

	for _, tokenURL := range []string{
		"https://example.com/auth/token", // accepted without dialing
		"http://127.0.0.1:6060/auth/token",
		"http://localhost:6060/auth/token",
		"http://[::1]:6060/auth/token",
	} {
		provider, err := NewRefreshTokenProvider(RefreshTokenConfig{TokenURL: tokenURL, AccessToken: "a1", RefreshToken: "r1"})
		require.NoError(t, err, "token URL %q must be accepted", tokenURL)
		require.NotNil(t, provider)
	}

	provider, err := NewRefreshTokenProvider(RefreshTokenConfig{TokenURL: "https://example.com/auth/token", AccessToken: "a1"})
	require.Error(t, err, "an empty refresh token must be rejected")
	assert.Nil(t, provider)
}

// A token far from expiry is returned as-is; a token inside the refresh
// margin (margin 30s exceeds a 1s lifetime) is refreshed proactively.
func TestRefreshTokenProviderProactiveRefresh(t *testing.T) {
	var grants int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&grants, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"fresh-%d","expires_in":3600}`, n)
	}))
	defer server.Close()

	provider, err := NewRefreshTokenProvider(RefreshTokenConfig{
		TokenURL: server.URL, AccessToken: "live", RefreshToken: "r1", ExpiresIn: 3600,
	})
	require.NoError(t, err)
	token, err := provider.AccessToken()
	require.NoError(t, err)
	assert.Equal(t, "live", token)
	assert.Equal(t, int32(0), atomic.LoadInt32(&grants), "a healthy token must not trigger a grant")

	provider, err = NewRefreshTokenProvider(RefreshTokenConfig{
		TokenURL: server.URL, AccessToken: "stale", RefreshToken: "r1", ExpiresIn: 1,
	})
	require.NoError(t, err)
	token, err = provider.AccessToken()
	require.NoError(t, err)
	assert.Equal(t, "fresh-1", token)
	assert.Equal(t, int32(1), atomic.LoadInt32(&grants))
}

// A rejectedToken the provider no longer holds means a racing caller already
// refreshed: return the current token without hitting the token endpoint.
func TestRefreshTokenProviderCoalescesRacingRefresh(t *testing.T) {
	var grants int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&grants, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	provider, err := NewRefreshTokenProvider(RefreshTokenConfig{
		TokenURL: server.URL, AccessToken: "current", RefreshToken: "r1", ExpiresIn: 3600,
	})
	require.NoError(t, err)
	token, err := provider.RefreshAccessToken("someone-elses-stale-token")
	require.NoError(t, err)
	assert.Equal(t, "current", token)
	assert.Equal(t, int32(0), atomic.LoadInt32(&grants), "a stale rejection must not trigger a grant")
}

// The grant posts grant_type/refresh_token/client_id (defaulting to
// appmesh-cli); a rotated refresh token replaces the stored one, while a
// response without refresh_token keeps the old one.
func TestRefreshTokenProviderGrantFormAndRotation(t *testing.T) {
	var mu sync.Mutex
	var forms []url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		_ = r.ParseForm()
		mu.Lock()
		forms = append(forms, r.Form)
		n := len(forms)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			fmt.Fprint(w, `{"access_token":"a2","expires_in":3600,"refresh_token":"r2"}`)
			return
		}
		fmt.Fprintf(w, `{"access_token":"a%d","expires_in":3600}`, n+1)
	}))
	defer server.Close()

	provider, err := NewRefreshTokenProvider(RefreshTokenConfig{
		TokenURL: server.URL, AccessToken: "a1", RefreshToken: "r1", ExpiresIn: 3600,
	})
	require.NoError(t, err)

	token, err := provider.RefreshAccessToken("a1")
	require.NoError(t, err)
	assert.Equal(t, "a2", token)
	token, err = provider.RefreshAccessToken("a2")
	require.NoError(t, err)
	assert.Equal(t, "a3", token)
	token, err = provider.RefreshAccessToken("a3")
	require.NoError(t, err)
	assert.Equal(t, "a4", token)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, forms, 3)
	assert.Equal(t, "refresh_token", forms[0].Get("grant_type"))
	assert.Equal(t, "appmesh-cli", forms[0].Get("client_id"), "an empty ClientID must default to appmesh-cli")
	assert.Equal(t, "r1", forms[0].Get("refresh_token"))
	assert.Equal(t, "r2", forms[1].Get("refresh_token"), "the rotated refresh token must be used next")
	assert.Equal(t, "r2", forms[2].Get("refresh_token"), "a response without refresh_token keeps the old one")
}

// invalid_grant kills the refresh token: both tokens are cleared, CanRefresh
// turns false and AccessToken fails afterwards.
func TestRefreshTokenProviderInvalidGrantClearsState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"refresh token expired"}`)
	}))
	defer server.Close()

	provider, err := NewRefreshTokenProvider(RefreshTokenConfig{
		TokenURL: server.URL, AccessToken: "a1", RefreshToken: "r1", ExpiresIn: 3600,
	})
	require.NoError(t, err)
	assert.True(t, provider.CanRefresh())

	_, err = provider.RefreshAccessToken("a1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant")
	assert.False(t, provider.CanRefresh())
	_, err = provider.AccessToken()
	require.Error(t, err, "a cleared provider must not yield a token")
}

// A transient failure (500, network) keeps the tokens so a retry can succeed.
func TestRefreshTokenProviderTransientErrorKeepsState(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"a2","expires_in":3600}`)
	}))
	defer server.Close()

	provider, err := NewRefreshTokenProvider(RefreshTokenConfig{
		TokenURL: server.URL, AccessToken: "a1", RefreshToken: "r1", ExpiresIn: 3600,
	})
	require.NoError(t, err)

	_, err = provider.RefreshAccessToken("a1")
	require.Error(t, err)
	assert.True(t, provider.CanRefresh(), "a transient error must keep the refresh token")
	token, err := provider.AccessToken()
	require.NoError(t, err)
	assert.Equal(t, "a1", token, "a transient error must keep the access token")

	token, err = provider.RefreshAccessToken("a1")
	require.NoError(t, err)
	assert.Equal(t, "a2", token)
}

// Concurrent AccessToken calls around expiry must serialize on the provider
// mutex and observe each other's refresh instead of corrupting state.
func TestRefreshTokenProviderConcurrentAccess(t *testing.T) {
	var grants int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&grants, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"fresh","expires_in":3600}`)
	}))
	defer server.Close()

	provider, err := NewRefreshTokenProvider(RefreshTokenConfig{
		TokenURL: server.URL, AccessToken: "stale", RefreshToken: "r1", ExpiresIn: 1,
	})
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				token, err := provider.AccessToken()
				assert.NoError(t, err)
				assert.NotEmpty(t, token)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), atomic.LoadInt32(&grants), "the refreshed 3600s token must satisfy later goroutines")
}

// End to end: the client's 401 retry path drives RefreshAccessToken through a
// real refresh grant, then replays the request with the fresh bearer.
func TestRefreshTokenProviderEndToEnd401(t *testing.T) {
	var mu sync.Mutex
	var authHeaders []string
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"fresh-token","expires_in":3600}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		attempt := len(authHeaders)
		mu.Unlock()
		if attempt == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"BaseConfig":{"LogLevel":"DEBUG"}}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	provider, err := NewRefreshTokenProvider(RefreshTokenConfig{
		TokenURL: server.URL + "/auth/token", AccessToken: "stale-token", RefreshToken: "r1", ExpiresIn: 3600,
	})
	require.NoError(t, err)
	client, err := NewHTTPClient(Option{AppMeshUri: server.URL, TokenProvider: provider})
	require.NoError(t, err)
	defer client.Close()

	level, err := client.SetLogLevel("DEBUG")
	require.NoError(t, err)
	assert.Equal(t, "DEBUG", level)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, authHeaders, 2)
	assert.Equal(t, "Bearer stale-token", authHeaders[0])
	assert.Equal(t, "Bearer fresh-token", authHeaders[1])
}
