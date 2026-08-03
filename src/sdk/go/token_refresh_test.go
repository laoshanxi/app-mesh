package appmesh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mockTokenRequester is a Requester that only holds a token; the refresh pacing
// logic never sends anything.
type mockTokenRequester struct{ token string }

func (m *mockTokenRequester) Send(method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	return http.StatusOK, nil, http.Header{}, nil
}
func (m *mockTokenRequester) SendContext(ctx context.Context, method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	return m.Send(method, apiPath, queries, headers, body)
}
func (m *mockTokenRequester) Close()                         {}
func (m *mockTokenRequester) handleTokenUpdate(token string) { m.token = token }
func (m *mockTokenRequester) setToken(token string)          { m.token = token }
func (m *mockTokenRequester) getAccessToken() string         { return m.token }
func (m *mockTokenRequester) setForwardTo(forwardTo string)  {}
func (m *mockTokenRequester) getForwardTo() string           { return "" }

// makeJWT builds an unsigned JWT carrying the given iat/exp, which is all the
// refresh pacing logic reads.
func makeJWT(iat, exp int64) string {
	claims := map[string]any{"exp": exp}
	if iat > 0 {
		claims["iat"] = iat
	}
	payload, _ := json.Marshal(claims)
	return "hdr." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func TestRefreshMarginIsAFractionOfLifetime(t *testing.T) {
	now := time.Now().Unix()
	cases := []struct {
		name             string
		lifetime         time.Duration
		wantMin, wantMax time.Duration
	}{
		// 40% of lifetime, ±10% of that margin.
		{"30 minutes", 30 * time.Minute, 10*time.Minute + 48*time.Second, 13*time.Minute + 12*time.Second},
		{"7 days", 7 * 24 * time.Hour, 60*time.Hour + 28*time.Minute, 73*time.Hour + 55*time.Minute},
		// Short tokens are floored at the 30s offset, not at 40% (= 24s).
		{"1 minute", time.Minute, 27 * time.Second, 33 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exp := now + int64(tc.lifetime.Seconds())
			got := refreshMargin(makeJWT(now, exp), exp, now)
			if got < tc.wantMin || got > tc.wantMax {
				t.Fatalf("margin %v outside [%v, %v]", got, tc.wantMin, tc.wantMax)
			}
		})
	}
}

func TestRefreshMarginIsStableForTheSameToken(t *testing.T) {
	now := time.Now().Unix()
	exp := now + 3600
	token := makeJWT(now, exp)
	first := refreshMargin(token, exp, now)
	for i := 0; i < 10; i++ {
		if got := refreshMargin(token, exp, now); got != first {
			t.Fatalf("jitter is not deterministic: %v then %v", first, got)
		}
	}
}

func TestRefreshMarginDiffersAcrossTokens(t *testing.T) {
	now := time.Now().Unix()
	exp := now + 3600
	seen := make(map[time.Duration]bool)
	for i := 0; i < 20; i++ {
		// Same lifetime, different token bytes: the jitter must spread them.
		token := makeJWT(now, exp) + fmt.Sprintf("%d", i)
		seen[refreshMargin(token, exp, now)] = true
	}
	if len(seen) < 5 {
		t.Fatalf("expected jitter to spread renewals, got only %d distinct margins", len(seen))
	}
}

// The regression this whole change exists for: a token that lives far longer
// than the poll interval must not renew once per poll.
func TestRefreshPlanDoesNotRenewOncePerPoll(t *testing.T) {
	now := time.Now().Unix()
	exp := now + int64((30 * time.Minute).Seconds())
	c := &AppMeshClient{req: &mockTokenRequester{token: makeJWT(now, exp)}}

	delay, due := c.refreshPlan()
	if due {
		t.Fatal("a token with 30 minutes left must not be due for renewal")
	}
	if delay != tokenRefreshIntervalSeconds*time.Second {
		t.Fatalf("expected a poll-capped sleep of %ds, got %v", tokenRefreshIntervalSeconds, delay)
	}
}

func TestRefreshPlanRenewsAtTheRefreshPoint(t *testing.T) {
	now := time.Now().Unix()
	// Lifetime 30m, already 25m old: past the ~18m refresh point.
	exp := now + int64((5 * time.Minute).Seconds())
	iat := now - int64((25 * time.Minute).Seconds())
	c := &AppMeshClient{req: &mockTokenRequester{token: makeJWT(iat, exp)}}

	delay, due := c.refreshPlan()
	if !due {
		t.Fatal("a token past its refresh point must be due")
	}
	if delay > time.Second {
		t.Fatalf("expected an immediate renewal, got %v", delay)
	}
}

func TestRefreshPlanWithoutAnyCredentialOnlyPolls(t *testing.T) {
	c := &AppMeshClient{req: &mockTokenRequester{}}
	delay, due := c.refreshPlan()
	if due {
		t.Fatal("no credential means nothing to renew")
	}
	if delay != tokenRefreshIntervalSeconds*time.Second {
		t.Fatalf("expected the poll interval, got %v", delay)
	}
}

// An access token lost to an expired cookie is recoverable from the refresh token —
// but only if the loop actually attempts a renewal.
func TestRefreshPlanRenewsFromRefreshTokenAlone(t *testing.T) {
	c := &AppMeshClient{req: &mockTokenRequester{}}
	c.refreshToken.Store("rt")

	delay, due := c.refreshPlan()
	if !due {
		t.Fatal("a held refresh token can still mint an access token")
	}
	if delay > time.Second {
		t.Fatalf("expected a prompt renewal, got %v", delay)
	}
}

// A 30s token must not renew every second: the margin is capped at half the lifetime,
// after jitter, so the refresh point stays inside the token's own life.
func TestRefreshMarginNeverExceedsHalfTheLifetime(t *testing.T) {
	now := time.Now().Unix()
	for _, lifetime := range []int64{5, 30, 60, 120} {
		exp := now + lifetime
		got := refreshMargin(makeJWT(now, exp), exp, now)
		if limit := time.Duration(lifetime) * time.Second / 2; got > limit {
			t.Fatalf("lifetime %ds: margin %v exceeds half-life %v", lifetime, got, limit)
		}
	}
}

// An opaque token keeps the legacy fixed cadence: it is the only safe fallback
// when the lifetime cannot be read.
func TestRefreshPlanFallsBackForUndecodableToken(t *testing.T) {
	c := &AppMeshClient{req: &mockTokenRequester{token: "not-a-jwt"}}
	delay, due := c.refreshPlan()
	if !due {
		t.Fatal("an undecodable token must fall back to renewing on the poll interval")
	}
	if delay != tokenRefreshIntervalSeconds*time.Second {
		t.Fatalf("expected the poll interval, got %v", delay)
	}
}

func TestRefreshRetryDelayBackoffIsBounded(t *testing.T) {
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second,
		60 * time.Second, 60 * time.Second, 60 * time.Second}
	for i, w := range want {
		if got := refreshRetryDelay(i + 1); got != w {
			t.Fatalf("failure %d: expected %v, got %v", i+1, w, got)
		}
	}
}

// mockHeaderRequester records the last request headers per path. Keyed by path and
// mutex-guarded because an enabled auto-refresh loop sends renewals concurrently.
type mockHeaderRequester struct {
	mu      sync.Mutex
	token   string
	headers map[string]map[string]string
}

func (m *mockHeaderRequester) Send(method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.headers == nil {
		m.headers = map[string]map[string]string{}
	}
	seen := make(map[string]string, len(headers))
	for k, v := range headers {
		seen[k] = v
	}
	m.headers[apiPath] = seen
	return http.StatusOK, []byte(`{"access_token":"tok","expires_in":3600}`), http.Header{}, nil
}
func (m *mockHeaderRequester) SendContext(ctx context.Context, method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	return m.Send(method, apiPath, queries, headers, body)
}
func (m *mockHeaderRequester) Close()                         {}
func (m *mockHeaderRequester) handleTokenUpdate(token string) { m.setToken(token) }
func (m *mockHeaderRequester) setToken(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.token = token
}
func (m *mockHeaderRequester) getAccessToken() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.token
}
func (m *mockHeaderRequester) setForwardTo(forwardTo string) {}
func (m *mockHeaderRequester) getForwardTo() string          { return "" }

func (m *mockHeaderRequester) headerFor(path, key string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.headers[path][key]
	return v, ok
}

// A refresh token is a long-lived credential, so it must be requested only when the
// caller asked for one — directly, or by running a long-lived (auto-refreshing) client.
func TestRefreshTokenRequestHeaderFollowsOption(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name        string
		autoRefresh bool
		useRefresh  *bool
		want        bool
	}{
		{"unset follows auto-refresh on", true, nil, true},
		{"unset follows auto-refresh off", false, nil, false},
		{"explicit false overrides auto-refresh", true, &no, false},
		{"explicit true without auto-refresh", false, &yes, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &mockHeaderRequester{}
			client, err := newHTTPClientWithRequester(Option{AutoRefreshToken: tc.autoRefresh, UseRefreshToken: tc.useRefresh}, req)
			require.NoError(t, err)

			_, err = client.Login("user", "pass", "", 60, "")
			require.NoError(t, err)
			require.NoError(t, client.ValidateTotp("user", "challenge", "123456", 60))
			// Silence the background loop before asserting on the renew path it also drives.
			client.StopTokenRefresh()
			_, err = client.RenewToken()
			require.NoError(t, err)

			for _, path := range []string{"/appmesh/login", "/appmesh/totp/validate", "/appmesh/token/renew"} {
				value, present := req.headerFor(path, headerJWTWantRefreshToken)
				require.Equal(t, tc.want, present, "%s: header presence", path)
				if tc.want {
					require.Equal(t, "true", value, "%s: header value", path)
				}
			}
		})
	}
}

func TestDecodeJwtTimes(t *testing.T) {
	exp, iat, err := decodeJwtTimes(makeJWT(1000, 2000))
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if exp != 2000 || iat != 1000 {
		t.Fatalf("expected exp=2000 iat=1000, got exp=%d iat=%d", exp, iat)
	}

	// iat is optional; exp is not.
	if _, iat, err = decodeJwtTimes(makeJWT(0, 2000)); err != nil || iat != 0 {
		t.Fatalf("expected a missing iat to decode as 0, got iat=%d err=%v", iat, err)
	}
	if _, _, err = decodeJwtTimes("garbage"); err == nil {
		t.Fatal("expected an error for a malformed token")
	}
}
