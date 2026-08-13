package cloud

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	"github.com/stretchr/testify/require"
)

func newTestConsulClient(t *testing.T, handler http.Handler) *consulapi.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cfg := consulapi.DefaultConfig()
	cfg.Address = strings.TrimPrefix(server.URL, "http://")
	client, err := consulapi.NewClient(cfg)
	require.NoError(t, err)
	return client
}

func TestHostResourceSessionAndAcquire(t *testing.T) {
	var acquiredSession string
	var acquiredBody []byte
	client := newTestConsulClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/session/create":
			var request map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("failed to decode session request: %v", err)
			}
			if got := request["TTL"]; got != hostResourceSessionTTL {
				t.Errorf("expected TTL %q, got %v", hostResourceSessionTTL, got)
			}
			if got := request["Behavior"]; got != consulapi.SessionBehaviorDelete {
				t.Errorf("expected delete behavior, got %v", got)
			}
			_, _ = w.Write([]byte(`{"ID":"resource-session"}`))
		case strings.HasPrefix(r.URL.Path, "/v1/kv/appmesh/nodes/test/resources"):
			acquiredSession = r.URL.Query().Get("acquire")
			var err error
			acquiredBody, err = io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("failed to read KV body: %v", err)
			}
			_, _ = w.Write([]byte("true"))
		default:
			http.NotFound(w, r)
		}
	}))

	sessionID := ""
	require.NoError(t, ensureHostResourceSession(context.Background(), client, "test-host", &sessionID))
	require.Equal(t, "resource-session", sessionID)
	require.NoError(t, acquireHostResource(context.Background(), client, "appmesh/nodes/test/resources", sessionID, []byte(`{"cpu":2}`)))
	require.Equal(t, sessionID, acquiredSession)
	require.JSONEq(t, `{"cpu":2}`, string(acquiredBody))
}

func TestEnsureHostResourceSessionReusesExistingSession(t *testing.T) {
	requestCalled := false
	client := newTestConsulClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCalled = true
		http.NotFound(w, r)
	}))

	sessionID := "resource-session"
	require.NoError(t, ensureHostResourceSession(context.Background(), client, "test-host", &sessionID))
	require.Equal(t, "resource-session", sessionID)
	require.False(t, requestCalled)
}

func TestPublishRecreatesExpiredSession(t *testing.T) {
	acquireCalls := 0
	client := newTestConsulClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/session/info/expired-session":
			_, _ = w.Write([]byte(`[]`))
		case r.URL.Path == "/v1/session/create":
			_, _ = w.Write([]byte(`{"ID":"new-session"}`))
		case strings.HasPrefix(r.URL.Path, "/v1/kv/appmesh/nodes/test/resources"):
			acquireCalls++
			if acquireCalls == 1 {
				_, _ = w.Write([]byte("false"))
			} else {
				_, _ = w.Write([]byte("true"))
			}
		case r.URL.Path == "/v1/session/renew/new-session":
			_, _ = w.Write([]byte(`[{"ID":"new-session","TTL":"90s"}]`))
		default:
			http.NotFound(w, r)
		}
	}))

	sessionID := "expired-session"
	require.NoError(t, publishHostResource(context.Background(), client, "test-host", "appmesh/nodes/test/resources", &sessionID, []byte(`{}`)))
	require.Equal(t, "new-session", sessionID)
	require.Equal(t, 2, acquireCalls)
}

func TestRenewHostResourceSession(t *testing.T) {
	client := newTestConsulClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/session/renew/resource-session", r.URL.Path)
		_, _ = w.Write([]byte(`[{"ID":"resource-session","TTL":"90s"}]`))
	}))

	require.NoError(t, renewHostResourceSession(context.Background(), client, "resource-session"))
}

func TestAcquireHostResourceRejectsLiveOwner(t *testing.T) {
	client := newTestConsulClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("false"))
	}))

	err := acquireHostResource(context.Background(), client, "appmesh/nodes/test/resources", "new-session", []byte(`{}`))
	require.ErrorContains(t, err, "owned by another live host session")
}

func TestPublishFailureDoesNotRenewSession(t *testing.T) {
	renewCalls := 0
	client := newTestConsulClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/session/renew/resource-session":
			renewCalls++
			_, _ = w.Write([]byte(`[{"ID":"resource-session","TTL":"90s"}]`))
		case strings.HasPrefix(r.URL.Path, "/v1/kv/appmesh/nodes/test/resources"):
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))

	sessionID := "resource-session"
	for range 2 {
		require.Error(t, publishHostResource(context.Background(), client, "test-host", "appmesh/nodes/test/resources", &sessionID, []byte(`{}`)))
	}
	require.Zero(t, renewCalls)
}

func TestPublishAcquireRejectionDoesNotRenewLiveSession(t *testing.T) {
	infoCalls := 0
	renewCalls := 0
	client := newTestConsulClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/session/info/resource-session":
			infoCalls++
			_, _ = w.Write([]byte(`[{"ID":"resource-session","TTL":"90s"}]`))
		case r.URL.Path == "/v1/session/renew/resource-session":
			renewCalls++
			_, _ = w.Write([]byte(`[{"ID":"resource-session","TTL":"90s"}]`))
		case strings.HasPrefix(r.URL.Path, "/v1/kv/appmesh/nodes/test/resources"):
			_, _ = w.Write([]byte("false"))
		default:
			http.NotFound(w, r)
		}
	}))

	sessionID := "resource-session"
	err := publishHostResource(context.Background(), client, "test-host", "appmesh/nodes/test/resources", &sessionID, []byte(`{}`))
	require.ErrorContains(t, err, "owned by another live host session")
	require.Equal(t, 1, infoCalls)
	require.Zero(t, renewCalls)
}

func TestPublishRenewsOnlyAfterAcquire(t *testing.T) {
	requests := make([]string, 0, 2)
	client := newTestConsulClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/kv/appmesh/nodes/test/resources"):
			requests = append(requests, "acquire")
			_, _ = w.Write([]byte("true"))
		case r.URL.Path == "/v1/session/renew/resource-session":
			requests = append(requests, "renew")
			_, _ = w.Write([]byte(`[{"ID":"resource-session","TTL":"90s"}]`))
		default:
			http.NotFound(w, r)
		}
	}))

	sessionID := "resource-session"
	require.NoError(t, publishHostResource(context.Background(), client, "test-host", "appmesh/nodes/test/resources", &sessionID, []byte(`{}`)))
	require.Equal(t, []string{"acquire", "renew"}, requests)
}

func TestPublishRenewFailureKeepsLiveSession(t *testing.T) {
	renewCalls := 0
	client := newTestConsulClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/kv/appmesh/nodes/test/resources"):
			_, _ = w.Write([]byte("true"))
		case r.URL.Path == "/v1/session/renew/resource-session":
			renewCalls++
			if renewCalls == 1 {
				http.Error(w, "response lost", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`[{"ID":"resource-session","TTL":"90s"}]`))
		default:
			http.NotFound(w, r)
		}
	}))

	sessionID := "resource-session"
	require.Error(t, publishHostResource(context.Background(), client, "test-host", "appmesh/nodes/test/resources", &sessionID, []byte(`{}`)))
	require.Equal(t, "resource-session", sessionID)
	require.NoError(t, publishHostResource(context.Background(), client, "test-host", "appmesh/nodes/test/resources", &sessionID, []byte(`{}`)))
	require.Equal(t, "resource-session", sessionID)
}

func TestPublishConfirmedRenewExpiryClearsSession(t *testing.T) {
	client := newTestConsulClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/kv/appmesh/nodes/test/resources"):
			_, _ = w.Write([]byte("true"))
		case r.URL.Path == "/v1/session/renew/resource-session":
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))

	sessionID := "resource-session"
	err := publishHostResource(context.Background(), client, "test-host", "appmesh/nodes/test/resources", &sessionID, []byte(`{}`))
	require.ErrorIs(t, err, errHostResourceSessionExpired)
	require.Empty(t, sessionID)
}

func TestLeader(t *testing.T) {
	consul, err := NewCloud()
	if err != nil {
		t.Skipf("daemon not available: %v", err)
	}
	logger.Info(consul.getLeader())
}

func TestRegisterSelf(t *testing.T) {
	consul, err := NewCloud()
	if err != nil {
		t.Skipf("daemon not available: %v", err)
	}
	logger.Info(consul.registerHttpService())
}

func TestReportResource(t *testing.T) {
	os.Setenv("APPMESH_CONSUL_ENABLE", "true")
	os.Setenv("APPMESH_CONSUL_ADDRESS", "192.168.1.1:8500")
	cfg, _ := readConsulConfig()
	require.NotNil(t, cfg)
	require.Equal(t, cfg.Address, "192.168.1.1:8500")

	require.False(t, config.IsAgentProdEnv())
	//consul := NewCloud()
	//consul.ReportHostResource()
}
