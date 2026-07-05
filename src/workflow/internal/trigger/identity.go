package trigger

import (
	"fmt"
	"sync"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// IdentityManager caches per-identity, auto-refreshing TCP clients (ADR 0004).
// A workflow's execution_identity runs its steps under that user; the daemon can't
// mint arbitrary tokens, so the engine holds real credentials (APPMESH_EXEC_IDENTITIES)
// and logs in as the identity. Credentials are never logged.
type IdentityManager struct {
	serverURI string
	mu        sync.Mutex
	creds     map[string]string                    // user -> password (read-only after construction)
	clients   map[string]*appmesh.AppMeshClientTCP // user -> logged-in client
}

func NewIdentityManager(serverURI string, creds map[string]string) *IdentityManager {
	return &IdentityManager{
		serverURI: serverURI,
		creds:     creds,
		clients:   make(map[string]*appmesh.AppMeshClientTCP),
	}
}

// Known reports whether a credential is configured for the given identity.
func (m *IdentityManager) Known(user string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.creds[user]
	return ok
}

// TokenFor returns a valid token for the given execution identity, logging in
// (and caching an auto-refreshing client) on first use. It errors when no
// credential is configured or the login fails.
func (m *IdentityManager) TokenFor(user string) (string, error) {
	if m == nil {
		return "", fmt.Errorf("no execution identities configured")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if c, ok := m.clients[user]; ok {
		if tok := c.GetToken(); tok != "" {
			return tok, nil
		}
		// Cached client lost its token; drop it and log in fresh below.
		c.CloseConnection()
		delete(m.clients, user)
	}

	pwd, ok := m.creds[user]
	if !ok {
		return "", fmt.Errorf("execution_identity %q is not configured on the engine", user)
	}

	c, err := appmesh.NewTCPClient(appmesh.Option{
		AppMeshUri:         m.serverURI,
		InsecureSkipVerify: true,
		AutoRefreshToken:   true,
	})
	if err != nil {
		return "", fmt.Errorf("connect as %q: %w", user, err)
	}
	// Parallel runs share this client; enable the demuxer so their concurrent
	// calls can't cross-wire responses on the shared socket.
	c.EnableConcurrency()
	// Login returns "" on success; read the stored token via GetToken.
	if _, err := c.Login(user, pwd, "", 86400, ""); err != nil {
		c.CloseConnection()
		return "", fmt.Errorf("login as %q: %w", user, err)
	}
	tok := c.GetToken()
	if tok == "" {
		c.CloseConnection()
		return "", fmt.Errorf("login as %q returned no token", user)
	}
	m.clients[user] = c
	return tok, nil
}

// Close tears down all cached identity clients.
func (m *IdentityManager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.clients {
		c.CloseConnection()
	}
	m.clients = make(map[string]*appmesh.AppMeshClientTCP)
}
